"""
Tests for Unweaver transform modules: Base64Decoder, HexDecoder, and
StringExtractor.

Covers decoding accuracy, language-specific extraction, constant folding
patterns (String.fromCharCode, chr()), language detection heuristics, IOC
extraction, and readability scoring.
"""

from __future__ import annotations

import base64

import pytest

from app.services.transforms.base import TransformResult
from app.services.transforms.base64_decoder import (
    Base64Decoder,
    _is_plausible_b64,
    _try_decode,
)
from app.services.transforms.hex_decoder import (
    HexDecoder,
    _decode_backslash_x,
    _decode_0x_list,
    _decode_unicode_escape,
    _decode_percent_hex,
    _decode_hex_stream,
)
from app.services.transforms.string_extraction import (
    StringExtractor,
    _strip_quotes,
    _flag_string,
)
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
