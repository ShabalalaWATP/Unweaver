"""
Unweaver Transform Services
============================

Code deobfuscation transforms for the Unweaver engine.  Each transform
implements ``BaseTransform`` and returns ``TransformResult`` objects.

Usage::

    from app.services.transforms import (
        StringExtractor,
        Base64Decoder,
        HexDecoder,
        XorRecovery,
        ConstantFolder,
        JunkCodeRemover,
        EvalExecDetector,
        EntropyAnalyzer,
        UnicodeNormalizer,
        StringDecryptor,
        LiteralPropagator,
        ControlFlowUnflattener,
        DeterministicRenamer,
        JavaScriptArrayResolver,
        PowerShellDecoder,
        PythonDecoder,
        LanguageDetector,
        ObfuscationFingerprinter,
        IOCExtractor,
        RenameSuggester,
        ReadabilityScorer,
    )

    state = {}
    code = "<obfuscated source>"
    detector = LanguageDetector()
    result = detector.apply(code, "", state)
    language = state.get("detected_language", "")
"""

# Base types
from .base import BaseTransform, TransformResult

# Analysis transforms (non-destructive)
from .language_detector import LanguageDetector
from .obfuscation_fingerprinter import ObfuscationFingerprinter
from .string_extraction import StringExtractor
from .eval_detection import EvalExecDetector
from .entropy_analyzer import EntropyAnalyzer
from .ioc_extractor import IOCExtractor
from .readability_scorer import ReadabilityScorer, compute_readability_score
from .rename_suggester import RenameSuggester
from .workspace_profiler import WorkspaceProfiler
from .workspace_file_deobfuscator import WorkspaceFileDeobfuscator
from .source_preprocessor import SourcePreprocessor

# Decoding transforms
from .base64_decoder import Base64Decoder
from .hex_decoder import HexDecoder
from .xor_recovery import XorRecovery
from .constant_folder import ConstantFolder
from .unicode_normalizer import UnicodeNormalizer
from .string_decryptor import StringDecryptor
from .literal_propagator import LiteralPropagator

# Language-specific decoders
from .javascript_encoder_decoder import JavaScriptEncoderDecoder
from .javascript_bundle_deobfuscator import JavaScriptBundleDeobfuscator
from .js_packer_unpacker import JavaScriptPackerUnpacker
from .js_resolvers import JavaScriptArrayResolver
from .powershell_decoder import PowerShellDecoder
from .python_decoder import PythonDecoder

# Structural transforms
from .control_flow_unflattener import ControlFlowUnflattener
from .deterministic_renamer import DeterministicRenamer

# Extended decoders
from .base32_base85_decoder import Base32Base85Decoder
from .crypto_decryptor import CryptoDecryptor
from .dotnet_assembly_analyzer import DotNetAssemblyAnalyzer
from .reflection_resolver import ReflectionResolver
from .python_serialization_decoder import PythonSerializationDecoder

# Cleanup transforms
from .junk_code import JunkCodeRemover

__all__ = [
    # Base
    "BaseTransform",
    "TransformResult",
    # Analysis
    "LanguageDetector",
    "ObfuscationFingerprinter",
    "StringExtractor",
    "EvalExecDetector",
    "EntropyAnalyzer",
    "IOCExtractor",
    "ReadabilityScorer",
    "compute_readability_score",
    "RenameSuggester",
    "WorkspaceProfiler",
    "WorkspaceFileDeobfuscator",
    "SourcePreprocessor",
    # Decoding
    "Base64Decoder",
    "HexDecoder",
    "XorRecovery",
    "ConstantFolder",
    "UnicodeNormalizer",
    "StringDecryptor",
    "LiteralPropagator",
    # Language-specific
    "JavaScriptEncoderDecoder",
    "JavaScriptBundleDeobfuscator",
    "JavaScriptPackerUnpacker",
    "JavaScriptArrayResolver",
    "PowerShellDecoder",
    "PythonDecoder",
    # Structural
    "ControlFlowUnflattener",
    "DeterministicRenamer",
    # Extended decoders
    "Base32Base85Decoder",
    "CryptoDecryptor",
    "DotNetAssemblyAnalyzer",
    "ReflectionResolver",
    "PythonSerializationDecoder",
    # Cleanup
    "JunkCodeRemover",
]

# Convenience: a default pipeline ordering for deobfuscation
DEFAULT_PIPELINE = [
    SourcePreprocessor,
    LanguageDetector,
    ReadabilityScorer,
    ObfuscationFingerprinter,
    EntropyAnalyzer,
    StringExtractor,
    EvalExecDetector,
    UnicodeNormalizer,
    Base64Decoder,
    HexDecoder,
    StringDecryptor,
    JavaScriptEncoderDecoder,
    JavaScriptBundleDeobfuscator,
    JavaScriptPackerUnpacker,
    PowerShellDecoder,
    PythonDecoder,
    JavaScriptArrayResolver,
    ConstantFolder,
    LiteralPropagator,
    XorRecovery,
    Base32Base85Decoder,
    CryptoDecryptor,
    DotNetAssemblyAnalyzer,
    ReflectionResolver,
    PythonSerializationDecoder,
    ControlFlowUnflattener,
    JunkCodeRemover,
    DeterministicRenamer,
    IOCExtractor,
    RenameSuggester,
    WorkspaceProfiler,
    WorkspaceFileDeobfuscator,
    ReadabilityScorer,  # re-score after transforms
]
