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
from .ioc_extractor import IOCExtractor
from .readability_scorer import ReadabilityScorer, compute_readability_score
from .rename_suggester import RenameSuggester

# Decoding transforms
from .base64_decoder import Base64Decoder
from .hex_decoder import HexDecoder
from .xor_recovery import XorRecovery
from .constant_folder import ConstantFolder

# Language-specific decoders
from .js_resolvers import JavaScriptArrayResolver
from .powershell_decoder import PowerShellDecoder
from .python_decoder import PythonDecoder

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
    "IOCExtractor",
    "ReadabilityScorer",
    "compute_readability_score",
    "RenameSuggester",
    # Decoding
    "Base64Decoder",
    "HexDecoder",
    "XorRecovery",
    "ConstantFolder",
    # Language-specific
    "JavaScriptArrayResolver",
    "PowerShellDecoder",
    "PythonDecoder",
    # Cleanup
    "JunkCodeRemover",
]

# Convenience: a default pipeline ordering for deobfuscation
DEFAULT_PIPELINE = [
    LanguageDetector,
    ReadabilityScorer,
    ObfuscationFingerprinter,
    StringExtractor,
    EvalExecDetector,
    Base64Decoder,
    HexDecoder,
    PowerShellDecoder,
    PythonDecoder,
    JavaScriptArrayResolver,
    ConstantFolder,
    XorRecovery,
    JunkCodeRemover,
    IOCExtractor,
    RenameSuggester,
    ReadabilityScorer,  # re-score after transforms
]
