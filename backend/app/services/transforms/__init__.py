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

# Decoding transforms
from .base64_decoder import Base64Decoder
from .hex_decoder import HexDecoder
from .xor_recovery import XorRecovery
from .constant_folder import ConstantFolder
from .unicode_normalizer import UnicodeNormalizer
from .string_decryptor import StringDecryptor

# Language-specific decoders
from .js_resolvers import JavaScriptArrayResolver
from .powershell_decoder import PowerShellDecoder
from .python_decoder import PythonDecoder

# Structural transforms
from .control_flow_unflattener import ControlFlowUnflattener
from .deterministic_renamer import DeterministicRenamer

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
    # Decoding
    "Base64Decoder",
    "HexDecoder",
    "XorRecovery",
    "ConstantFolder",
    "UnicodeNormalizer",
    "StringDecryptor",
    # Language-specific
    "JavaScriptArrayResolver",
    "PowerShellDecoder",
    "PythonDecoder",
    # Structural
    "ControlFlowUnflattener",
    "DeterministicRenamer",
    # Cleanup
    "JunkCodeRemover",
]

# Convenience: a default pipeline ordering for deobfuscation
DEFAULT_PIPELINE = [
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
    PowerShellDecoder,
    PythonDecoder,
    JavaScriptArrayResolver,
    ConstantFolder,
    XorRecovery,
    ControlFlowUnflattener,
    JunkCodeRemover,
    DeterministicRenamer,
    IOCExtractor,
    RenameSuggester,
    ReadabilityScorer,  # re-score after transforms
]
