"""
Base transform class and result dataclass for the Unweaver deobfuscation engine.
All transforms inherit from BaseTransform and return TransformResult objects.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class TransformResult:
    """Result of applying a transform to code."""

    success: bool
    output: str
    confidence: float  # 0.0 - 1.0
    description: str
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, self.confidence))
        if self.details is None:
            self.details = {}


class BaseTransform(ABC):
    """Abstract base class for all code transforms."""

    name: str = "BaseTransform"
    description: str = "Base transform"

    @abstractmethod
    def can_apply(self, code: str, language: str, state: dict) -> bool:
        """Check whether this transform is applicable to the given code.

        Args:
            code: The source code to inspect.
            language: The detected or declared language (e.g. "javascript", "python").
            state: Shared state dict that transforms can read/write to pass
                   information between pipeline stages.

        Returns:
            True if the transform can meaningfully be applied.
        """
        ...

    @abstractmethod
    def apply(self, code: str, language: str, state: dict) -> TransformResult:
        """Apply the transform to the given code.

        Args:
            code: The source code to transform.
            language: The detected or declared language.
            state: Shared state dict.

        Returns:
            A TransformResult with the transformed code and metadata.
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.name}>"
