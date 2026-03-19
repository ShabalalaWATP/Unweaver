"""
OpenAI-compatible async LLM client for Unweaver.

Connects to any OpenAI-compatible chat/completions endpoint (OpenAI, Azure,
vLLM, Ollama, LM Studio, etc.) using httpx for fully async HTTP.
"""

from __future__ import annotations

import logging
import ssl
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

# Mapping from human-friendly preset labels to actual token counts.
_MAX_TOKENS_MAP: Dict[str, int] = {
    "128k": 131_072,
    "200k": 204_800,
}


class LLMClient:
    """Async client that speaks the OpenAI chat/completions protocol."""

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        model: str = "gpt-3.5-turbo",
        max_tokens: int = 4096,
        cert_bundle: Optional[str] = None,
        use_system_trust: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.cert_bundle = cert_bundle
        self.use_system_trust = use_system_trust

        # Build SSL context
        self._ssl_context = self._build_ssl_context()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_ssl_context(self) -> ssl.SSLContext | bool:
        """Build an SSL context based on configuration.

        Returns either an ``ssl.SSLContext`` when a custom cert bundle is
        specified, ``True`` for default system trust, or ``False`` to skip
        verification entirely (not recommended).
        """
        if self.cert_bundle:
            ctx = ssl.create_default_context(cafile=self.cert_bundle)
            return ctx
        if self.use_system_trust:
            return True  # httpx default verification
        return False  # disable verification (insecure)

    def _build_headers(self) -> Dict[str, str]:
        """Construct request headers.  Never log the full API key."""
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _chat_url(self) -> str:
        """Return the full URL for the chat completions endpoint."""
        # Handle the case where base_url already ends with /v1 or similar
        base = self.base_url
        if base.endswith("/chat/completions"):
            return base
        if base.endswith("/v1"):
            return f"{base}/chat/completions"
        # Default: assume the caller gives us the root, append /v1/chat/completions
        return f"{base}/v1/chat/completions"

    def _safe_key_repr(self) -> str:
        """Return a masked version of the API key for logging."""
        if not self.api_key:
            return "(none)"
        if len(self.api_key) <= 8:
            return "****"
        return f"{self.api_key[:4]}...{self.api_key[-4:]}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.3,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Send a chat completion request and return the assistant reply text.

        Args:
            messages: List of ``{"role": ..., "content": ...}`` dicts.
            temperature: Sampling temperature (0.0-2.0).
            max_tokens: Override the per-call max tokens.  Falls back to the
                        instance default if not provided.

        Returns:
            The assistant's reply as a plain string.

        Raises:
            httpx.HTTPStatusError: If the remote API returns an error status.
            httpx.TimeoutException: If the request exceeds timeout limits.
        """
        effective_max = max_tokens or self.max_tokens

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": effective_max,
        }

        url = self._chat_url()
        logger.debug(
            "LLM request to %s  model=%s  max_tokens=%s  key=%s",
            url,
            self.model,
            effective_max,
            self._safe_key_repr(),
        )

        timeout = httpx.Timeout(connect=30.0, read=120.0, write=30.0, pool=30.0)

        async with httpx.AsyncClient(
            verify=self._ssl_context,
            timeout=timeout,
        ) as client:
            response = await client.post(
                url,
                headers=self._build_headers(),
                json=payload,
            )
            response.raise_for_status()

        data = response.json()

        # Standard OpenAI response shape
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            logger.error("Unexpected response shape from LLM: %s", data)
            raise ValueError(
                f"Unexpected response from LLM endpoint: {exc}"
            ) from exc

    async def test_connection(self) -> Tuple[bool, str]:
        """Send a lightweight test message and report whether the endpoint is reachable.

        Returns:
            A ``(success, message)`` tuple.  On success the message contains
            the model's short reply; on failure it contains a safe error
            description (no secrets).
        """
        test_messages = [
            {"role": "user", "content": "Reply with exactly: OK"},
        ]

        try:
            reply = await self.chat(
                messages=test_messages,
                temperature=0.0,
                max_tokens=16,
            )
            return True, f"Connection successful. Model replied: {reply.strip()[:80]}"
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            # Try to extract a useful error body without leaking secrets
            try:
                body = exc.response.json()
                detail = body.get("error", {}).get("message", str(body)[:200])
            except Exception:
                detail = exc.response.text[:200]
            return False, f"HTTP {status}: {detail}"
        except httpx.TimeoutException:
            return False, "Connection timed out.  Check the base URL and network."
        except httpx.ConnectError as exc:
            return False, f"Connection failed: {exc}"
        except ssl.SSLError as exc:
            return False, f"SSL error: {exc}. Check certificate bundle settings."
        except Exception as exc:
            return False, f"Unexpected error: {type(exc).__name__}: {exc}"
