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
        context_window: int = 131_072,
        cert_bundle: Optional[str] = None,
        use_system_trust: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.context_window = context_window
        self.cert_bundle = cert_bundle
        self.use_system_trust = use_system_trust

        # Decide whether to use 'max_completion_tokens' (modern) or 'max_tokens'
        # (legacy).  Modern models (OpenAI o-series, gpt-4o, etc.) require the
        # new parameter name; legacy models may only support the old one.
        # Default to the modern parameter and fall back on error.
        self._use_max_completion_tokens = self._should_prefer_completion_tokens(model)

        # Build SSL context
        self._ssl_context = self._build_ssl_context()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _should_prefer_completion_tokens(model_name: str) -> bool:
        """Return True if the model is known (or likely) to require
        ``max_completion_tokens`` instead of the legacy ``max_tokens``.

        Conservative heuristic: default to **True** (modern parameter) for
        any model whose name we don't explicitly recognise as legacy-only.
        The auto-retry logic in :meth:`chat` will correct a wrong guess.
        """
        name = model_name.lower()
        # Explicitly legacy models that only support max_tokens
        legacy_prefixes = ("gpt-3.5", "gpt-3", "text-davinci", "text-curie",
                           "text-babbage", "text-ada")
        for prefix in legacy_prefixes:
            if name.startswith(prefix):
                return False
        # Everything else (gpt-4o, o1, o3, claude, etc.) → modern parameter
        return True

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
        return await self._chat_inner(messages, temperature, max_tokens, _retrying_token_param=False)

    async def _chat_inner(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: Optional[int],
        *,
        _retrying_token_param: bool = False,
    ) -> str:
        """Internal implementation of chat with call-level retry guard."""
        effective_max = max_tokens or self.max_tokens

        # Use the modern 'max_completion_tokens' or legacy 'max_tokens'
        # based on model detection (set in __init__) and auto-correction.
        token_key = "max_completion_tokens" if self._use_max_completion_tokens else "max_tokens"

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            token_key: effective_max,
        }

        url = self._chat_url()
        logger.debug(
            "LLM request to %s  model=%s  %s=%s  key=%s",
            url,
            self.model,
            token_key,
            effective_max,
            self._safe_key_repr(),
        )

        timeout = httpx.Timeout(connect=30.0, read=120.0, write=30.0, pool=30.0)

        try:
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
        except httpx.HTTPStatusError as exc:
            # Auto-detect: if the API rejects 'max_tokens' asking for
            # 'max_completion_tokens' (or vice versa), retry with the
            # alternative parameter and remember for future calls.
            if exc.response.status_code == 400:
                try:
                    body = exc.response.json()
                    err_msg = str(body.get("error", {}).get("message", "")).lower()
                except Exception:
                    err_msg = exc.response.text[:500].lower()

                needs_swap = (
                    ("max_tokens" in err_msg and "max_completion_tokens" in err_msg)
                    or ("unsupported parameter" in err_msg and "max_tokens" in err_msg)
                )
                if needs_swap and not _retrying_token_param:
                    self._use_max_completion_tokens = not self._use_max_completion_tokens
                    alt_key = "max_completion_tokens" if self._use_max_completion_tokens else "max_tokens"
                    logger.info(
                        "Switching token parameter from '%s' to '%s' and retrying",
                        token_key, alt_key,
                    )
                    # Retry with swapped parameter (call-level guard prevents infinite recursion)
                    return await self._chat_inner(messages, temperature, max_tokens, _retrying_token_param=True)

            logger.error(
                "LLM HTTP error %d from %s", exc.response.status_code, url
            )
            raise
        except httpx.TimeoutException:
            logger.error("LLM request timed out: %s", url)
            raise
        except httpx.ConnectError as exc:
            logger.error("LLM connection failed: %s — %s", url, exc)
            raise
        except Exception as exc:
            logger.error("LLM request failed: %s — %s", url, exc)
            raise

        try:
            data = response.json()
        except Exception as exc:
            logger.error("LLM response is not valid JSON: %s", response.text[:500])
            raise ValueError("LLM response is not valid JSON") from exc

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
