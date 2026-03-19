"""
Tests for LLM provider settings: creation, API key masking, max token
preset handling, and connection testing with mocks.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.schemas import (
    ProviderSettingsCreate,
    ProviderSettingsResponse,
)
from app.services.llm.client import LLMClient, _MAX_TOKENS_MAP


# ════════════════════════════════════════════════════════════════════════
#  Provider Creation & Validation
# ════════════════════════════════════════════════════════════════════════

class TestProviderCreation:
    """Test that provider configs can be created with valid data."""

    def test_create_provider_schema_valid(self):
        """ProviderSettingsCreate should accept well-formed input."""
        payload = ProviderSettingsCreate(
            name="test-openai",
            base_url="https://api.openai.com",
            model_name="gpt-4o",
            api_key="sk-abcdef1234567890abcdef1234567890",
            max_tokens_preset="128k",
        )
        assert payload.name == "test-openai"
        assert payload.base_url == "https://api.openai.com"
        assert payload.model_name == "gpt-4o"
        assert payload.api_key == "sk-abcdef1234567890abcdef1234567890"
        assert payload.max_tokens_preset == "128k"
        assert payload.use_system_trust is True
        assert payload.cert_bundle_path is None

    def test_create_provider_200k_preset(self):
        """200k preset should be accepted."""
        payload = ProviderSettingsCreate(
            name="test-claude",
            base_url="https://api.anthropic.com",
            model_name="claude-3-opus",
            api_key="sk-ant-12345",
            max_tokens_preset="200k",
        )
        assert payload.max_tokens_preset == "200k"

    def test_create_provider_minimal(self):
        """Provider with only required fields should succeed."""
        payload = ProviderSettingsCreate(
            name="local-ollama",
            base_url="http://localhost:11434",
            model_name="llama3",
        )
        assert payload.api_key == ""
        assert payload.use_system_trust is True

    def test_create_provider_empty_name_fails(self):
        """Empty name should be rejected by Pydantic validation."""
        with pytest.raises(Exception):
            ProviderSettingsCreate(
                name="",
                base_url="http://localhost:11434",
                model_name="llama3",
            )


# ════════════════════════════════════════════════════════════════════════
#  API Key Masking
# ════════════════════════════════════════════════════════════════════════

class TestAPIKeyMasking:
    """Test that API keys are properly masked in response models."""

    def test_mask_long_key(self):
        """Long API key should show only last 4 characters."""
        from datetime import datetime, timezone

        response = ProviderSettingsResponse(
            id="test-id",
            name="test",
            base_url="https://api.example.com",
            model_name="gpt-4",
            api_key_masked="sk-abcdef1234567890abcdef1234567890",
            max_tokens_preset="128k",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        # The validator masks everything except last 4 chars
        assert response.api_key_masked.endswith("7890")
        assert response.api_key_masked.startswith("*")
        assert "abcdef" not in response.api_key_masked

    def test_mask_short_key(self):
        """Short API key (<= 4 chars) should be fully masked."""
        from datetime import datetime, timezone

        response = ProviderSettingsResponse(
            id="test-id",
            name="test",
            base_url="https://api.example.com",
            model_name="gpt-4",
            api_key_masked="sk",
            max_tokens_preset="128k",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        assert response.api_key_masked == "****"

    def test_mask_empty_key(self):
        """Empty API key should be masked as '****'."""
        from datetime import datetime, timezone

        response = ProviderSettingsResponse(
            id="test-id",
            name="test",
            base_url="https://api.example.com",
            model_name="gpt-4",
            api_key_masked="",
            max_tokens_preset="128k",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        assert response.api_key_masked == "****"

    def test_mask_exactly_four_chars(self):
        """Four-char key should be fully masked."""
        from datetime import datetime, timezone

        response = ProviderSettingsResponse(
            id="test-id",
            name="test",
            base_url="https://api.example.com",
            model_name="gpt-4",
            api_key_masked="abcd",
            max_tokens_preset="128k",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        assert response.api_key_masked == "****"


# ════════════════════════════════════════════════════════════════════════
#  Max Token Preset Handling
# ════════════════════════════════════════════════════════════════════════

class TestMaxTokenPresets:
    """Test that preset labels map to the correct token counts."""

    def test_128k_maps_to_131072(self):
        assert _MAX_TOKENS_MAP["128k"] == 131_072

    def test_200k_maps_to_204800(self):
        assert _MAX_TOKENS_MAP["200k"] == 204_800

    def test_unknown_preset_defaults(self):
        """Unknown preset should fall through to dict.get default."""
        result = _MAX_TOKENS_MAP.get("unknown", 4096)
        assert result == 4096

    def test_llm_client_uses_preset(self):
        """LLMClient should accept the resolved max_tokens value."""
        max_tokens = _MAX_TOKENS_MAP["128k"]
        client = LLMClient(
            base_url="http://localhost:11434",
            model="test",
            max_tokens=max_tokens,
        )
        assert client.max_tokens == 131_072

    def test_llm_client_200k_preset(self):
        max_tokens = _MAX_TOKENS_MAP["200k"]
        client = LLMClient(
            base_url="http://localhost:11434",
            model="test",
            max_tokens=max_tokens,
        )
        assert client.max_tokens == 204_800


# ════════════════════════════════════════════════════════════════════════
#  Connection Test with Mock
# ════════════════════════════════════════════════════════════════════════

class TestConnectionTest:
    """Test the LLMClient.test_connection method with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_successful_connection(self):
        """A successful connection should return (True, message)."""
        client = LLMClient(
            base_url="http://localhost:11434",
            api_key="test-key",
            model="test-model",
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "OK"}}]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            success, message = await client.test_connection()

        assert success is True
        assert "OK" in message

    @pytest.mark.asyncio
    async def test_failed_connection_timeout(self):
        """A timeout should return (False, message) with timeout info."""
        import httpx

        client = LLMClient(
            base_url="http://localhost:11434",
            api_key="test-key",
            model="test-model",
        )

        with patch(
            "httpx.AsyncClient.post",
            side_effect=httpx.TimeoutException("timed out"),
        ):
            success, message = await client.test_connection()

        assert success is False
        assert "timed out" in message.lower()

    @pytest.mark.asyncio
    async def test_failed_connection_error(self):
        """A connection error should return (False, message)."""
        import httpx

        client = LLMClient(
            base_url="http://localhost:11434",
            api_key="test-key",
            model="test-model",
        )

        with patch(
            "httpx.AsyncClient.post",
            side_effect=httpx.ConnectError("refused"),
        ):
            success, message = await client.test_connection()

        assert success is False
        assert "refused" in message.lower() or "connection" in message.lower()

    @pytest.mark.asyncio
    async def test_failed_connection_http_error(self):
        """An HTTP error should return (False, message) with status code."""
        import httpx

        client = LLMClient(
            base_url="http://localhost:11434",
            api_key="wrong-key",
            model="test-model",
        )

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {
            "error": {"message": "Invalid API key"}
        }
        mock_response.text = "Unauthorized"
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401 Unauthorized",
            request=httpx.Request("POST", "http://test"),
            response=mock_response,
        )
        # Patch the response attribute on the exception
        exc = mock_response.raise_for_status.side_effect
        exc.response = mock_response

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            success, message = await client.test_connection()

        assert success is False
        assert "401" in message


# ════════════════════════════════════════════════════════════════════════
#  LLM Client Helper Methods
# ════════════════════════════════════════════════════════════════════════

class TestLLMClientHelpers:
    """Test internal helper methods of LLMClient."""

    def test_chat_url_with_bare_url(self):
        client = LLMClient(base_url="http://localhost:11434", model="test")
        assert client._chat_url() == "http://localhost:11434/v1/chat/completions"

    def test_chat_url_with_v1(self):
        client = LLMClient(base_url="http://localhost:11434/v1", model="test")
        assert client._chat_url() == "http://localhost:11434/v1/chat/completions"

    def test_chat_url_already_complete(self):
        url = "http://localhost:11434/v1/chat/completions"
        client = LLMClient(base_url=url, model="test")
        assert client._chat_url() == url

    def test_safe_key_repr_none(self):
        client = LLMClient(base_url="http://test", model="test", api_key="")
        assert client._safe_key_repr() == "(none)"

    def test_safe_key_repr_short(self):
        client = LLMClient(base_url="http://test", model="test", api_key="abcd")
        assert client._safe_key_repr() == "****"

    def test_safe_key_repr_long(self):
        client = LLMClient(
            base_url="http://test",
            model="test",
            api_key="sk-abcdef1234567890",
        )
        repr_str = client._safe_key_repr()
        assert repr_str.startswith("sk-a")
        assert repr_str.endswith("7890")

    def test_build_headers_with_key(self):
        client = LLMClient(
            base_url="http://test",
            model="test",
            api_key="sk-test123",
        )
        headers = client._build_headers()
        assert headers["Authorization"] == "Bearer sk-test123"
        assert headers["Content-Type"] == "application/json"

    def test_build_headers_without_key(self):
        client = LLMClient(base_url="http://test", model="test", api_key="")
        headers = client._build_headers()
        assert "Authorization" not in headers
