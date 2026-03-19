"""
Tests for Unweaver API endpoints.

Uses httpx AsyncClient with the FastAPI test app to exercise:
  - Project CRUD
  - Sample upload and paste
  - Sample listing
  - Analysis start
  - Health check
"""

from __future__ import annotations

import io

import pytest
from httpx import AsyncClient


# ════════════════════════════════════════════════════════════════════════
#  Health Check
# ════════════════════════════════════════════════════════════════════════

class TestHealthCheck:
    """Test the health check endpoint."""

    @pytest.mark.asyncio
    async def test_health_returns_ok(self, client: AsyncClient):
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "app" in data


# ════════════════════════════════════════════════════════════════════════
#  Projects
# ════════════════════════════════════════════════════════════════════════

class TestProjectEndpoints:
    """Test project CRUD endpoints."""

    @pytest.mark.asyncio
    async def test_create_project(self, client: AsyncClient):
        """POST /api/projects should create a new project."""
        response = await client.post(
            "/api/projects",
            json={"name": "Test Project", "description": "A test project"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Test Project"
        assert data["description"] == "A test project"
        assert "id" in data
        assert "created_at" in data

    @pytest.mark.asyncio
    async def test_list_projects(self, client: AsyncClient):
        """GET /api/projects should return a list of projects."""
        # Create two projects
        await client.post("/api/projects", json={"name": "Project A"})
        await client.post("/api/projects", json={"name": "Project B"})

        response = await client.get("/api/projects")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 2

    @pytest.mark.asyncio
    async def test_get_project_by_id(self, client: AsyncClient):
        """GET /api/projects/{id} should return a single project."""
        create_resp = await client.post(
            "/api/projects",
            json={"name": "Lookup Test"},
        )
        project_id = create_resp.json()["id"]

        response = await client.get(f"/api/projects/{project_id}")
        assert response.status_code == 200
        assert response.json()["id"] == project_id
        assert response.json()["name"] == "Lookup Test"

    @pytest.mark.asyncio
    async def test_get_nonexistent_project(self, client: AsyncClient):
        """GET /api/projects/{id} with bad ID should return 404."""
        response = await client.get("/api/projects/nonexistent-id")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_project(self, client: AsyncClient):
        """DELETE /api/projects/{id} should remove the project."""
        create_resp = await client.post(
            "/api/projects",
            json={"name": "To Delete"},
        )
        project_id = create_resp.json()["id"]

        del_resp = await client.delete(f"/api/projects/{project_id}")
        assert del_resp.status_code == 204

        # Verify it's gone
        get_resp = await client.get(f"/api/projects/{project_id}")
        assert get_resp.status_code == 404


# ════════════════════════════════════════════════════════════════════════
#  Samples -- Paste
# ════════════════════════════════════════════════════════════════════════

class TestSamplePaste:
    """Test the paste-sample endpoint."""

    @pytest.mark.asyncio
    async def test_paste_sample(self, client: AsyncClient):
        """POST /api/projects/{id}/samples/paste should create a sample."""
        # Create project first
        proj_resp = await client.post(
            "/api/projects",
            json={"name": "Paste Test"},
        )
        project_id = proj_resp.json()["id"]

        response = await client.post(
            f"/api/projects/{project_id}/samples/paste",
            json={
                "original_text": 'var x = atob("aGVsbG8=");',
                "language": "javascript",
                "filename": "test.js",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["project_id"] == project_id
        assert data["filename"] == "test.js"
        assert data["language"] == "javascript"

    @pytest.mark.asyncio
    async def test_paste_sample_empty_text_rejected(self, client: AsyncClient):
        """Empty paste text should be rejected."""
        proj_resp = await client.post(
            "/api/projects",
            json={"name": "Empty Paste Test"},
        )
        project_id = proj_resp.json()["id"]

        response = await client.post(
            f"/api/projects/{project_id}/samples/paste",
            json={"original_text": ""},
        )
        # Pydantic rejects empty string due to min_length=1 on original_text
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_paste_sample_nonexistent_project(self, client: AsyncClient):
        """Pasting to a nonexistent project should return 404."""
        response = await client.post(
            "/api/projects/nonexistent-id/samples/paste",
            json={"original_text": "some code"},
        )
        assert response.status_code == 404


# ════════════════════════════════════════════════════════════════════════
#  Samples -- Upload
# ════════════════════════════════════════════════════════════════════════

class TestSampleUpload:
    """Test the file upload endpoint."""

    @pytest.mark.asyncio
    async def test_upload_sample(self, client: AsyncClient):
        """POST /api/projects/{id}/samples/upload should accept a file."""
        proj_resp = await client.post(
            "/api/projects",
            json={"name": "Upload Test"},
        )
        project_id = proj_resp.json()["id"]

        file_content = b'var x = atob("dGVzdA==");'
        response = await client.post(
            f"/api/projects/{project_id}/samples/upload",
            files={"file": ("test.js", io.BytesIO(file_content), "text/javascript")},
            data={"language": "javascript"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["project_id"] == project_id
        assert "test.js" in data["filename"]

    @pytest.mark.asyncio
    async def test_upload_empty_file_rejected(self, client: AsyncClient):
        """Uploading an empty file should return 400."""
        proj_resp = await client.post(
            "/api/projects",
            json={"name": "Empty Upload Test"},
        )
        project_id = proj_resp.json()["id"]

        response = await client.post(
            f"/api/projects/{project_id}/samples/upload",
            files={"file": ("empty.txt", io.BytesIO(b""), "text/plain")},
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_upload_to_nonexistent_project(self, client: AsyncClient):
        """Uploading to a nonexistent project should return 404."""
        response = await client.post(
            "/api/projects/nonexistent-id/samples/upload",
            files={"file": ("test.txt", io.BytesIO(b"code"), "text/plain")},
        )
        assert response.status_code == 404


# ════════════════════════════════════════════════════════════════════════
#  Samples -- Listing
# ════════════════════════════════════════════════════════════════════════

class TestSampleListing:
    """Test sample listing endpoints."""

    @pytest.mark.asyncio
    async def test_list_samples(self, client: AsyncClient):
        """GET /api/projects/{id}/samples should return samples."""
        proj_resp = await client.post(
            "/api/projects",
            json={"name": "List Test"},
        )
        project_id = proj_resp.json()["id"]

        # Create two samples
        await client.post(
            f"/api/projects/{project_id}/samples/paste",
            json={"original_text": "code one", "filename": "a.js"},
        )
        await client.post(
            f"/api/projects/{project_id}/samples/paste",
            json={"original_text": "code two", "filename": "b.js"},
        )

        response = await client.get(f"/api/projects/{project_id}/samples")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 2

    @pytest.mark.asyncio
    async def test_list_samples_nonexistent_project(self, client: AsyncClient):
        """Listing samples for nonexistent project should return 404."""
        response = await client.get("/api/projects/nonexistent-id/samples")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_sample_detail(self, client: AsyncClient):
        """GET /api/samples/{id} should return full sample detail."""
        proj_resp = await client.post(
            "/api/projects",
            json={"name": "Detail Test"},
        )
        project_id = proj_resp.json()["id"]

        paste_resp = await client.post(
            f"/api/projects/{project_id}/samples/paste",
            json={"original_text": "var x = 1;", "filename": "detail.js"},
        )
        sample_id = paste_resp.json()["id"]

        response = await client.get(f"/api/samples/{sample_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == sample_id
        assert data["original_text"] == "var x = 1;"

    @pytest.mark.asyncio
    async def test_get_nonexistent_sample(self, client: AsyncClient):
        """GET /api/samples/{id} with bad ID should return 404."""
        response = await client.get("/api/samples/nonexistent-id")
        assert response.status_code == 404


# ════════════════════════════════════════════════════════════════════════
#  Analysis
# ════════════════════════════════════════════════════════════════════════

class TestAnalysisEndpoints:
    """Test analysis control endpoints."""

    @pytest.mark.asyncio
    async def test_start_analysis(self, client: AsyncClient):
        """POST /api/samples/{id}/analyze should accept and start analysis."""
        proj_resp = await client.post(
            "/api/projects",
            json={"name": "Analysis Test"},
        )
        project_id = proj_resp.json()["id"]

        paste_resp = await client.post(
            f"/api/projects/{project_id}/samples/paste",
            json={"original_text": 'atob("dGVzdA==")', "filename": "test.js"},
        )
        sample_id = paste_resp.json()["id"]

        response = await client.post(f"/api/samples/{sample_id}/analyze")
        assert response.status_code == 202
        data = response.json()
        assert data["sample_id"] == sample_id

    @pytest.mark.asyncio
    async def test_start_analysis_nonexistent_sample(self, client: AsyncClient):
        """Starting analysis for nonexistent sample should return 404."""
        response = await client.post("/api/samples/nonexistent-id/analyze")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_analysis_status(self, client: AsyncClient):
        """GET /api/samples/{id}/analysis/status should return status."""
        proj_resp = await client.post(
            "/api/projects",
            json={"name": "Status Test"},
        )
        project_id = proj_resp.json()["id"]

        paste_resp = await client.post(
            f"/api/projects/{project_id}/samples/paste",
            json={"original_text": "code here", "filename": "status.js"},
        )
        sample_id = paste_resp.json()["id"]

        response = await client.get(f"/api/samples/{sample_id}/analysis/status")
        assert response.status_code == 200
        data = response.json()
        assert data["sample_id"] == sample_id
        assert "status" in data


# ════════════════════════════════════════════════════════════════════════
#  Providers (via API)
# ════════════════════════════════════════════════════════════════════════

class TestProviderEndpoints:
    """Test LLM provider endpoints through the API."""

    @pytest.mark.asyncio
    async def test_create_provider(self, client: AsyncClient):
        """POST /api/providers should create a new provider."""
        response = await client.post(
            "/api/providers",
            json={
                "name": "test-provider",
                "base_url": "http://localhost:11434",
                "model_name": "llama3",
                "api_key": "sk-test1234567890abcdef",
                "max_tokens_preset": "128k",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "test-provider"
        assert data["model_name"] == "llama3"
        # Key should be masked
        assert "sk-test" not in data["api_key_masked"] or data["api_key_masked"].count("*") > 0

    @pytest.mark.asyncio
    async def test_list_providers(self, client: AsyncClient):
        """GET /api/providers should return all providers."""
        await client.post(
            "/api/providers",
            json={
                "name": "provider-a",
                "base_url": "http://localhost:11434",
                "model_name": "model-a",
            },
        )

        response = await client.get("/api/providers")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1

    @pytest.mark.asyncio
    async def test_duplicate_provider_name_rejected(self, client: AsyncClient):
        """Creating two providers with the same name should fail."""
        payload = {
            "name": "unique-provider",
            "base_url": "http://localhost:11434",
            "model_name": "model-x",
        }
        resp1 = await client.post("/api/providers", json=payload)
        assert resp1.status_code == 201

        resp2 = await client.post("/api/providers", json=payload)
        assert resp2.status_code == 409


# ════════════════════════════════════════════════════════════════════════
#  Sample Sub-resources
# ════════════════════════════════════════════════════════════════════════

class TestSampleSubResources:
    """Test sample sub-resource endpoints (strings, iocs, etc.)."""

    async def _create_sample(self, client: AsyncClient) -> str:
        """Helper: create a project and sample, return sample_id."""
        proj = await client.post("/api/projects", json={"name": "SubRes Test"})
        project_id = proj.json()["id"]
        sample = await client.post(
            f"/api/projects/{project_id}/samples/paste",
            json={"original_text": "var x = 1;", "filename": "sub.js"},
        )
        return sample.json()["id"]

    @pytest.mark.asyncio
    async def test_get_original_text(self, client: AsyncClient):
        sample_id = await self._create_sample(client)
        response = await client.get(f"/api/samples/{sample_id}/original")
        assert response.status_code == 200
        assert "original_text" in response.json()

    @pytest.mark.asyncio
    async def test_get_recovered_text(self, client: AsyncClient):
        sample_id = await self._create_sample(client)
        response = await client.get(f"/api/samples/{sample_id}/recovered")
        assert response.status_code == 200
        assert "recovered_text" in response.json()

    @pytest.mark.asyncio
    async def test_get_diff(self, client: AsyncClient):
        sample_id = await self._create_sample(client)
        response = await client.get(f"/api/samples/{sample_id}/diff")
        assert response.status_code == 200
        assert "diff" in response.json()

    @pytest.mark.asyncio
    async def test_get_strings(self, client: AsyncClient):
        sample_id = await self._create_sample(client)
        response = await client.get(f"/api/samples/{sample_id}/strings")
        assert response.status_code == 200
        assert "strings" in response.json()

    @pytest.mark.asyncio
    async def test_get_iocs(self, client: AsyncClient):
        sample_id = await self._create_sample(client)
        response = await client.get(f"/api/samples/{sample_id}/iocs")
        assert response.status_code == 200
        assert "iocs" in response.json()

    @pytest.mark.asyncio
    async def test_get_findings(self, client: AsyncClient):
        sample_id = await self._create_sample(client)
        response = await client.get(f"/api/samples/{sample_id}/findings")
        assert response.status_code == 200
        assert "findings" in response.json()

    @pytest.mark.asyncio
    async def test_get_transforms(self, client: AsyncClient):
        sample_id = await self._create_sample(client)
        response = await client.get(f"/api/samples/{sample_id}/transforms")
        assert response.status_code == 200
        assert "transforms" in response.json()
