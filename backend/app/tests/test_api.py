import os
import pytest
import pytest_asyncio
import httpx
from fastapi import FastAPI
from app.main import app
from app.db.session import init_db, engine
from app.db.models import Base

# Set testing environment variables
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

SAMPLES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../samples")
)

def read_sample_file(filename: str) -> str:
    path = os.path.join(SAMPLES_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

@pytest_asyncio.fixture(scope="module", autouse=True)
async def setup_test_db():
    """Initializes schema in in-memory database for API testing."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.mark.asyncio
async def test_root_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/")
        assert response.status_code == 200
        assert response.json()["status"] == "online"

@pytest.mark.asyncio
async def test_upload_text_and_database_cycles():
    raw_content = read_sample_file("display_name_spoof.eml")
    
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. POST raw EML text
        response = await ac.post(
            "/api/upload/text",
            json={"raw_text": raw_content}
        )
        assert response.status_code == 200
        report = response.json()
        assert "id" in report
        investigation_id = report["id"]
        assert report["parsed_email"]["envelope"]["sender"]["name"] == "John Doe"
        assert report["risk_assessment"]["level"] in ["Medium", "High", "Critical"]
        
        # 2. GET List of Investigations (contains item)
        list_response = await ac.get("/api/investigations")
        assert list_response.status_code == 200
        list_data = list_response.json()
        assert list_data["total"] >= 1
        assert any(item["id"] == investigation_id for item in list_data["items"])
        
        # 3. GET Analytics Stats
        stats_response = await ac.get("/api/investigations/stats")
        assert stats_response.status_code == 200
        stats = stats_response.json()
        assert stats["total_cases"] >= 1
        assert stats["average_risk_score"] > 0
        
        # 4. GET Investigation Detail
        detail_response = await ac.get(f"/api/investigations/{investigation_id}")
        assert detail_response.status_code == 200
        detail = detail_response.json()
        assert detail["id"] == investigation_id
        assert "SOC Security Investigation Report" in detail["analysis_summary"]
        
        # 5. DELETE Investigation
        delete_response = await ac.get("/api/investigations") # confirm list first
        del_res = await ac.delete(f"/api/investigations/{investigation_id}")
        assert del_res.status_code == 200
        
        # Verify deletion
        detail_res_after = await ac.get(f"/api/investigations/{investigation_id}")
        assert detail_res_after.status_code == 404
