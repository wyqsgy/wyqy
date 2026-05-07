import pytest
from httpx import AsyncClient


@pytest.mark.anyio
async def test_health_check(client: AsyncClient):
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


@pytest.mark.anyio
async def test_list_tasks(client: AsyncClient):
    response = await client.get("/api/tasks")
    assert response.status_code == 200
    data = response.json()
    assert "tasks" in data
    assert "total" in data


@pytest.mark.anyio
async def test_create_task(client: AsyncClient):
    task_data = {
        "name": "Test Task",
        "target": "https://example.com",
        "scan_type": "quick"
    }
    response = await client.post("/api/tasks", json=task_data)
    assert response.status_code in [200, 201]
    data = response.json()
    assert data["name"] == task_data["name"]
    assert data["target"] == task_data["target"]
