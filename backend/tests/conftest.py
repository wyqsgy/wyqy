import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as ac:
        yield ac
