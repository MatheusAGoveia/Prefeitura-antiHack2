"""
Testes Unitários da API de Dashboard de Desenvolvimento
GovSec Shield — Dashboard API Tests
"""

import pytest
from src.api.dashboard_api import get_memoria_dashboard
from src.api.main import get_dashboard

@pytest.mark.asyncio
async def test_get_memoria_api_endpoint():
    res = await get_memoria_dashboard()
    assert res.memoria is not None
    assert res.total_steps > 0
    assert res.progress_percentage > 0
    assert res.git.branch != ""

@pytest.mark.asyncio
async def test_get_dashboard_html_page():
    html = await get_dashboard()
    assert "GovSec Shield — Dashboard de Desenvolvimento" in html

