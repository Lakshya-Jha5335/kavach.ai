import pytest
import respx
from httpx import Response

from database import init_db, report_threat_db
from redirect_tracer import trace_redirects
from vuln_scanner import scan_web_security
from content_scanner import analyze_page_content
from threat_intel import check_threat_intel


@pytest.mark.asyncio
@respx.mock
async def test_redirect_chain_detection():
    respx.get("https://bit.ly/fake-bank").mock(
        return_value=Response(302, headers={"Location": "http://evil-login-verify.com/auth"})
    )
    respx.get("http://evil-login-verify.com/auth").mock(
        return_value=Response(200, text="<html><body>Login</body></html>")
    )

    result = await trace_redirects("https://bit.ly/fake-bank")
    assert result["hop_count"] == 2
    assert result["deduction"] >= 25
    assert any("Cross-domain redirect" in f for f in result["flags"])


@pytest.mark.asyncio
@respx.mock
async def test_exposed_env_detection():
    respx.get("https://example.com/.env").mock(return_value=Response(200, text="DB_PASSWORD=secret"))
    respx.get("https://example.com/.git/config").mock(return_value=Response(404))
    respx.get("https://example.com/.well-known/security.txt").mock(return_value=Response(404))
    respx.get("https://example.com/robots.txt").mock(return_value=Response(200, text="User-agent: *"))

    result = await scan_web_security("https://example.com")
    assert "/.env" in result["exposed_files"]
    assert result["deduction"] >= 30


@pytest.mark.asyncio
@respx.mock
async def test_ai_brand_impersonation_detection():
    fake_html = """
    <html><head><title>SBI NetBanking KYC Update</title></head>
    <body>Verify your SBI bank account immediately suspended kyc update pan card otp password
    <form><input type="password" /></form></body></html>
    """
    respx.get("https://sbi-kyc-alert.xyz").mock(return_value=Response(200, text=fake_html))

    result = await analyze_page_content("https://sbi-kyc-alert.xyz")
    assert result["ai_analysis"]["impersonating"] is True
    assert result["ai_analysis"]["target_brand"] == "SBI"
    assert result["deduction"] >= 35


@pytest.mark.asyncio
async def test_sqlite_collaborative_intel():
    init_db()
    report_threat_db("http://phish-test-domain.xyz", "phishing", "Fake portal")
    intel = await check_threat_intel("http://phish-test-domain.xyz")
    assert len(intel["community_reports"]) >= 1
    assert intel["deduction"] >= 25