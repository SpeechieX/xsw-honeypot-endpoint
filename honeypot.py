# honeypot.py — The fake SAML ACS (Assertion Consumer Service) endpoint.

# This router presents a convincing SAML SP surface that:
#   - Accepts ALL incoming SAML responses (no signature validation)
#   - Decodes and parses every payload
#   - Runs XSW detection on the XML
#   - Persists the full capture
#   - Fires alerts asynchronously
#   - Returns a realistic-looking (but harmless) redirect response

# The endpoint deliberately looks like a real SP to maximize attacker engagement.

import asyncio
from datetime import datetime
from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import RedirectResponse, HTMLResponse
from typing import Optional

from ..models import SAMLCapture, RequestMetadata, XSWAnalysis
from ..services import saml_parser, xsw_detector, alerting
from ..services.storage import storage
from ..config import settings

router = APIRouter()

# Headers that suggest this is a real SP (adds realism to the honeypot)
_REALISTIC_HEADERS = {
    "Cache-Control": "no-store, no-cache",
    "Pragma": "no-cache",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
}


def _extract_request_metadata(request: Request) -> RequestMetadata:
    # Pull all useful HTTP metadata from the incoming request.
    headers = dict(request.headers)
    # Collect non-standard / interesting headers
    skip = {"host", "content-type", "content-length", "user-agent", "referer",
            "accept", "accept-encoding", "accept-language", "connection"}
    extra = {k: v for k, v in headers.items() if k.lower() not in skip}

    return RequestMetadata(
        source_ip=request.client.host if request.client else "unknown",
        user_agent=headers.get("user-agent"),
        referer=headers.get("referer"),
        x_forwarded_for=headers.get("x-forwarded-for"),
        content_type=headers.get("content-type"),
        content_length=int(headers.get("content-length", 0)) or None,
        extra_headers=extra,
    )


@router.post(settings.honeypot_path, include_in_schema=False)
async def fake_acs(
    request: Request,
    SAMLResponse: str = Form(...),
    RelayState: Optional[str] = Form(default=None),
) -> Response:
   
    # The honeypot endpoint. Accepts everything, validates nothing,
    # records everything, alerts on suspicious payloads.
    
    # ── 1. Guard: payload size limit ─────────────────────────────────────────
    if len(SAMLResponse) > settings.max_payload_bytes:
        # Still log the hit but truncate
        SAMLResponse = SAMLResponse[:settings.max_payload_bytes]

    # ── 2. Parse the SAML response (best-effort) ──────────────────────────────
    parsed = saml_parser.parse_saml_response(SAMLResponse)

    # ── 3. Run XSW detection ──────────────────────────────────────────────────
    xsw_analysis = XSWAnalysis()
    xml_bytes = parsed.pop("_xml_bytes", None)
    if xml_bytes and not parsed["is_malformed_xml"]:
        xsw_analysis = xsw_detector.analyze(xml_bytes)

    # ── 4. Build the capture record ───────────────────────────────────────────
    capture = SAMLCapture(
        raw_saml_response=SAMLResponse,
        relay_state=RelayState,
        request=_extract_request_metadata(request),
        xsw_analysis=xsw_analysis,
        **{k: v for k, v in parsed.items() if k != "_xml_bytes"},
    )

    # ── 5. Persist + alert (fire-and-forget so we respond quickly) ────────────
    asyncio.create_task(storage.save_capture(capture))
    asyncio.create_task(alerting.send_alert(capture))

    # ── 6. Return a realistic-looking redirect (like a real SP would) ─────────
    # This keeps attackers engaged and unaware they've hit a honeypot.
    # We redirect to a benign page rather than showing an error.
    target = RelayState if RelayState and RelayState.startswith("http") else "/"
    response = RedirectResponse(url=target, status_code=302)
    for k, v in _REALISTIC_HEADERS.items():
        response.headers[k] = v
    return response


@router.get(settings.honeypot_path, include_in_schema=False)
async def fake_acs_get(request: Request) -> Response:
    
    # Handle GET requests to the ACS URL — some scanners probe with GET first.
    # Return a 405 with a realistic SP error page.
    
    asyncio.create_task(_log_probe(request))
    html = """<!DOCTYPE html>
<html><head><title>SSO Error</title></head>
<body>
<h2>Single Sign-On Error</h2>
<p>This endpoint only accepts HTTP POST requests from your Identity Provider.</p>
<p>Error code: <code>SAML_BINDING_UNSUPPORTED</code></p>
</body></html>"""
    return HTMLResponse(content=html, status_code=405, headers=_REALISTIC_HEADERS)


async def _log_probe(request: Request) -> None:
    # Log a GET probe as a low-severity capture (no SAMLResponse to parse).
    import uuid
    from ..models import SAMLCapture, XSWAnalysis, Severity
    # Create a minimal capture record just to track the probe
    capture = SAMLCapture(
        id=str(uuid.uuid4()),
        raw_saml_response="[GET probe — no SAMLResponse]",
        request=_extract_request_metadata(request),
        xsw_analysis=XSWAnalysis(),
        is_malformed_xml=True,
        parse_errors=["GET probe — no SAMLResponse body"],
    )
    await storage.save_capture(capture)
