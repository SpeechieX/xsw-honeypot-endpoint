# models.py — Pydantic data models for captures, XSW analysis, and alerts.

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum
import uuid


class XSWVariant(str, Enum):
    # The 8 canonical XSW attack variants documented by Somorovsky et al.
    # Each exploits a different structural trick to make the SP read a different
    # element than the one covered by the signature.

    XSW1 = "XSW1"   # Duplicate root assertion, original moved inside extensions
    XSW2 = "XSW2"   # Unsigned clone inserted before signed original
    XSW3 = "XSW3"   # Signed element wrapped inside new unsigned parent
    XSW4 = "XSW4"   # Unsigned sibling inserted, signed element buried
    XSW5 = "XSW5"   # Extensions block used to shadow the signed assertion
    XSW6 = "XSW6"   # Signature element relocated into the cloned assertion
    XSW7 = "XSW7"   # Clone placed inside the KeyInfo element
    XSW8 = "XSW8"   # Object element used as a wrapper around the signed content
    UNKNOWN = "UNKNOWN"  # Novel or unclassified wrapping structure


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class XSWIndicator(BaseModel):
#   A single structural anomaly detected in a SAML response.
    indicator_type: str
    description: str
    xpath: Optional[str] = None          # XPath location of the suspicious element
    severity_contribution: int = 0       # How much this adds to the overall score (0–100)


class XSWAnalysis(BaseModel):
#   Full analysis result for one SAML response.
    is_xsw_suspected: bool = False
    severity: Severity = Severity.LOW
    severity_score: int = 0              # 0–100 composite score
    variant_guesses: list[XSWVariant] = Field(default_factory=list)
    indicators: list[XSWIndicator] = Field(default_factory=list)
    assertion_count: int = 0             # Total <Assertion> elements found
    signed_assertion_count: int = 0      # Assertions covered by a Signature
    unsigned_assertion_count: int = 0    # Assertions NOT covered by any Signature
    signature_count: int = 0             # Total <Signature> elements found
    has_duplicate_ids: bool = False      # Same ID attribute appears more than once
    has_extensions_wrapping: bool = False
    has_nested_signatures: bool = False
    namespace_count: int = 0
    element_count: int = 0


class RequestMetadata(BaseModel):
    # HTTP-level metadata captured from the incoming request.
    source_ip: str
    user_agent: Optional[str] = None
    referer: Optional[str] = None
    x_forwarded_for: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    extra_headers: dict[str, str] = Field(default_factory=dict)


class SAMLCapture(BaseModel):

    # Complete record of one honeypot hit — everything we received and
    # everything we inferred about it. This is the primary storage object.
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    captured_at: datetime = Field(default_factory=datetime.utcnow)

    # Raw payload
    raw_saml_response: str              # Base64-encoded SAMLResponse form field
    raw_xml: Optional[str] = None       # Decoded XML (may fail if malformed)
    relay_state: Optional[str] = None   # RelayState form field if present

    # Parsed SAML fields (best-effort — may be None if XML is malformed)
    issuer: Optional[str] = None
    name_id: Optional[str] = None
    name_id_format: Optional[str] = None
    assertion_id: Optional[str] = None
    not_before: Optional[datetime] = None
    not_on_or_after: Optional[datetime] = None
    audience: Optional[str] = None
    authn_context: Optional[str] = None
    attributes: dict[str, list[str]] = Field(default_factory=dict)

    # XSW analysis
    xsw_analysis: XSWAnalysis = Field(default_factory=XSWAnalysis)

    # Request metadata
    request: RequestMetadata

    # Processing flags
    is_malformed_xml: bool = False
    parse_errors: list[str] = Field(default_factory=list)

    @property
    def short_id(self) -> str:
        return self.id[:8]

    @property
    def severity_badge_class(self) -> str:
        return {
            Severity.LOW: "badge-low",
            Severity.MEDIUM: "badge-medium",
            Severity.HIGH: "badge-high",
            Severity.CRITICAL: "badge-critical",
        }.get(self.xsw_analysis.severity, "badge-low")


class AlertPayload(BaseModel):
    # Webhook alert payload sent to Slack / Discord / custom endpoints.
    honeypot_hit_id: str
    captured_at: str
    source_ip: str
    issuer: Optional[str]
    severity: str
    severity_score: int
    is_xsw_suspected: bool
    variant_guesses: list[str]
    indicators: list[str]
    dashboard_url: Optional[str] = None


class DashboardStats(BaseModel):
    # Aggregate statistics for the dashboard summary view.
    total_captures: int = 0
    xsw_suspected: int = 0
    unique_ips: int = 0
    unique_issuers: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    variant_breakdown: dict[str, int] = Field(default_factory=dict)
    recent_captures: list[SAMLCapture] = Field(default_factory=list)
