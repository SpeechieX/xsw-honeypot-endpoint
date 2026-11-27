# test_xsw_detector.py — Tests for the XSW detection engine.

# Builds synthetic SAML XML payloads representing each attack variant and
# verifies the detector correctly identifies them.

import base64
import pytest
from lxml import etree

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services import xsw_detector, saml_parser
from app.models import XSWVariant, Severity


# ── XML Builders ──────────────────────────────────────────────────────────────

SAML_NS    = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS   = "urn:oasis:names:tc:SAML:2.0:protocol"
DS_NS      = "http://www.w3.org/2000/09/xmldsig#"


# Minimal well-formed SAML Response with one signed assertion.
def _build_clean_response(assertion_id: str = "legit001") -> bytes:
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}" xmlns:ds="{DS_NS}" ID="_resp1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <saml:Issuer>https://legitimate-idp.example.com</saml:Issuer>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:Reference URI="#{assertion_id}">
        <ds:DigestValue>abc123</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>fakesig</ds:SignatureValue>
  </ds:Signature>
  <saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Issuer>https://legitimate-idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">admin@target.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-01-01T00:00:00Z" NotOnOrAfter="2026-01-01T01:00:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://target.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>user</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
    <saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>"""
    return xml.encode("utf-8")


# XSW1: Unsigned evil clone at top level; real signed assertion buried inside.
# A vulnerable SP's find('.//Assertion') returns the evil clone.
def _build_xsw1_response() -> bytes:
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}" xmlns:ds="{DS_NS}" ID="_resp1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <saml:Issuer>https://attacker.example.com</saml:Issuer>
  <!-- XSW1: Evil unsigned clone — no Reference URI points to this ID -->
  <saml:Assertion ID="evil001" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Issuer>https://attacker.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>superadmin@target.com</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
    <!-- The real signed assertion is buried INSIDE the clone -->
    <saml:Assertion ID="legit001" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
      <saml:Issuer>https://legitimate-idp.example.com</saml:Issuer>
      <ds:Signature>
        <ds:SignedInfo>
          <ds:Reference URI="#legit001">
            <ds:DigestValue>abc123</ds:DigestValue>
          </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>validsig</ds:SignatureValue>
      </ds:Signature>
      <saml:Subject>
        <saml:NameID>normal@target.com</saml:NameID>
      </saml:Subject>
    </saml:Assertion>
  </saml:Assertion>
</samlp:Response>"""
    return xml.encode("utf-8")


# XSW2: Unsigned clone PRECEDES the signed assertion as a sibling.
# SP using find() gets the first match (the evil clone).
def _build_xsw2_response() -> bytes:
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}" xmlns:ds="{DS_NS}" ID="_resp1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <saml:Issuer>https://attacker.example.com</saml:Issuer>
  <!-- XSW2: Evil clone comes FIRST — find() returns this one -->
  <saml:Assertion ID="evil001" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Subject><saml:NameID>superadmin@target.com</saml:NameID></saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  <!-- Signed legitimate assertion comes SECOND -->
  <ds:Signature>
    <ds:SignedInfo>
      <ds:Reference URI="#legit001">
        <ds:DigestValue>abc123</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>validsig</ds:SignatureValue>
  </ds:Signature>
  <saml:Assertion ID="legit001" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Subject><saml:NameID>normal@target.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>"""
    return xml.encode("utf-8")


def _build_xsw5_response() -> bytes:
    """XSW5: Signed assertion hidden inside a samlp:Extensions block."""
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}" xmlns:ds="{DS_NS}" ID="_resp1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <saml:Issuer>https://attacker.example.com</saml:Issuer>
  <!-- XSW5: Evil unsigned clone at top level -->
  <saml:Assertion ID="evil001" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Subject><saml:NameID>superadmin@target.com</saml:NameID></saml:Subject>
  </saml:Assertion>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:Reference URI="#legit001"><ds:DigestValue>abc</ds:DigestValue></ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>validsig</ds:SignatureValue>
  </ds:Signature>
  <!-- Signed assertion buried in Extensions -->
  <samlp:Extensions>
    <saml:Assertion ID="legit001" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
      <saml:Subject><saml:NameID>normal@target.com</saml:NameID></saml:Subject>
    </saml:Assertion>
  </samlp:Extensions>
</samlp:Response>"""
    return xml.encode("utf-8")


def _build_xsw7_response() -> bytes:
    """XSW7: Malicious assertion nested inside ds:KeyInfo."""
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}" xmlns:ds="{DS_NS}" ID="_resp1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <saml:Issuer>https://attacker.example.com</saml:Issuer>
  <saml:Assertion ID="evil001" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Subject><saml:NameID>superadmin@target.com</saml:NameID></saml:Subject>
  </saml:Assertion>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:Reference URI="#legit001"><ds:DigestValue>abc</ds:DigestValue></ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>validsig</ds:SignatureValue>
    <!-- XSW7: Signed assertion hidden in KeyInfo -->
    <ds:KeyInfo>
      <saml:Assertion ID="legit001" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
        <saml:Subject><saml:NameID>normal@target.com</saml:NameID></saml:Subject>
      </saml:Assertion>
    </ds:KeyInfo>
  </ds:Signature>
</samlp:Response>"""
    return xml.encode("utf-8")


def _build_duplicate_id_response() -> bytes:
    """Two elements share the same ID — invalid XML, classic XSW red flag."""
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}" xmlns:ds="{DS_NS}" ID="_resp1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:Reference URI="#dup001"><ds:DigestValue>abc</ds:DigestValue></ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>validsig</ds:SignatureValue>
  </ds:Signature>
  <saml:Assertion ID="dup001" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
  </saml:Assertion>
  <!-- Second element with the SAME ID — invalid and suspicious -->
  <saml:Assertion ID="dup001" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Subject><saml:NameID>normal@target.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>"""
    return xml.encode("utf-8")


def _signed(assertion_id: str = "legit001", extra: str = "") -> str:
    return f'''<saml:Assertion ID="{assertion_id}">{extra}
      <saml:Subject><saml:NameID>normal@target.com</saml:NameID></saml:Subject>
    </saml:Assertion>'''


def _evil(extra: str = "") -> str:
    return f'''<saml:Assertion ID="evil001">{extra}
      <saml:Subject><saml:NameID>superadmin@target.com</saml:NameID></saml:Subject>
    </saml:Assertion>'''


def _response(body: str) -> bytes:
    """A Response whose signature references the assertion 'legit001'."""
    return f'''<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}" xmlns:ds="{DS_NS}" ID="_resp1">
  <ds:Signature><ds:SignedInfo><ds:Reference URI="#legit001"/></ds:SignedInfo></ds:Signature>
  {body}
</samlp:Response>'''.encode("utf-8")


XSW_VARIANT_PAYLOADS = {
    XSWVariant.XSW3: _response(f"<Wrapper>{_signed()}</Wrapper>"),
    XSWVariant.XSW4: _response(f"{_evil()}<Wrapper>{_signed()}</Wrapper>"),
    XSWVariant.XSW6: _response(
        _evil("<ds:Signature><ds:SignatureValue>x</ds:SignatureValue></ds:Signature>") + _signed()
    ),
    XSWVariant.XSW8: _response(
        f"{_evil()}<ds:Signature><ds:Object>{_signed()}</ds:Object></ds:Signature>"
    ),
}


# ── Tests: XSW3, XSW4, XSW6, XSW8 ─────────────────────────────────────────────

@pytest.mark.parametrize("variant", list(XSW_VARIANT_PAYLOADS))
def test_variant_detected(variant):
    analysis = xsw_detector.analyze(XSW_VARIANT_PAYLOADS[variant])
    assert variant in analysis.variant_guesses
    assert analysis.is_xsw_suspected


def test_xsw3_and_xsw4_are_distinct():
    xsw3 = xsw_detector.analyze(XSW_VARIANT_PAYLOADS[XSWVariant.XSW3]).variant_guesses
    xsw4 = xsw_detector.analyze(XSW_VARIANT_PAYLOADS[XSWVariant.XSW4]).variant_guesses
    assert XSWVariant.XSW4 not in xsw3
    assert XSWVariant.XSW3 not in xsw4


@pytest.mark.parametrize("builder", [
    _build_clean_response, _build_xsw1_response, _build_xsw2_response,
    _build_xsw5_response, _build_xsw7_response, _build_duplicate_id_response,
])
def test_wrapper_checks_do_not_fire_on_other_payloads(builder):
    guesses = xsw_detector.analyze(builder()).variant_guesses
    assert XSWVariant.XSW3 not in guesses
    assert XSWVariant.XSW4 not in guesses


@pytest.mark.parametrize("body", [
    _signed(),
    f"<saml:Advice>{_signed()}</saml:Advice>",
])
def test_expected_parents_are_not_flagged(body):
    assert not xsw_detector.analyze(_response(body)).variant_guesses


# ── Tests: Clean Responses ────────────────────────────────────────────────────

class TestCleanResponse:
    def test_clean_response_no_xsw(self):
        analysis = xsw_detector.analyze(_build_clean_response())
        assert not analysis.is_xsw_suspected
        assert analysis.severity == Severity.LOW
        assert analysis.severity_score < 20

    def test_clean_response_counts(self):
        analysis = xsw_detector.analyze(_build_clean_response())
        assert analysis.assertion_count == 1
        assert analysis.signed_assertion_count == 1
        assert analysis.unsigned_assertion_count == 0
        assert analysis.signature_count == 1

    def test_clean_response_no_variants(self):
        analysis = xsw_detector.analyze(_build_clean_response())
        assert len(analysis.variant_guesses) == 0

    def test_malformed_xml_returns_empty_analysis(self):
        analysis = xsw_detector.analyze(b"this is not xml <<>>")
        assert analysis.severity_score == 0
        assert not analysis.is_xsw_suspected


# ── Tests: XSW1 ───────────────────────────────────────────────────────────────

class TestXSW1:
    def setup_method(self):
        self.analysis = xsw_detector.analyze(_build_xsw1_response())

    def test_xsw_suspected(self):
        assert self.analysis.is_xsw_suspected

    def test_xsw1_variant_detected(self):
        assert XSWVariant.XSW1 in self.analysis.variant_guesses

    def test_unsigned_assertion_detected(self):
        assert self.analysis.unsigned_assertion_count >= 1

    def test_multiple_assertions_detected(self):
        assert self.analysis.assertion_count == 2

    def test_high_or_critical_severity(self):
        assert self.analysis.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_burial_indicator_present(self):
        types = [i.indicator_type for i in self.analysis.indicators]
        assert "XSW1_BURIAL" in types


# ── Tests: XSW2 ───────────────────────────────────────────────────────────────

class TestXSW2:
    def setup_method(self):
        self.analysis = xsw_detector.analyze(_build_xsw2_response())

    def test_xsw_suspected(self):
        assert self.analysis.is_xsw_suspected

    def test_xsw2_variant_detected(self):
        assert XSWVariant.XSW2 in self.analysis.variant_guesses

    def test_preceding_clone_indicator(self):
        types = [i.indicator_type for i in self.analysis.indicators]
        assert "XSW2_PRECEDING_CLONE" in types


# ── Tests: XSW5 ───────────────────────────────────────────────────────────────

class TestXSW5:
    def setup_method(self):
        self.analysis = xsw_detector.analyze(_build_xsw5_response())

    def test_xsw5_detected(self):
        assert XSWVariant.XSW5 in self.analysis.variant_guesses

    def test_extensions_flag(self):
        assert self.analysis.has_extensions_wrapping

    def test_extensions_indicator(self):
        types = [i.indicator_type for i in self.analysis.indicators]
        assert "XSW5_EXTENSIONS_WRAPPING" in types


# ── Tests: XSW7 ───────────────────────────────────────────────────────────────

class TestXSW7:
    def setup_method(self):
        self.analysis = xsw_detector.analyze(_build_xsw7_response())

    def test_xsw7_detected(self):
        assert XSWVariant.XSW7 in self.analysis.variant_guesses

    def test_keyinfo_indicator(self):
        types = [i.indicator_type for i in self.analysis.indicators]
        assert "XSW7_KEYINFO_WRAPPING" in types

    def test_high_severity(self):
        assert self.analysis.severity in (Severity.HIGH, Severity.CRITICAL)


# ── Tests: Duplicate IDs ──────────────────────────────────────────────────────

class TestDuplicateIds:
    def setup_method(self):
        self.analysis = xsw_detector.analyze(_build_duplicate_id_response())

    def test_duplicate_ids_detected(self):
        assert self.analysis.has_duplicate_ids

    def test_duplicate_id_indicator(self):
        types = [i.indicator_type for i in self.analysis.indicators]
        assert "DUPLICATE_IDS" in types

    def test_xsw_suspected(self):
        assert self.analysis.is_xsw_suspected


# ── Tests: Severity Scoring ───────────────────────────────────────────────────

class TestSeverityScoring:
    def test_score_is_capped_at_100(self):
        # XSW1 + XSW5 + duplicate IDs — lots of signals
        analysis = xsw_detector.analyze(_build_xsw1_response())
        assert 0 <= analysis.severity_score <= 100

    def test_clean_score_is_low(self):
        analysis = xsw_detector.analyze(_build_clean_response())
        assert analysis.severity_score < 20

    def test_xsw1_score_is_high(self):
        analysis = xsw_detector.analyze(_build_xsw1_response())
        assert analysis.severity_score >= 50


# ── Tests: SAML Parser ────────────────────────────────────────────────────────

class TestSAMLParser:
    def test_parse_clean_response(self):
        xml_bytes = _build_clean_response()
        b64 = base64.b64encode(xml_bytes).decode()
        result = saml_parser.parse_saml_response(b64)
        assert not result["is_malformed_xml"]
        assert result["issuer"] == "https://legitimate-idp.example.com"
        assert result["name_id"] == "admin@target.com"
        assert result["audience"] == "https://target.example.com"

    def test_parse_extracts_attributes(self):
        xml_bytes = _build_clean_response()
        b64 = base64.b64encode(xml_bytes).decode()
        result = saml_parser.parse_saml_response(b64)
        assert "role" in result["attributes"]
        assert result["attributes"]["role"] == ["user"]

    def test_parse_invalid_base64(self):
        result = saml_parser.parse_saml_response("!!!not-base64!!!")
        assert result["is_malformed_xml"]
        assert len(result["parse_errors"]) > 0

    def test_parse_malformed_xml(self):
        b64 = base64.b64encode(b"<broken xml <<<<").decode()
        result = saml_parser.parse_saml_response(b64)
        assert result["is_malformed_xml"]

    def test_decode_with_whitespace_padding(self):
        xml_bytes = _build_clean_response()
        b64 = base64.b64encode(xml_bytes).decode()
        # Add whitespace (some IdPs do this)
        b64_with_ws = "  " + b64[:20] + "\n" + b64[20:] + "  "
        result = saml_parser.parse_saml_response(b64_with_ws)
        assert not result["is_malformed_xml"]
