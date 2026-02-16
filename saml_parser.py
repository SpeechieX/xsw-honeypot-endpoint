
# saml_parser.py — Best-effort SAML response parser.

# The honeypot intentionally accepts *everything*, including malformed, truncated,
# and adversarially crafted payloads. Every field is optional — we capture
# whatever we can and record parse errors for the rest.


import base64
import re
from datetime import datetime
from typing import Optional
from lxml import etree

NS = {
    "saml":  "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds":    "http://www.w3.org/2000/09/xmldsig#",
}


def _safe_text(el: Optional[etree._Element]) -> Optional[str]:
    """Return stripped text content of an element, or None."""
    if el is None:
        return None
    return (el.text or "").strip() or None


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 datetime string, returning None on failure."""
    if not value:
        return None
    try:
        # Handle both 'Z' suffix and +00:00 offset
        value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return None


def decode_saml_response(raw_b64: str) -> tuple[Optional[str], Optional[bytes], list[str]]:
    # Decode a Base64-encoded SAMLResponse field.
    # Returns (xml_string, xml_bytes, errors).
    # Some implementations add whitespace or use non-standard padding.
    errors = []
    # Normalize: strip whitespace, fix padding
    cleaned = re.sub(r"\s+", "", raw_b64)
    # Try with and without padding fixes
    for candidate in [cleaned, cleaned + "==", cleaned + "="]:
        try:
            xml_bytes = base64.b64decode(candidate)
            xml_str = xml_bytes.decode("utf-8", errors="replace")
            return xml_str, xml_bytes, errors
        except Exception:
            continue
    errors.append("Base64 decoding failed after multiple padding strategies")
    return None, None, errors


def extract_saml_fields(root: etree._Element) -> dict:
    # Walk the XML tree and extract well-known SAML fields.
    # All accesses are guarded — nothing raises here.
    fields: dict = {
        "issuer": None,
        "name_id": None,
        "name_id_format": None,
        "assertion_id": None,
        "not_before": None,
        "not_on_or_after": None,
        "audience": None,
        "authn_context": None,
        "attributes": {},
    }

    # Issuer — look in both Response and first Assertion
    issuer_el = root.find("saml:Issuer", NS) or root.find(".//saml:Issuer", NS)
    fields["issuer"] = _safe_text(issuer_el)

    # First Assertion (what a non-hardened SP would read)
    assertion = root.find(".//saml:Assertion", NS)
    if assertion is None:
        return fields

    fields["assertion_id"] = assertion.get("ID") or assertion.get("Id")

    # NameID
    name_id_el = assertion.find(".//saml:NameID", NS)
    if name_id_el is not None:
        fields["name_id"] = _safe_text(name_id_el)
        fields["name_id_format"] = name_id_el.get("Format")

    # Conditions (validity window)
    conditions = assertion.find("saml:Conditions", NS)
    if conditions is not None:
        fields["not_before"] = _parse_datetime(conditions.get("NotBefore"))
        fields["not_on_or_after"] = _parse_datetime(conditions.get("NotOnOrAfter"))

        # Audience
        aud_el = conditions.find(".//saml:Audience", NS)
        fields["audience"] = _safe_text(aud_el)

    # AuthnContext
    authn_el = assertion.find(".//saml:AuthnContextClassRef", NS)
    fields["authn_context"] = _safe_text(authn_el)

    # Attributes — collect all values per attribute name
    attrs: dict[str, list[str]] = {}
    for attr_el in assertion.findall(".//saml:Attribute", NS):
        name = attr_el.get("Name") or attr_el.get("FriendlyName") or "unknown"
        values = [
            _safe_text(v) or ""
            for v in attr_el.findall("saml:AttributeValue", NS)
        ]
        attrs[name] = values
    fields["attributes"] = attrs

    return fields

    # Full parse pipeline:
    #   1. Base64-decode the SAMLResponse
    #   2. Parse the XML
    #   3. Extract fields
    #   4. Return a flat dict suitable for SAMLCapture construction

def parse_saml_response(raw_b64: str) -> dict:
    result = {
        "raw_xml": None,
        "is_malformed_xml": False,
        "parse_errors": [],
        # SAML fields
        "issuer": None,
        "name_id": None,
        "name_id_format": None,
        "assertion_id": None,
        "not_before": None,
        "not_on_or_after": None,
        "audience": None,
        "authn_context": None,
        "attributes": {},
        # Raw bytes for XSW detector
        "_xml_bytes": None,
    }

    # Step 1: Decode
    xml_str, xml_bytes, decode_errors = decode_saml_response(raw_b64)
    result["parse_errors"].extend(decode_errors)
    if xml_bytes is None:
        result["is_malformed_xml"] = True
        return result

    result["raw_xml"] = xml_str
    result["_xml_bytes"] = xml_bytes

    # Step 2: Parse XML
    try:
        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            huge_tree=False,
        )
        root = etree.fromstring(xml_bytes, parser=parser)
    except etree.XMLSyntaxError as e:
        result["is_malformed_xml"] = True
        result["parse_errors"].append(f"XML parse error: {e}")
        return result

    # Step 3: Extract fields
    try:
        fields = extract_saml_fields(root)
        result.update(fields)
    except Exception as e:
        result["parse_errors"].append(f"Field extraction error: {e}")

    return result
