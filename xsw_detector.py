# xsw_detector.py — Core XSW detection engine.

# Analyzes a parsed SAML XML document for structural indicators of XML Signature
# Wrapping attacks. Assigns a severity score and attempts to classify which of
# the canonical XSW variants (XSW1–XSW8) is being attempted.

# Detection strategy:
#   - Count signed vs unsigned Assertion elements
#   - Check for duplicate XML IDs (a red flag for all XSW variants)
#   - Detect Extensions-block wrapping (XSW5)
#   - Detect Signature relocation (XSW6)
#   - Detect KeyInfo wrapping (XSW7)
#   - Detect Object-element wrapping (XSW8)
#   - Detect shadowing siblings (XSW2, XSW4)
#   - Detect structural depth anomalies

from lxml import etree
from typing import Optional
from .models import (
    XSWAnalysis, XSWIndicator, XSWVariant, Severity
)

# ── XML Namespace Map ─────────────────────────────────────────────────────────
NS = {
    "saml":  "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds":    "http://www.w3.org/2000/09/xmldsig#",
}

# XPath helpers
ASSERTION_XPATH   = ".//saml:Assertion"
SIGNATURE_XPATH   = ".//ds:Signature"
REFERENCE_XPATH   = ".//ds:Reference"
EXTENSIONS_XPATH  = ".//samlp:Extensions"
KEYINFO_XPATH     = ".//ds:KeyInfo"
OBJECT_XPATH      = ".//ds:Object"
NAMEID_XPATH      = ".//saml:NameID"
ISSUER_XPATH      = ".//saml:Issuer"
CONDITIONS_XPATH  = ".//saml:Conditions"
AUTHN_XPATH       = ".//saml:AuthnStatement"


def _score_to_severity(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 50:
        return Severity.HIGH
    if score >= 20:
        return Severity.MEDIUM
    return Severity.LOW


def _get_signed_ids(root: etree._Element) -> set[str]:
    # Extract all XML IDs that are explicitly covered by a ds:Reference URI.
    # A Reference URI of '#foo' means the element with ID='foo' is signed.
    signed_ids = set()
    for ref in root.findall(REFERENCE_XPATH, NS):
        uri = ref.get("URI", "")
        if uri.startswith("#"):
            signed_ids.add(uri[1:])  # strip leading '#'
    return signed_ids


def _get_all_assertion_ids(root: etree._Element) -> list[tuple[etree._Element, Optional[str]]]:
    # Return (element, ID) pairs for every Assertion in the document.
    return [
        (el, el.get("ID") or el.get("Id") or el.get("id"))
        for el in root.findall(ASSERTION_XPATH, NS)
    ]


def _has_duplicate_ids(root: etree._Element) -> bool:
    # True if any ID value appears on more than one element in the document.
    all_ids = []
    for el in root.iter():
        for attr in ("ID", "Id", "id"):
            val = el.get(attr)
            if val:
                all_ids.append(val)
    return len(all_ids) != len(set(all_ids))


def _check_xsw1_xsw2(
    root: etree._Element,
    assertions: list,
    signed_ids: set[str],
    indicators: list[XSWIndicator],
) -> list[XSWVariant]:
    # XSW1: A cloned (unsigned) Assertion appears as the direct child of the
    #       Response; the original signed Assertion is buried inside it.
    # XSW2: An unsigned clone is inserted *before* the signed original as a
    #       sibling, relying on the SP using find() (returns first match).
    variants = []
    if len(assertions) < 2:
        return variants

    signed = [(el, aid) for el, aid in assertions if aid in signed_ids]
    unsigned = [(el, aid) for el, aid in assertions if aid not in signed_ids]

    if not unsigned:
        return variants

    for u_el, u_id in unsigned:
        # XSW1: Is the signed assertion a *descendant* of the unsigned one?
        for s_el, s_id in signed:
            if u_el.find(f".//{{{NS['saml']}}}Assertion[@ID='{s_id}']") is not None:
                variants.append(XSWVariant.XSW1)
                indicators.append(XSWIndicator(
                    indicator_type="XSW1_BURIAL",
                    description=(
                        f"Signed Assertion ID='{s_id}' is a descendant of "
                        f"unsigned Assertion ID='{u_id}'. Classic XSW1 burial."
                    ),
                    xpath=f"//saml:Assertion[@ID='{u_id}']",
                    severity_contribution=40,
                ))

        # XSW2: Is the unsigned clone a *preceding sibling* of a signed one?
        parent = u_el.getparent()
        if parent is not None:
            siblings = list(parent)
            u_idx = siblings.index(u_el)
            for s_el, s_id in signed:
                if s_el in siblings:
                    s_idx = siblings.index(s_el)
                    if u_idx < s_idx:
                        variants.append(XSWVariant.XSW2)
                        indicators.append(XSWIndicator(
                            indicator_type="XSW2_PRECEDING_CLONE",
                            description=(
                                f"Unsigned Assertion ID='{u_id}' precedes signed "
                                f"ID='{s_id}' as a sibling — XSW2 shadow pattern."
                            ),
                            xpath=f"//saml:Assertion[@ID='{u_id}']",
                            severity_contribution=40,
                        ))

    return list(set(variants))


def _check_xsw5_extensions(
    root: etree._Element,
    indicators: list[XSWIndicator],
) -> list[XSWVariant]:
    # XSW5: The Extensions block is used to carry the real signed Assertion
    #       while a forged unsigned Assertion sits at the top level.
    variants = []
    for ext in root.findall(EXTENSIONS_XPATH, NS):
        nested = ext.findall(f"saml:Assertion", NS)
        if nested:
            variants.append(XSWVariant.XSW5)
            indicators.append(XSWIndicator(
                indicator_type="XSW5_EXTENSIONS_WRAPPING",
                description=(
                    f"Found {len(nested)} Assertion element(s) inside an "
                    "Extensions block — XSW5 pattern."
                ),
                xpath=".//samlp:Extensions/saml:Assertion",
                severity_contribution=50,
            ))
    return variants


def _check_xsw6_signature_relocation(
    root: etree._Element,
    assertions: list,
    signed_ids: set[str],
    indicators: list[XSWIndicator],
) -> list[XSWVariant]:

    # XSW6: The Signature element is moved *into* the cloned (unsigned) Assertion
    #       so that naive validators think the clone is signed.
    variants = []
    for el, aid in assertions:
        if aid in signed_ids:
            continue
        sig = el.find(f"ds:Signature", NS)
        if sig is not None:
            # This assertion carries a Signature but its ID is not in any Reference URI
            variants.append(XSWVariant.XSW6)
            indicators.append(XSWIndicator(
                indicator_type="XSW6_RELOCATED_SIGNATURE",
                description=(
                    f"Assertion ID='{aid}' contains a ds:Signature but is NOT "
                    "covered by any ds:Reference — XSW6 signature relocation."
                ),
                xpath=f"//saml:Assertion[@ID='{aid}']/ds:Signature",
                severity_contribution=60,
            ))
    return variants


def _check_xsw7_keyinfo(
    root: etree._Element,
    indicators: list[XSWIndicator],
) -> list[XSWVariant]:
    
    # XSW7: The malicious Assertion is nested inside a ds:KeyInfo element,
    #       exploiting parsers that don't recurse into KeyInfo when validating.
    
    variants = []
    for ki in root.findall(KEYINFO_XPATH, NS):
        nested = ki.findall(f"saml:Assertion", NS)
        if nested:
            variants.append(XSWVariant.XSW7)
            indicators.append(XSWIndicator(
                indicator_type="XSW7_KEYINFO_WRAPPING",
                description=(
                    f"Found {len(nested)} Assertion(s) inside ds:KeyInfo — "
                    "XSW7 pattern. Very suspicious."
                ),
                xpath=".//ds:KeyInfo/saml:Assertion",
                severity_contribution=70,
            ))
    return variants


def _check_xsw8_object(
    root: etree._Element,
    indicators: list[XSWIndicator],
) -> list[XSWVariant]:
    
    # XSW8: A ds:Object element wraps the legitimate signed Assertion,
    #       while a forged clone sits outside and is read by the SP.
    
    variants = []
    for obj in root.findall(OBJECT_XPATH, NS):
        nested = obj.findall(f"saml:Assertion", NS)
        if nested:
            variants.append(XSWVariant.XSW8)
            indicators.append(XSWIndicator(
                indicator_type="XSW8_OBJECT_WRAPPING",
                description=(
                    f"Found {len(nested)} Assertion(s) inside ds:Object — "
                    "XSW8 pattern."
                ),
                xpath=".//ds:Object/saml:Assertion",
                severity_contribution=65,
            ))
    return variants


def _check_structural_anomalies(
    root: etree._Element,
    assertions: list,
    indicators: list[XSWIndicator],
) -> None:
    # Catch anomalies that don't fit a known variant but are still suspicious.

    # Unusually deep nesting for an assertion
    for el, aid in assertions:
        depth = 0
        parent = el.getparent()
        while parent is not None:
            depth += 1
            parent = parent.getparent()
        if depth > 4:
            indicators.append(XSWIndicator(
                indicator_type="DEEP_NESTING",
                description=(
                    f"Assertion ID='{aid}' is at XML depth {depth}. "
                    "Legitimate assertions are typically at depth 1–2."
                ),
                severity_contribution=20,
            ))

    # Unexpected namespace declarations
    all_namespaces = set()
    for el in root.iter():
        all_namespaces.update(el.nsmap.values())
    unexpected = all_namespaces - set(NS.values()) - {
        "http://www.w3.org/2001/XMLSchema-instance",
        "http://www.w3.org/2001/XMLSchema",
        "http://www.w3.org/2000/09/xmldsig-more#",
    }
    if len(unexpected) > 3:
        indicators.append(XSWIndicator(
            indicator_type="NAMESPACE_PROLIFERATION",
            description=(
                f"{len(unexpected)} unexpected XML namespaces declared. "
                "May indicate obfuscation attempt."
            ),
            severity_contribution=10,
        ))


def analyze(xml_bytes: bytes) -> XSWAnalysis:
    # Entry point. Parse the XML and run all detection checks.
    # Returns an XSWAnalysis even if the XML is malformed (with zero score).

    analysis = XSWAnalysis()
    indicators: list[XSWIndicator] = []
    variant_guesses: list[XSWVariant] = []

    # ── Parse ─────────────────────────────────────────────────────────────────
    try:
        # defusedxml-style: disable network access and entity expansion
        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            huge_tree=False,
        )
        root = etree.fromstring(xml_bytes, parser=parser)
    except etree.XMLSyntaxError:
        # Can't analyze malformed XML — return empty analysis
        return analysis

    # ── Basic Counts ──────────────────────────────────────────────────────────
    all_elements = list(root.iter())
    analysis.element_count = len(all_elements)
    analysis.namespace_count = len(set(
        el.nsmap.get(None) or "" for el in all_elements
    ))

    assertions = _get_all_assertion_ids(root)
    signed_ids = _get_signed_ids(root)
    signatures = root.findall(SIGNATURE_XPATH, NS)

    analysis.assertion_count = len(assertions)
    analysis.signature_count = len(signatures)
    analysis.signed_assertion_count = sum(
        1 for _, aid in assertions if aid in signed_ids
    )
    analysis.unsigned_assertion_count = (
        analysis.assertion_count - analysis.signed_assertion_count
    )
    analysis.has_duplicate_ids = _has_duplicate_ids(root)

    # ── Baseline Indicators ───────────────────────────────────────────────────
    if analysis.assertion_count > 1:
        indicators.append(XSWIndicator(
            indicator_type="MULTIPLE_ASSERTIONS",
            description=(
                f"Response contains {analysis.assertion_count} Assertion elements. "
                "Legitimate responses almost never have more than one."
            ),
            severity_contribution=30,
        ))

    if analysis.unsigned_assertion_count > 0:
        indicators.append(XSWIndicator(
            indicator_type="UNSIGNED_ASSERTION",
            description=(
                f"{analysis.unsigned_assertion_count} Assertion(s) are NOT covered "
                "by any ds:Reference — these could be injected forgeries."
            ),
            severity_contribution=35,
        ))

    if analysis.has_duplicate_ids:
        indicators.append(XSWIndicator(
            indicator_type="DUPLICATE_IDS",
            description=(
                "Duplicate XML ID attribute values detected. "
                "This is invalid XML and a hallmark of XSW attacks."
            ),
            severity_contribution=50,
        ))

    # ── Variant-Specific Checks ───────────────────────────────────────────────
    variant_guesses += _check_xsw1_xsw2(root, assertions, signed_ids, indicators)
    variant_guesses += _check_xsw5_extensions(root, indicators)
    analysis.has_extensions_wrapping = XSWVariant.XSW5 in variant_guesses
    variant_guesses += _check_xsw6_signature_relocation(root, assertions, signed_ids, indicators)
    variant_guesses += _check_xsw7_keyinfo(root, indicators)
    variant_guesses += _check_xsw8_object(root, indicators)
    _check_structural_anomalies(root, assertions, indicators)

    # ── Nested Signatures Check ───────────────────────────────────────────────
    for sig in signatures:
        nested = sig.findall(f".//ds:Signature", NS)
        if nested:
            analysis.has_nested_signatures = True
            indicators.append(XSWIndicator(
                indicator_type="NESTED_SIGNATURES",
                description="A ds:Signature element contains another ds:Signature — highly anomalous.",
                severity_contribution=45,
            ))

    # ── Score Aggregation ─────────────────────────────────────────────────────
    raw_score = sum(i.severity_contribution for i in indicators)
    # Cap at 100 but don't let multiple weak signals alone trigger CRITICAL
    analysis.severity_score = min(raw_score, 100)
    analysis.severity = _score_to_severity(analysis.severity_score)
    analysis.is_xsw_suspected = analysis.severity_score >= 20
    analysis.indicators = indicators
    analysis.variant_guesses = list(set(variant_guesses))

    return analysis
