
# alerting.py — Webhook alerting service.

# Sends structured alerts to Slack, Discord, or any custom HTTP webhook
# when a honeypot hit meets the configured severity threshold.


import httpx
from datetime import datetime
from ..models import SAMLCapture, AlertPayload
from ..config import settings


def _build_slack_blocks(capture: SAMLCapture) -> dict:
    """Build a rich Slack Block Kit message for a honeypot hit."""
    severity = capture.xsw_analysis.severity.value
    score = capture.xsw_analysis.severity_score
    emoji = {"LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "🚨"}.get(severity, "⚠️")

    indicator_lines = "\n".join(
        f"• *{ind.indicator_type}*: {ind.description}"
        for ind in capture.xsw_analysis.indicators[:5]  # cap at 5 for readability
    )
    if len(capture.xsw_analysis.indicators) > 5:
        indicator_lines += f"\n_...and {len(capture.xsw_analysis.indicators) - 5} more_"

    variants = ", ".join(v.value for v in capture.xsw_analysis.variant_guesses) or "None detected"

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} XSW Honeypot Hit — {severity} ({score}/100)"
            }
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Capture ID:*\n`{capture.short_id}`"},
                {"type": "mrkdwn", "text": f"*Time:*\n{capture.captured_at.strftime('%Y-%m-%d %H:%M:%S')} UTC"},
                {"type": "mrkdwn", "text": f"*Source IP:*\n`{capture.request.source_ip}`"},
                {"type": "mrkdwn", "text": f"*Issuer:*\n{capture.issuer or '_unknown_'}"},
                {"type": "mrkdwn", "text": f"*XSW Suspected:*\n{'✅ Yes' if capture.xsw_analysis.is_xsw_suspected else '❌ No'}"},
                {"type": "mrkdwn", "text": f"*Variants Guessed:*\n{variants}"},
            ]
        },
    ]

    if indicator_lines:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Indicators:*\n{indicator_lines}"}
        })

    if settings.dashboard_enabled:
        blocks.append({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": {"type": "plain_text", "text": "View in Dashboard"},
                "url": f"{settings.dashboard_path}/captures/{capture.id}",
                "style": "danger" if severity in ("HIGH", "CRITICAL") else "primary",
            }]
        })

    return {"blocks": blocks}


def _build_discord_embed(capture: SAMLCapture) -> dict:
    # Build a Discord embed message for a honeypot hit.
    severity = capture.xsw_analysis.severity.value
    color = {"LOW": 0xFFCC00, "MEDIUM": 0xFF8800, "HIGH": 0xFF3300, "CRITICAL": 0xCC0000}.get(severity, 0xAAAAAA)

    fields = [
        {"name": "Source IP", "value": f"`{capture.request.source_ip}`", "inline": True},
        {"name": "Severity", "value": f"{severity} ({capture.xsw_analysis.severity_score}/100)", "inline": True},
        {"name": "Issuer", "value": capture.issuer or "unknown", "inline": True},
        {"name": "XSW Suspected", "value": "Yes" if capture.xsw_analysis.is_xsw_suspected else "No", "inline": True},
        {"name": "Variants", "value": ", ".join(v.value for v in capture.xsw_analysis.variant_guesses) or "None", "inline": True},
        {"name": "Assertions", "value": str(capture.xsw_analysis.assertion_count), "inline": True},
    ]

    if capture.xsw_analysis.indicators:
        top = capture.xsw_analysis.indicators[0]
        fields.append({
            "name": f"Top Indicator: {top.indicator_type}",
            "value": top.description[:200],
            "inline": False
        })

    return {
        "embeds": [{
            "title": f"🎯 XSW Honeypot Hit — {severity}",
            "color": color,
            "fields": fields,
            "footer": {"text": f"Capture ID: {capture.short_id}"},
            "timestamp": capture.captured_at.isoformat(),
        }]
    }


def _build_generic_payload(capture: SAMLCapture) -> dict:
    # Plain JSON payload for custom webhooks.
    return AlertPayload(
        honeypot_hit_id=capture.id,
        captured_at=capture.captured_at.isoformat(),
        source_ip=capture.request.source_ip,
        issuer=capture.issuer,
        severity=capture.xsw_analysis.severity.value,
        severity_score=capture.xsw_analysis.severity_score,
        is_xsw_suspected=capture.xsw_analysis.is_xsw_suspected,
        variant_guesses=[v.value for v in capture.xsw_analysis.variant_guesses],
        indicators=[i.indicator_type for i in capture.xsw_analysis.indicators],
    ).model_dump()


async def send_alert(capture: SAMLCapture) -> None:
    # Send a webhook alert if the capture meets the configured thresholds.
    # Silently logs failures — alerting must never crash the honeypot.
    url = settings.alert_webhook_url
    if not url:
        return

    # Threshold check
    if settings.alert_on_xsw_only and not capture.xsw_analysis.is_xsw_suspected:
        return
    if capture.xsw_analysis.severity_score < settings.alert_min_severity:
        return

    # Build payload based on webhook type
    if "hooks.slack.com" in url:
        payload = _build_slack_blocks(capture)
    elif "discord.com/api/webhooks" in url:
        payload = _build_discord_embed(capture)
    else:
        payload = _build_generic_payload(capture)

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(url, json=payload)
            if response.status_code not in (200, 204):
                print(f"[alert] Webhook returned {response.status_code}: {response.text[:200]}")
    except Exception as e:
        print(f"[alert] Failed to send webhook: {e}")
