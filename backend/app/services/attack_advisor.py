"""Grounded attack explanations with optional server-side LLM enrichment."""
from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

GUIDANCE: dict[str, dict[str, Any]] = {
    "BENIGN": {"summary": "The classifier did not identify this flow as malicious.", "risk": "Continue monitoring and investigate if other signals disagree.", "actions": ["Keep detection rules and endpoint protections current.", "Correlate this flow with authentication and host telemetry if it appears unusual."]},
    "PortScan": {"summary": "A host is probing multiple ports to discover exposed services.", "risk": "Reconnaissance can precede exploitation and may reveal unnecessary services.", "actions": ["Verify the source host and whether the scan is authorized.", "Restrict inbound access with security groups or firewall rules.", "Disable unused services and review exposed ports.", "Apply rate limits or temporary blocks only after validating business impact."]},
    "DDoS": {"summary": "Distributed traffic is overwhelming or attempting to overwhelm a network service.", "risk": "Service availability may degrade for legitimate users.", "actions": ["Engage your upstream provider or DDoS scrubbing service.", "Enable CDN, WAF, and load-balancer rate controls.", "Scale or isolate affected services and preserve traffic logs."]},
    "DoS": {"summary": "Traffic is consistent with a denial-of-service attempt against a service.", "risk": "The target service may become slow or unavailable.", "actions": ["Check resource utilization and service health.", "Apply edge rate limits and filtering for the affected protocol.", "Coordinate with the network provider if volume exceeds local capacity."]},
    "DoS Hulk": {"summary": "High-rate HTTP requests resemble the Hulk application-layer denial-of-service pattern.", "risk": "Web workers and application resources may be exhausted.", "actions": ["Enable WAF bot and rate controls for the affected routes.", "Inspect request paths and web server saturation.", "Use caching and upstream protection while preserving logs."]},
    "DoS GoldenEye": {"summary": "HTTP traffic resembles the GoldenEye denial-of-service tool pattern.", "risk": "Repeated web requests can exhaust server connections and workers.", "actions": ["Apply WAF and reverse-proxy rate limits.", "Review connection counts and server worker utilization.", "Escalate to upstream DDoS protection if service availability is affected."]},
    "DoS slowloris": {"summary": "Long-lived, incomplete HTTP connections resemble a Slowloris attack.", "risk": "Connection slots can be held open and deny service to legitimate clients.", "actions": ["Set request and header read timeouts at the proxy or web server.", "Limit concurrent connections per client.", "Use a reverse proxy or CDN to absorb slow connections."]},
    "DoS Slowhttptest": {"summary": "Slow or incomplete HTTP requests resemble a SlowHTTPTest denial-of-service pattern.", "risk": "Web server connection pools may be consumed over time.", "actions": ["Set strict header and body timeouts.", "Limit concurrent connections and request body sizes.", "Review proxy logs and confirm server health."]},
    "Web Attack - Sql Injection": {"summary": "Request behavior resembles SQL injection probing or payloads.", "risk": "If exploitable, an attacker may read or alter application data.", "actions": ["Use parameterized queries and remove dynamic SQL construction.", "Validate inputs server-side and apply least-privilege database accounts.", "Review application and database logs for successful queries or data access.", "Patch the affected application and use WAF rules as a compensating control."]},
    "Web Attack - XSS": {"summary": "Request behavior resembles cross-site scripting payloads.", "risk": "A successful injection may execute script in another user's browser.", "actions": ["Apply context-aware output encoding and safe templating.", "Validate inputs and sanitize rich text with a maintained library.", "Deploy a restrictive Content Security Policy and review affected pages."]},
    "Web Attack - Brute Force": {"summary": "Repeated login attempts resemble password guessing against a web service.", "risk": "Weak or reused credentials may be compromised.", "actions": ["Enforce MFA and rate-limit login attempts.", "Review authentication logs for successful logins from the source.", "Apply temporary account protections and reset credentials if compromise is confirmed."]},
    "FTP-Patator": {"summary": "Repeated FTP authentication attempts resemble credential brute forcing.", "risk": "An exposed FTP service or weak credentials may allow unauthorized access.", "actions": ["Disable FTP or replace it with SFTP/SSH where possible.", "Restrict access to trusted networks and enforce strong credentials.", "Review authentication logs and rotate any potentially exposed credentials."]},
    "SSH-Patator": {"summary": "Repeated SSH authentication attempts resemble credential brute forcing.", "risk": "Successful guessing could provide remote shell access.", "actions": ["Require SSH keys and MFA where supported; disable password login if practical.", "Restrict SSH to trusted management networks.", "Review successful logins and rotate credentials if compromise is suspected."]},
    "Heartbleed": {"summary": "Traffic resembles probing for the historical Heartbleed TLS memory disclosure flaw.", "risk": "Vulnerable OpenSSL services could disclose sensitive process memory.", "actions": ["Inventory and patch any affected OpenSSL installations.", "Replace TLS certificates and rotate secrets if a vulnerable service was exposed.", "Review vendor advisories and TLS service logs."]},
    "Bot": {"summary": "Traffic patterns are consistent with automated bot activity.", "risk": "Bots may automate abuse, credential attacks, scraping, or command-and-control activity.", "actions": ["Identify the targeted service and correlate with endpoint and DNS telemetry.", "Apply service-appropriate bot controls and rate limits.", "Block or isolate the source only after confirming it is not an authorized agent."]},
    "Infiltration": {"summary": "Traffic is classified as possible network infiltration or unauthorized access activity.", "risk": "A compromised host may be communicating with an attacker or moving laterally.", "actions": ["Correlate with endpoint, identity, DNS, and firewall logs.", "Isolate the suspected host if compromise is corroborated.", "Preserve evidence and investigate lateral movement and persistence."]},
}


def _base_guidance(attack: str) -> dict[str, Any]:
    result = GUIDANCE.get(attack)
    if result:
        return {**result, "attack": attack, "source": "built-in playbook"}
    return {
        "attack": attack,
        "summary": f"The IDS classifier labeled this traffic as {attack}.",
        "risk": "Treat this as a triage signal; validate it with network and endpoint telemetry.",
        "actions": ["Review the flow and nearby events from the same source and destination.", "Check relevant firewall, service, and endpoint logs for impact.", "Apply a scoped block or containment action only after confirming the traffic is malicious.", "Preserve evidence and escalate according to your incident response process."],
        "source": "built-in playbook",
    }


async def explain_attack(attack: str, context: dict[str, Any]) -> dict[str, Any]:
    """Return actionable built-in guidance, optionally refined by configured LLM."""
    result = _base_guidance(attack)
    settings = get_settings()
    if not settings.AI_API_KEY:
        return result

    provider = settings.AI_PROVIDER.lower()
    base_url = settings.AI_BASE_URL or ("https://api.groq.com/openai/v1" if provider == "groq" else "https://api.openai.com/v1")
    model = settings.AI_MODEL or ("openai/gpt-oss-120b" if provider == "groq" else "gpt-4o-mini")
    # Do not send network identifiers to a third-party model provider.
    safe_context = {key: value for key, value in context.items() if key in {"severity", "confidence", "source_port", "destination_port", "protocol"}}
    prompt = (
        "You are a defensive SOC analyst. Explain the supplied IDS classification and recommend "
        "safe, specific defensive triage steps. The classification may be wrong; state validation "
        "caveats. Never claim an action was performed. Return JSON with keys summary, risk, actions "
        "(array of 3-5 strings). Do not repeat IP addresses.\n"
        f"Built-in guidance: {json.dumps(result, ensure_ascii=True)}\n"
        f"Observed context: {json.dumps(safe_context, ensure_ascii=True)}"
    )
    try:
        async with httpx.AsyncClient(timeout=18.0) as client:
            response = await client.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {settings.AI_API_KEY}"},
                json={"model": model, "temperature": 0.2, "response_format": {"type": "json_object"}, "messages": [{"role": "user", "content": prompt}]},
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            generated = json.loads(content)
            actions = generated.get("actions")
            if not isinstance(generated.get("summary"), str) or not isinstance(generated.get("risk"), str) or not isinstance(actions, list) or not all(isinstance(item, str) for item in actions):
                return result
            return {"attack": attack, "summary": generated["summary"][:1200], "risk": generated["risk"][:1200], "actions": [item[:500] for item in actions[:6]], "source": f"{provider} ({model})"}
    except Exception as exc:
        logger.warning("AI attack explanation unavailable; using built-in guidance (%s)", type(exc).__name__)
        return result
