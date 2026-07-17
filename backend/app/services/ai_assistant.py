import logging
import json
from typing import Dict, Any, Optional
from app.config import settings

logger = logging.getLogger(__name__)

class AIAssistant:
    """
    AI Investigation Engine.
    Leverages LLMs (Google Gemini or OpenAI) to analyze investigation findings
    and generate SOC analyst reports. Degrades to high-fidelity template rules if offline.
    """

    def __init__(self):
        self.provider = settings.AI_PROVIDER.lower()
        self.gemini_key = settings.GEMINI_API_KEY
        self.openai_key = settings.OPENAI_API_KEY

    def _generate_rule_based_report(self, context: Dict[str, Any]) -> str:
        """
        Generates a highly-detailed, contextual template-based report when LLM keys are missing.
        Ensures the SOC dashboard is always visually rich and analyst-ready.
        """
        envelope = context.get("envelope", {})
        sender = envelope.get("sender", {}).get("email", "Unknown")
        subject = envelope.get("subject", "No Subject")
        risk_level = context.get("risk", {}).get("level", "Low")
        risk_score = context.get("risk", {}).get("score", 0)
        mitre = context.get("mitre", [])
        
        # Analyze findings to tailor the mock analysis
        display_spoof = context.get("spoof", {}).get("display_name_spoof", {}).get("is_spoofed")
        lookalike = context.get("spoof", {}).get("lookalike_domain", {}).get("is_lookalike")
        bec_risk = context.get("spoof", {}).get("bec_content", {}).get("bec_risk_level", "None")
        dmarc_status = context.get("auth", {}).get("dmarc", {}).get("status", "None")

        mitre_list = ", ".join([f"{t['id']} ({t['name']})" for t in mitre])

        report = f"""# SOC Security Investigation Report - AI Assistant (Rule-Based Simulation)

## Executive Summary
This email from **{sender}** with subject **"{subject}"** has been classified with a **{risk_level.upper()}** risk rating (Score: **{risk_score}/100**). 
The investigation detected structural anomalies, domain alignment errors, and social engineering indicators aligning with MITRE ATT&CK techniques: **{mitre_list or 'None'}**.

---

## Detailed Threat Indicators

### 1. Email Authentication Verification
- **DMARC Status**: `{dmarc_status}`.
"""
        if dmarc_status == "Fail":
            report += "- *Anomaly*: The sending IP is not authorized by the SPF record, or the DKIM signature is missing/invalid, causing DMARC alignment verification to fail. This is a strong indicator of spoofing.\n"
        elif dmarc_status == "None":
            report += "- *Warning*: The sender's domain does not publish a DMARC policy. This leaves the organization vulnerable to displays and domain impersonation attacks.\n"
        else:
            report += "- *Verification*: Domain authentication checks (SPF/DKIM/DMARC) passed successfully.\n"

        report += "\n### 2. Impersonation & BEC Analysis\n"
        if display_spoof:
            report += f"- **Display Name Impersonation Detected**: The sender name matches an internal VIP ({envelope.get('sender', {}).get('name')}), but utilizes an external email address ({sender}). This is a classic VIP impersonation tactic.\n"
        if lookalike:
            report += f"- **Lookalike Domain Spoofing**: The domain `{sender.split('@')[-1]}` closely resembles corporate domains or trusted vendors, suggesting a typosquatting campaign.\n"
        if bec_risk in ["High", "Medium"]:
            report += f"- **BEC Urgency Markers**: Semantic analysis identified multiple high-risk indicators associated with financial wire transfers, credential updates, or urgent gift card purchases (risk categorization: {bec_risk}).\n"
        if not display_spoof and not lookalike and bec_risk == "None":
            report += "- No VIP impersonation or significant social engineering indicators were triggered in the headers or body.\n"

        report += "\n### 3. Indicator of Compromise (IOC) Analysis\n"
        ips = context.get("intel", {}).get("ips", {})
        hashes = context.get("intel", {}).get("hashes", {})
        urls = context.get("intel", {}).get("urls", {})
        
        malicious_ips = [ip for ip, d in ips.items() if d.get("is_malicious")]
        malicious_urls = [u for u, d in urls.items() if d.get("is_malicious")]
        malicious_hashes = [h for h, d in hashes.items() if d.get("is_malicious")]

        if malicious_ips:
            report += f"- **IP Reputation**: Sending or referenced IPs ({', '.join(malicious_ips)}) are flagged on threat intelligence blocklists (AbuseIPDB).\n"
        if malicious_urls:
            report += f"- **Phishing URLs**: Referenced links ({', '.join(malicious_urls)}) are associated with credential harvesting portals on VirusTotal.\n"
        if malicious_hashes:
            report += f"- **Malicious Attachments**: File attachment hashes ({', '.join(malicious_hashes)}) are marked as malicious on VirusTotal.\n"
        if not malicious_ips and not malicious_urls and not malicious_hashes:
            report += "- Extracted IOCs do not have active threat intelligence detections.\n"

        report += f"""
---

## Threat Actor Intent Profile
Based on the mapping, the threat actor's apparent goal is **{"Credential Harvesting / Access Gain" if "T1566.002" in mitre_list else "Social Engineering / Financial Fraud" if bec_risk != "None" else "Malware Delivery"}**. 
The campaign relies on target manipulation (urgency triggers) combined with technology gaps (weak DMARC enforcement) to bypass local gateway protections.

---

## Defense-in-Depth Recommendations

1. **Gateway Enforcement**: Transition the corporate email filter to reject or quarantine emails from domains failing DMARC policies.
2. **Defensive DNS**: Add block entries for the identified malicious domains and IPs on DNS firewalls and web proxies.
3. **Identity Verification**: Inform the recipient to verify any financial or sensitive operational requests through secondary out-of-band channels (e.g. phone call).
4. **Endpoint Containment**: If the attachment was downloaded or link clicked, isolate the endpoint immediately and run a full antivirus/EDR scan.
5. **Security Awareness**: Use this email structure as a training template for phishing awareness simulation programs.
"""
        return report

    async def investigate(self, context: Dict[str, Any]) -> str:
        """
        Orchestrates the AI investigation.
        Queries the chosen LLM provider or falls back to rule-based template.
        """
        # Formulate prompt context
        prompt = f"""
You are a Senior SOC Analyst and Threat Intelligence Engineer. 
Investigate this parsed email payload and threat intelligence enrichment data:

{json.dumps(context, indent=2)}

Provide a professional, executive investigation report in markdown format. Do not write introductory chatter. Start directly with the markdown headers.
The report must include:
1. Executive Summary (include risk score and overall judgment)
2. Detailed Threat Indicators breakdown (Authentication validation, Impersonation analysis, IOC checks)
3. Threat Actor Intent (explain what they are trying to achieve)
4. Actionable Defense-in-Depth Recommendations (specific blocking, email gateway, and endpoint recommendations)
"""

        # 1. Google Gemini API
        if self.provider == "gemini" and self.gemini_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.gemini_key)
                # Use standard gemini-1.5-flash or similar available model
                model = genai.GenerativeModel('gemini-1.5-flash')
                response = model.generate_content(prompt)
                if response.text:
                    return response.text.strip()
            except Exception as e:
                logger.error(f"Gemini AI investigation API call failed: {e}. Falling back to rule-based.")

        # 2. OpenAI API
        elif self.provider == "openai" and self.openai_key:
            try:
                from openai import OpenAI
                client = OpenAI(api_key=self.openai_key)
                response = client.chat.completions.create(
                    model="gpt-4-turbo",
                    messages=[
                        {"role": "system", "content": "You are a Senior Cybersecurity SOC Analyst conducting a thorough email threat investigation."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2
                )
                content = response.choices[0].message.content
                if content:
                    return content.strip()
            except Exception as e:
                logger.error(f"OpenAI AI investigation API call failed: {e}. Falling back to rule-based.")

        # 3. Rule-based Fallback
        logger.debug("Running rule-based report generation.")
        return self._generate_rule_based_report(context)
