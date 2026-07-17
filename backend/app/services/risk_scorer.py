import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

class RiskScorer:
    """
    Risk Scoring Engine.
    Aggregates findings from auth checks, BEC scans, spoof analysis, and threat intel
    to calculate a dynamic risk score (0-100), severity level, and confidence level.
    """

    def calculate_score(
        self,
        auth_results: Dict[str, Any],
        spoof_results: Dict[str, Any],
        intel_results: Dict[str, Any],
        attachments: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculates risk score, severity, and confidence.
        """
        score = 0
        contributors = []
        confidence_points = []

        # ----------------------------------------------------
        # 1. Authentication Checks (Max 25 pts)
        # ----------------------------------------------------
        dmarc_status = auth_results.get("dmarc", {}).get("status", "None")
        spf_status = auth_results.get("spf", {}).get("status", "None")
        dkim_status = auth_results.get("dkim", {}).get("status", "None")

        if dmarc_status == "Fail":
            score += 20
            contributors.append({
                "score_added": 20,
                "category": "Authentication",
                "reason": "DMARC authentication failed. Email domain alignment checks failed."
            })
        elif dmarc_status == "None":
            score += 5
            contributors.append({
                "score_added": 5,
                "category": "Authentication",
                "reason": "No DMARC record published by sender domain. Vulnerable to spoofing."
            })

        if spf_status == "Fail":
            score += 10
            contributors.append({
                "score_added": 10,
                "category": "Authentication",
                "reason": "SPF validation failed. Sending IP is not authorized by the domain's SPF record."
            })

        # Confidence contribution
        if dmarc_status != "None":
            confidence_points.append(15)  # explicit DMARC status increases investigation confidence

        # ----------------------------------------------------
        # 2. Spoof & Impersonation Checks (Max 40 pts)
        # ----------------------------------------------------
        display_spoof = spoof_results.get("display_name_spoof", {})
        lookalike = spoof_results.get("lookalike_domain", {})
        discrepancies = spoof_results.get("header_discrepancies", [])
        bec_content = spoof_results.get("bec_content", {})

        if display_spoof.get("is_spoofed"):
            score += 30
            contributors.append({
                "score_added": 30,
                "category": "Impersonation",
                "reason": f"Display Name spoofing detected: Impersonating VIP '{display_spoof.get('matched_vip')}'."
            })

        if lookalike.get("is_lookalike"):
            score += 25
            contributors.append({
                "score_added": 25,
                "category": "Impersonation",
                "reason": lookalike.get("detail", "Typosquatting/lookalike domain detected.")
            })

        # Header discrepancies (e.g. reply-to mismatch)
        for disc in discrepancies:
            disc_score = 10 if disc.get("severity") == "Medium" else 5
            score += disc_score
            contributors.append({
                "score_added": disc_score,
                "category": "Header Discrepancy",
                "reason": disc.get("detail", "Mismatched routing header.")
            })

        # BEC content keywords
        bec_risk = bec_content.get("bec_risk_level", "None")
        if bec_risk == "High":
            score += 30
            contributors.append({
                "score_added": 30,
                "category": "BEC Analysis",
                "reason": "High frequency of Business Email Compromise / social engineering keywords in email body."
            })
        elif bec_risk == "Medium":
            score += 15
            contributors.append({
                "score_added": 15,
                "category": "BEC Analysis",
                "reason": "Moderate frequency of Business Email Compromise keywords in email body."
            })

        # ----------------------------------------------------
        # 3. Threat Intelligence Check (Max 50 pts)
        # ----------------------------------------------------
        ips = intel_results.get("ips", {})
        hashes = intel_results.get("hashes", {})
        urls = intel_results.get("urls", {})
        domains = intel_results.get("domains", {})

        # IP Reputation
        for ip, data in ips.items():
            if data.get("is_malicious"):
                # Weight by abuse score
                abuse_score = data.get("abuse_score", 0)
                added = 15 if abuse_score > 50 else 10
                score += added
                contributors.append({
                    "score_added": added,
                    "category": "Threat Intelligence",
                    "reason": f"Extracted IP {ip} flagged in AbuseIPDB with abuse score: {abuse_score}%."
                })
                confidence_points.append(20)

        # File Hash Reputation
        for f_hash, data in hashes.items():
            if data.get("is_malicious"):
                score += 40
                contributors.append({
                    "score_added": 40,
                    "category": "Threat Intelligence",
                    "reason": f"Attachment hash is flagged as malicious on VirusTotal ({data.get('positives')}/{data.get('total_scans')} engines)."
                })
                confidence_points.append(30)

        # URL Reputation
        for url, data in urls.items():
            if data.get("is_malicious"):
                score += 35
                contributors.append({
                    "score_added": 35,
                    "category": "Threat Intelligence",
                    "reason": f"Extracted URL is flagged as malicious on VirusTotal ({data.get('vt_positives')} engines)."
                })
                confidence_points.append(25)

        # Domain registration age (WHOIS)
        for dom, data in domains.items():
            if data.get("is_newly_registered"):
                score += 20
                contributors.append({
                    "score_added": 20,
                    "category": "Threat Intelligence",
                    "reason": f"Domain '{dom}' was registered recently ({data.get('age_days')} days ago). Common for phishing."
                })
                confidence_points.append(15)

        # ----------------------------------------------------
        # 4. Attachment Properties (Max 15 pts)
        # ----------------------------------------------------
        dangerous_extensions = ['.exe', '.scr', '.bat', '.vbs', '.js', '.ps1', '.html', '.htm', '.lnk', '.docm', '.xlsm']
        for att in attachments:
            name = att.get("filename", "").lower()
            if any(name.endswith(ext) for ext in dangerous_extensions):
                score += 15
                contributors.append({
                    "score_added": 15,
                    "category": "Attachment Analysis",
                    "reason": f"Email contains a potentially dangerous attachment type: '{name}'"
                })
                break # count once

        # ----------------------------------------------------
        # Normalization and Risk Level
        # ----------------------------------------------------
        # Risk score is capped at 100
        final_score = min(score, 100)
        
        # Risk levels mapping
        if final_score >= 80:
            level = "Critical"
        elif final_score >= 60:
            level = "High"
        elif final_score >= 30:
            level = "Medium"
        else:
            level = "Low"

        # Calculate Confidence Score (0-100)
        # Base confidence is 40. Each intelligence indicator or auth check adds confidence. Max 100.
        base_confidence = 40
        confidence = min(base_confidence + sum(confidence_points), 100)

        return {
            "score": final_score,
            "level": level,
            "confidence_score": confidence,
            "contributors": contributors
        }
