import re
import logging
from typing import Dict, Any, List
from app.config import settings

logger = logging.getLogger(__name__)

class SpoofDetector:
    """
    Spoof & Business Email Compromise (BEC) Detection Engine.
    Identifies header manipulation, display-name spoofing, lookalike domains,
    and business email compromise keywords.
    """

    BEC_KEYWORDS = {
        "financial_urgency": [
            r"\bwire\s+transfer\b",
            r"\burgent\s+payment\b",
            r"\bswift\s+transfer\b",
            r"\brouting\s+(?:number|transit)\b",
            r"\bbank\s+(?:details|account|routing)\b",
            r"\bupdate\s+(?:direct\s+deposit|banking\s+details)\b",
            r"\bconfidential\s+payment\b",
            r"\bimmediate\s+wire\b",
        ],
        "gift_cards": [
            r"\bgift\s+cards?\b",
            r"\bapple\s+gift\b",
            r"\bitunes\b",
            r"\bsteam\s+card\b",
            r"\bscratch\s+the\s+back\b",
        ],
        "social_engineering": [
            r"\bare\s+you\s+at\s+your\s+desk\b",
            r"\bquick\s+favor\b",
            r"\bbusy\s+right\s+now\b",
            r"\bin\s+a\s+meeting\b",
            r"\bdiscreetly\b",
            r"\burgent\s+task\b",
            r"\bdo\s+not\s+call\s+me\b",
        ],
        "credential_harvesting": [
            r"\bpassword\s+(?:\w+\s+){0,3}expir(?:e|y)\b",
            r"\baction\s+required\b",
            r"\bverify\s+your\s+account\b",
            r"\bsuspended\s+temporarily\b",
            r"\blogin\s+alert\b",
            r"\bsecurity\s+update\b",
        ]
    }

    def __init__(self):
        self.vip_names = [name.lower() for name in settings.ORG_VIP_NAMES]
        self.internal_domains = [dom.lower() for dom in settings.ORG_INTERNAL_DOMAINS]

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculates Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def check_display_name_spoofing(self, sender_name: str, sender_email: str) -> Dict[str, Any]:
        """
        Detects display-name spoofing where an external sender uses the name of an internal VIP.
        """
        result = {
            "is_spoofed": False,
            "matched_vip": "",
            "detail": "No display-name impersonation detected."
        }

        if not sender_name or not sender_email:
            return result

        sender_name_lower = sender_name.lower().strip()
        sender_email_lower = sender_email.lower().strip()
        
        # Extract domain
        sender_domain = sender_email_lower.split('@')[-1] if '@' in sender_email_lower else ""
        
        # Check if the domain is external
        is_external = sender_domain not in self.internal_domains

        if is_external:
            for vip in self.vip_names:
                # Direct check: does the sender name contain the VIP name?
                # E.g. "John Doe" or "John Doe <ceo@gmail.com>"
                if vip in sender_name_lower:
                    result["is_spoofed"] = True
                    result["matched_vip"] = vip.title()
                    result["detail"] = (
                        f"Display name '{sender_name}' matches internal VIP '{vip.title()}' "
                        f"but sender email '{sender_email}' is external."
                    )
                    break
                    
        return result

    def check_lookalike_domains(self, sender_email: str) -> Dict[str, Any]:
        """
        Checks if the sender domain is a lookalike (typosquatting) of internal domains.
        """
        result = {
            "is_lookalike": False,
            "target_domain": "",
            "distance": 0,
            "detail": "No lookalike domains detected."
        }

        if not sender_email or '@' not in sender_email:
            return result

        sender_domain = sender_email.split('@')[-1].lower()
        
        # If it's already a legitimate internal domain, skip
        if sender_domain in self.internal_domains:
            return result

        for internal_domain in self.internal_domains:
            # Check 1: Levenshtein distance for close typos
            distance = self._levenshtein_distance(sender_domain, internal_domain)
            # Typosquatting boundary: distance between 1 and 3 changes
            if 1 <= distance <= 2:
                result["is_lookalike"] = True
                result["target_domain"] = internal_domain
                result["distance"] = distance
                result["detail"] = (
                    f"Sender domain '{sender_domain}' is highly similar to internal domain "
                    f"'{internal_domain}' (edit distance: {distance}). Potential typosquatting."
                )
                return result

            # Check 2: Corporate domain name used inside the domain structure (e.g. security-mycompany-portal.com)
            # but is not the exact domain.
            corp_name = internal_domain.split('.')[0]
            if corp_name in sender_domain and sender_domain != internal_domain:
                result["is_lookalike"] = True
                result["target_domain"] = internal_domain
                result["detail"] = (
                    f"Sender domain '{sender_domain}' contains internal brand name '{corp_name}' "
                    f"but is not an authorized company domain."
                )
                return result

        return result

    def check_header_discrepancies(self, envelope: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Checks for discrepancies between From, Return-Path, and Reply-To headers.
        """
        findings = []
        sender_email = envelope["sender"]["email"].lower()
        return_path_email = envelope["return_path"]["email"].lower() if envelope.get("return_path") else ""
        reply_to_email = envelope["reply_to"]["email"].lower() if envelope.get("reply_to") else ""

        # 1. From vs Return-Path Discrepancy
        if return_path_email and sender_email != return_path_email:
            # Return Path is often empty or bounce address, but if they are completely different domains, flag it
            from_domain = sender_email.split('@')[-1]
            rp_domain = return_path_email.split('@')[-1]
            if from_domain != rp_domain:
                findings.append({
                    "type": "return_path_mismatch",
                    "severity": "Medium",
                    "detail": f"Sender domain ({from_domain}) does not match Return-Path domain ({rp_domain})."
                })

        # 2. From vs Reply-To Discrepancy
        if reply_to_email and sender_email != reply_to_email:
            from_domain = sender_email.split('@')[-1]
            rt_domain = reply_to_email.split('@')[-1]
            if from_domain != rt_domain:
                findings.append({
                    "type": "reply_to_mismatch",
                    "severity": "Medium",
                    "detail": f"Replies are routed to a different domain: '{reply_to_email}' (From: '{sender_email}')."
                })

        return findings

    def check_bec_content(self, body_text: str) -> Dict[str, Any]:
        """
        Scans email text for Business Email Compromise and Phishing semantic keywords.
        """
        scores = {}
        matched_patterns = []
        total_hits = 0

        body_text_lower = body_text.lower()

        for category, regex_list in self.BEC_KEYWORDS.items():
            hits = 0
            category_matches = []
            for pattern in regex_list:
                matches = list(re.finditer(pattern, body_text_lower))
                if matches:
                    hits += len(matches)
                    for m in matches:
                        matched_text = m.group(0)
                        if matched_text not in category_matches:
                            category_matches.append(matched_text)
            
            if hits > 0:
                scores[category] = hits
                matched_patterns.extend(category_matches)
                total_hits += hits

        # Calculate high/medium/low severity based on total matches
        risk = "None"
        if total_hits >= 4:
            risk = "High"
        elif total_hits >= 2:
            risk = "Medium"
        elif total_hits >= 1:
            risk = "Low"

        return {
            "bec_risk_level": risk,
            "total_matches": total_hits,
            "scores": scores,
            "matched_phrases": matched_patterns,
            "detail": f"Found {total_hits} BEC/phishing semantic indicator(s) in email body." if total_hits > 0 else "No BEC keywords found."
        }

    def run_spoof_bec_analysis(self, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs the full suite of spoof and BEC detection checks.
        """
        envelope = parsed_email["envelope"]
        sender = envelope["sender"]
        
        display_name_spoof = self.check_display_name_spoofing(sender["name"], sender["email"])
        lookalike_domain = self.check_lookalike_domains(sender["email"])
        discrepancies = self.check_header_discrepancies(envelope)
        
        # Combine text and HTML body text for keyword search
        text_body = parsed_email["body"]["text"] or ""
        html_body = parsed_email["body"]["html"] or ""
        # Strip simple tags for keyword checks
        clean_html = re.sub(r'<[^>]+>', ' ', html_body)
        combined_body = text_body + "\n" + clean_html
        
        bec_content = self.check_bec_content(combined_body)

        # Overall assessment
        is_suspicious = (
            display_name_spoof["is_spoofed"] or 
            lookalike_domain["is_lookalike"] or 
            len(discrepancies) > 0 or 
            bec_content["bec_risk_level"] in ["High", "Medium"]
        )

        return {
            "display_name_spoof": display_name_spoof,
            "lookalike_domain": lookalike_domain,
            "header_discrepancies": discrepancies,
            "bec_content": bec_content,
            "is_suspicious": is_suspicious
        }
