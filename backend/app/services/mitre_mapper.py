import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class MitreMapper:
    """
    MITRE ATT&CK Mapping Engine.
    Maps email metrics, threat intelligence, and behavioral flags to MITRE ATT&CK
    tactics and techniques for threat reporting.
    """

    MAPPINGS = {
        "T1566.001": {
            "name": "Phishing: Spearphishing Attachment",
            "tactic": "Initial Access",
            "description": "Adversaries may send spearphishing emails with malicious attachments to gain initial access to organizations."
        },
        "T1566.002": {
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "description": "Adversaries may send spearphishing emails with malicious links to credential harvesting portals or exploit vectors."
        },
        "T1204.001": {
            "name": "User Execution: Malicious Link",
            "tactic": "Execution",
            "description": "Adversaries may rely on users clicking a link inside a phishing email to initiate system compromise."
        },
        "T1204.002": {
            "name": "User Execution: Malicious Attachment",
            "tactic": "Execution",
            "description": "Adversaries may rely on users opening a malicious file attachment to execute code."
        },
        "T1071.003": {
            "name": "Application Layer Protocol: Mail Protocols",
            "tactic": "Command and Control",
            "description": "Adversaries may use SMTP/IMAP protocol structures for exfiltration or command routing, or abuse mail servers to send spoofed content."
        },
        "T1585.002": {
            "name": "Establish Accounts: Email Accounts",
            "tactic": "Resource Development",
            "description": "Adversaries may register lookalike domains and email accounts to establish trust and bypass basic security checks during target campaigns."
        }
    }

    def map_techniques(
        self,
        parser_results: Dict[str, Any],
        auth_results: Dict[str, Any],
        spoof_results: Dict[str, Any],
        intel_results: Dict[str, Any],
        risk_score: int
    ) -> List[Dict[str, Any]]:
        """
        Analyses all modules to construct list of applicable MITRE techniques.
        """
        techniques = []
        triggered_ids = set()

        has_attachments = len(parser_results.get("attachments", [])) > 0
        has_urls = len(parser_results.get("urls", [])) > 0
        
        # Check for malicious attachment threat intelligence
        malicious_attachment = False
        for h, data in intel_results.get("hashes", {}).items():
            if data.get("is_malicious"):
                malicious_attachment = True

        # Check for malicious URL threat intelligence
        malicious_url = False
        for u, data in intel_results.get("urls", {}).items():
            if data.get("is_malicious"):
                malicious_url = True

        # Check lookalike domain status
        is_lookalike = spoof_results.get("lookalike_domain", {}).get("is_lookalike", False)
        
        # Check newly registered domains
        is_newly_registered = False
        for d, data in intel_results.get("domains", {}).items():
            if data.get("is_newly_registered"):
                is_newly_registered = True

        # ----------------------------------------------------
        # Mappings Evaluation
        # ----------------------------------------------------
        
        # 1. Spearphishing Attachment (T1566.001) & User Execution (T1204.002)
        if has_attachments and (malicious_attachment or risk_score >= 60):
            triggered_ids.add("T1566.001")
            triggered_ids.add("T1204.002")

        # 2. Spearphishing Link (T1566.002) & User Execution (T1204.001)
        if has_urls and (malicious_url or risk_score >= 40):
            triggered_ids.add("T1566.002")
            triggered_ids.add("T1204.001")

        # 3. Establish Accounts: Email Accounts (T1585.002)
        if is_lookalike or is_newly_registered:
            triggered_ids.add("T1585.002")

        # 4. Application Layer Protocol: Mail Protocols (T1071.003)
        # Triggered when DMARC fails or SPF is forged, showing protocol manipulation
        dmarc_status = auth_results.get("dmarc", {}).get("status")
        if dmarc_status == "Fail" or spoof_results.get("display_name_spoof", {}).get("is_spoofed"):
            triggered_ids.add("T1071.003")

        # Assemble detailed mapping reports
        for t_id in triggered_ids:
            if t_id in self.MAPPINGS:
                techniques.append({
                    "id": t_id,
                    "name": self.MAPPINGS[t_id]["name"],
                    "tactic": self.MAPPINGS[t_id]["tactic"],
                    "description": self.MAPPINGS[t_id]["description"]
                })

        return techniques
