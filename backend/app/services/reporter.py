import logging
from typing import Dict, Any
from app.services.parser import EmailParser
from app.services.validator import AuthValidator
from app.services.spoof_detector import SpoofDetector
from app.services.ioc_extractor import IOCExtractor
from app.services.threat_intel import ThreatIntelEngine
from app.services.risk_scorer import RiskScorer
from app.services.mitre_mapper import MitreMapper
from app.services.ai_assistant import AIAssistant

logger = logging.getLogger(__name__)

class InvestigationReporter:
    """
    Report Generation Engine.
    Orchestrates the entire threat investigation workflow, calling each specialized
    service in sequence, compiling all modular analyses into a unified structured report.
    """

    def __init__(self):
        self.parser = EmailParser()
        self.validator = AuthValidator(use_mock_fallback=True)
        self.spoof_detector = SpoofDetector()
        self.ioc_extractor = IOCExtractor()
        self.threat_intel = ThreatIntelEngine()
        self.risk_scorer = RiskScorer()
        self.mitre_mapper = MitreMapper()
        self.ai_assistant = AIAssistant()

    async def run_investigation(self, raw_eml_content: str, filename: str = "raw_headers.txt") -> Dict[str, Any]:
        """
        Runs the complete email investigation workflow.
        """
        # 1. Parse EML
        parsed_email = self.parser.parse(raw_eml_content)
        
        # 2. Authentication Validation
        auth_results = self.validator.run_full_auth_check(parsed_email, raw_eml_content.encode("utf-8"))
        
        # 3. Spoofing & BEC Detection
        spoof_results = self.spoof_detector.run_spoof_bec_analysis(parsed_email)
        
        # 4. Extract IOCs
        ioc_results = self.ioc_extractor.run_extraction(parsed_email)
        
        # 5. Enrich IOCs via Threat Intelligence
        intel_results = await self.threat_intel.run_full_enrichment(ioc_results)
        
        # 6. Risk Scoring
        risk_results = self.risk_scorer.calculate_score(
            auth_results,
            spoof_results,
            intel_results,
            parsed_email.get("attachments", [])
        )
        
        # 7. MITRE ATT&CK Mapping
        mitre_results = self.mitre_mapper.map_techniques(
            parsed_email,
            auth_results,
            spoof_results,
            intel_results,
            risk_results["score"]
        )
        
        # Compile contextual payload for AI analysis
        investigation_context = {
            "filename": filename,
            "envelope": parsed_email["envelope"],
            "hops": parsed_email["hops"],
            "source_ip": parsed_email["source_ip"],
            "auth": auth_results,
            "spoof": spoof_results,
            "intel": intel_results,
            "risk": risk_results,
            "mitre": mitre_results,
            "urls": parsed_email["urls"],
            "attachments": parsed_email["attachments"]
        }
        
        # 8. AI Investigation Analysis
        ai_report = await self.ai_assistant.investigate(investigation_context)
        
        # Build unified report response
        return {
            "metadata": {
                "filename": filename,
                "investigation_date": parsed_email["envelope"].get("date") or parsed_email["hops"][-1].get("timestamp_raw") if parsed_email["hops"] else "",
                "analyst_notes_markdown": ai_report
            },
            "parsed_email": parsed_email,
            "auth_validation": auth_results,
            "spoof_bec_analysis": spoof_results,
            "ioc_extraction": ioc_results,
            "threat_intelligence": intel_results,
            "risk_assessment": risk_results,
            "mitre_mapping": mitre_results
        }
