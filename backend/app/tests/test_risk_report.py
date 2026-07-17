import os
import pytest
from app.services.parser import EmailParser
from app.services.validator import AuthValidator
from app.services.spoof_detector import SpoofDetector
from app.services.ioc_extractor import IOCExtractor
from app.services.threat_intel import ThreatIntelEngine
from app.services.risk_scorer import RiskScorer
from app.services.mitre_mapper import MitreMapper
from app.services.ai_assistant import AIAssistant
from app.services.reporter import InvestigationReporter

SAMPLES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../samples")
)

def read_sample_file(filename: str) -> str:
    path = os.path.join(SAMPLES_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

@pytest.mark.asyncio
async def test_full_risk_scoring_and_mitre_mapping():
    # 1. Load EML
    raw_content = read_sample_file("suspicious_invoice.eml")
    parser = EmailParser()
    parsed = parser.parse(raw_content)
    
    # 2. Run validations
    validator = AuthValidator(use_mock_fallback=True)
    auth = validator.run_full_auth_check(parsed, raw_content.encode("utf-8"))
    
    detector = SpoofDetector()
    spoof = detector.run_spoof_bec_analysis(parsed)
    
    extractor = IOCExtractor()
    iocs = extractor.run_extraction(parsed)
    
    intel_engine = ThreatIntelEngine()
    intel = await intel_engine.run_full_enrichment(iocs)
    
    # 3. Calculate risk
    scorer = RiskScorer()
    risk = scorer.calculate_score(auth, spoof, intel, parsed["attachments"])
    
    assert risk["score"] >= 60 # should be High or Critical risk
    assert risk["level"] in ["High", "Critical"]
    
    # Check contributors
    categories = [c["category"] for c in risk["contributors"]]
    assert "Authentication" in categories
    assert "Threat Intelligence" in categories
    
    # 4. Map MITRE ATT&CK
    mapper = MitreMapper()
    mitre = mapper.map_techniques(parsed, auth, spoof, intel, risk["score"])
    
    technique_ids = [t["id"] for t in mitre]
    assert "T1566.001" in technique_ids # Spearphishing Attachment
    assert "T1204.002" in technique_ids # User Execution: Malicious Attachment
    assert "T1566.002" in technique_ids # Spearphishing Link (suspicious URL)

@pytest.mark.asyncio
async def test_ai_assistant_offline_report():
    assistant = AIAssistant()
    
    # Mock context payload
    context = {
        "envelope": {
            "sender": {"name": "Test CEO", "email": "ceo@malicious-domain.com"},
            "subject": "Wire Transfer Needed Immediately"
        },
        "risk": {"score": 85, "level": "Critical"},
        "auth": {"dmarc": {"status": "Fail", "record": "v=DMARC1; p=reject"}},
        "spoof": {
            "display_name_spoof": {"is_spoofed": True, "matched_vip": "Test CEO"},
            "bec_content": {"bec_risk_level": "High"}
        },
        "intel": {"ips": {}, "hashes": {}, "urls": {}},
        "mitre": [{"id": "T1566.002", "name": "Spearphishing Link"}]
    }
    
    report = await assistant.investigate(context)
    assert "# SOC Security Investigation Report" in report
    assert "Detailed Threat Indicators" in report
    assert "Display Name Impersonation Detected" in report
    assert "T1566.002" in report

@pytest.mark.asyncio
async def test_unified_investigation_reporter():
    reporter = InvestigationReporter()
    raw_content = read_sample_file("display_name_spoof.eml")
    
    report = await reporter.run_investigation(raw_content, "display_name_spoof.eml")
    
    # Verify overall report keys
    assert "metadata" in report
    assert "parsed_email" in report
    assert "auth_validation" in report
    assert "spoof_bec_analysis" in report
    assert "ioc_extraction" in report
    assert "threat_intelligence" in report
    assert "risk_assessment" in report
    assert "mitre_mapping" in report
    
    # Check risk level
    assert report["risk_assessment"]["level"] in ["High", "Critical", "Medium"]
    assert report["spoof_bec_analysis"]["display_name_spoof"]["is_spoofed"] is True
    assert "SOC Security Investigation Report" in report["metadata"]["analyst_notes_markdown"]
