import os
import pytest
from app.services.parser import EmailParser
from app.services.validator import AuthValidator
from app.services.spoof_detector import SpoofDetector

SAMPLES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../samples")
)

def read_sample_file(filename: str) -> str:
    path = os.path.join(SAMPLES_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def test_auth_validator_suspicious_invoice():
    # Parse EML first
    raw_content = read_sample_file("suspicious_invoice.eml")
    parser = EmailParser()
    parsed = parser.parse(raw_content)
    
    # Run Validator
    validator = AuthValidator(use_mock_fallback=True)
    auth_results = validator.run_full_auth_check(parsed, raw_content.encode("utf-8"))
    
    # Verify SPF
    assert auth_results["spf"]["status"] in ["Pass", "Fail"]
    # The first hop in suspicious_invoice.eml is 203.0.113.155.
    # The return-path domain is secure-verify-invoice.com, which has mock record: v=spf1 ip4:198.51.100.42 -all
    # Since 203.0.113.155 is not 198.51.100.42, SPF status should be Fail.
    assert auth_results["spf"]["status"] == "Fail"
    
    # Verify DMARC is flagged as Fail (since SPF fails and there is no valid DKIM signature)
    assert auth_results["dmarc"]["status"] == "Fail"
    assert auth_results["dmarc"]["spf_aligned"] is True

def test_auth_validator_credential_harvesting():
    # Parse EML
    raw_content = read_sample_file("credential_harvesting.eml")
    parser = EmailParser()
    parsed = parser.parse(raw_content)
    
    # Run Validator (source_ip is 192.0.2.77)
    validator = AuthValidator(use_mock_fallback=True)
    auth_results = validator.run_full_auth_check(parsed, raw_content.encode("utf-8"))
    
    # The return-path is bounce@security-mycompany-portal.com
    # The mock SPF record is "v=spf1 ip4:192.0.2.77 -all"
    # Source IP is 192.0.2.77, so it matches. SPF should be Pass!
    assert auth_results["spf"]["status"] == "Pass"
    
    # DMARC alignment: From domain is security-mycompany-portal.com, Return-Path domain is security-mycompany-portal.com
    # Alignment should be true. DMARC status should be Pass since SPF passed and is aligned.
    assert auth_results["dmarc"]["spf_aligned"] is True
    assert auth_results["dmarc"]["status"] == "Pass"

def test_spoof_detector_display_name():
    detector = SpoofDetector()
    
    # VIP check
    res = detector.check_display_name_spoofing("John Doe", "john.doe.personal.desk39@gmail.com")
    assert res["is_spoofed"] is True
    assert "John Doe" in res["detail"]
    
    # Non-VIP check
    res = detector.check_display_name_spoofing("Random Guy", "random.guy@gmail.com")
    assert res["is_spoofed"] is False

def test_spoof_detector_lookalike_domain():
    detector = SpoofDetector()
    
    # Typosquatting / brand hijacking
    res = detector.check_lookalike_domains("admin@security-mycompany-portal.com")
    assert res["is_lookalike"] is True
    assert "mycompany" in res["detail"]
    
    # Edit distance check (mycompany.com vs myconpany.com)
    res = detector.check_lookalike_domains("ceo@myconpany.com")
    assert res["is_lookalike"] is True
    assert res["distance"] == 1
    
    # Legitimate internal
    res = detector.check_lookalike_domains("jane.smith@mycompany.com")
    assert res["is_lookalike"] is False

def test_spoof_detector_bec_content():
    detector = SpoofDetector()
    
    # BEC words
    body = "Jane, please execute a wire transfer to update our bank details immediately. Do not call me, as I am in a meeting."
    res = detector.check_bec_content(body)
    assert res["bec_risk_level"] in ["High", "Medium"]
    assert "wire transfer" in res["matched_phrases"]
    assert "bank details" in res["matched_phrases"]
    
    # Phishing credentials words
    body = "Your password will expire today. Verify your account immediately."
    res = detector.check_bec_content(body)
    assert res["bec_risk_level"] in ["High", "Medium"]
    
    # Safe text
    body = "Hi Jane, let's meet tomorrow to discuss the new project timeline."
    res = detector.check_bec_content(body)
    assert res["bec_risk_level"] == "None"

def test_full_spoof_bec_analysis_emls():
    parser = EmailParser()
    detector = SpoofDetector()
    
    # 1. Test Invoice EML
    raw_invoice = read_sample_file("suspicious_invoice.eml")
    parsed_invoice = parser.parse(raw_invoice)
    invoice_analysis = detector.run_spoof_bec_analysis(parsed_invoice)
    
    assert invoice_analysis["is_suspicious"] is True
    assert len(invoice_analysis["header_discrepancies"]) > 0  # Reply-To/Return-Path mismatches
    
    # 2. Test Gift Card Spoof EML
    raw_giftcard = read_sample_file("display_name_spoof.eml")
    parsed_giftcard = parser.parse(raw_giftcard)
    giftcard_analysis = detector.run_spoof_bec_analysis(parsed_giftcard)
    
    assert giftcard_analysis["is_suspicious"] is True
    assert giftcard_analysis["display_name_spoof"]["is_spoofed"] is True
    assert giftcard_analysis["bec_content"]["bec_risk_level"] == "High"
