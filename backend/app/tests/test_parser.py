import os
import pytest
from app.services.parser import EmailParser, EmailParserError

# Determine base paths
SAMPLES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../samples")
)

def read_sample_file(filename: str) -> str:
    """Helper to read sample EML content."""
    path = os.path.join(SAMPLES_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def test_parse_suspicious_invoice():
    """Tests parsing on a complex multipart email (invoice)."""
    raw_content = read_sample_file("suspicious_invoice.eml")
    parser = EmailParser()
    result = parser.parse(raw_content)
    
    # Verify Envelope
    envelope = result["envelope"]
    assert envelope["sender"]["name"] == "Billing Dept"
    assert envelope["sender"]["email"] == "billing-alerts@secure-verify-invoice.com"
    assert len(envelope["recipients"]) == 1
    assert envelope["recipients"][0]["email"] == "jane.smith@mycompany.com"
    assert len(envelope["cc"]) == 1
    assert envelope["cc"][0]["email"] == "accounting@mycompany.com"
    assert "Outstanding Invoice" in envelope["subject"]
    assert envelope["message_id"] == "<84729104.billing-alerts@secure-verify-invoice.com>"
    assert envelope["return_path"]["email"] == "bounce@secure-verify-invoice.com"
    assert envelope["reply_to"]["email"] == "billing-reply@billing-queries-desk.com"
    
    # Verify Hops & Source IP
    assert len(result["hops"]) == 2
    assert result["hops"][0]["from_ip"] == "203.0.113.155" # first hop
    assert result["hops"][1]["from_ip"] == "198.51.100.42" # second hop
    assert result["source_ip"] == "203.0.113.155" # oldest hop IP
    
    # Verify URLs
    assert len(result["urls"]) == 1
    assert result["urls"][0] == "http://billing-portal-update.com/login?id=jane.smith@mycompany.com"
    
    # Verify Attachments
    assert len(result["attachments"]) == 1
    attachment = result["attachments"][0]
    assert attachment["filename"] == "Invoice_INV-887261.pdf"
    assert attachment["content_type"] == "application/pdf"
    # SHA-256 for the base64 content
    assert len(attachment["sha256"]) == 64
    assert attachment["size_bytes"] > 0

def test_parse_display_name_spoof():
    """Tests parsing a plain text email with impersonation."""
    raw_content = read_sample_file("display_name_spoof.eml")
    parser = EmailParser()
    result = parser.parse(raw_content)
    
    # Verify Envelope
    envelope = result["envelope"]
    assert envelope["sender"]["name"] == "John Doe"
    assert envelope["sender"]["email"] == "john.doe.personal.desk39@gmail.com"
    assert "Quick favor" in envelope["subject"]
    
    # Verify Hops
    assert len(result["hops"]) == 1
    assert result["hops"][0]["from_ip"] == "209.85.220.65"
    assert result["source_ip"] == "209.85.220.65"
    
    # Body
    assert "Apple gift cards" in result["body"]["text"]
    assert result["body"]["html"] == ""
    assert len(result["attachments"]) == 0

def test_parse_credential_harvesting():
    """Tests parsing an HTML email with a lookalike domain and phishing link."""
    raw_content = read_sample_file("credential_harvesting.eml")
    parser = EmailParser()
    result = parser.parse(raw_content)
    
    # Verify Envelope
    envelope = result["envelope"]
    assert envelope["sender"]["name"] == "Microsoft Security Team"
    assert envelope["sender"]["email"] == "no-reply@security-mycompany-portal.com"
    
    # Verify URLs
    assert len(result["urls"]) == 1
    assert "login.microsoftonline.com.security-mycompany-portal.com" in result["urls"][0]
