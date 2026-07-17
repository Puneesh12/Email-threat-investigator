import pytest
from app.services.ioc_extractor import IOCExtractor
from app.services.threat_intel import ThreatIntelEngine

def test_ioc_defanging():
    extractor = IOCExtractor()
    
    # URL defanging
    assert extractor.defang_url("http://evil.com/path/to/malware") == "hxxp[://]evil[.]com/path/to/malware"
    assert extractor.defang_url("https://secure.update-banking.com") == "hxxps[://]secure[.]update-banking[.]com"
    
    # IP/Domain defanging
    assert extractor.defang_ip_or_domain("192.0.2.1") == "192[.]0[.]2[.]1"
    assert extractor.defang_ip_or_domain("malicious-invoice-download.com") == "malicious-invoice-download[.]com"

def test_ioc_extraction():
    extractor = IOCExtractor()
    
    sample_text = """
    Please check this file hash: f5cf07c4bc4703a58d3419084fb59b13998b368798bfd4ce9c8dfbcfb2bcf1b5 
    And connect to command center at 203.0.113.155 and 192.168.1.5 (internal).
    Also check these links: http://phish-site.com/login and https://legit-site.com/about.
    """
    
    # IPs (should extract 203.0.113.155, but ignore private 192.168.1.5)
    ips = extractor.extract_ips(sample_text)
    assert "203.0.113.155" in ips
    assert "192.168.1.5" not in ips
    
    # Hashes
    hashes = extractor.extract_hashes_from_text(sample_text)
    assert "f5cf07c4bc4703a58d3419084fb59b13998b368798bfd4ce9c8dfbcfb2bcf1b5" in hashes["sha256"]
    
    # Domains from URL list
    domains = extractor.extract_domains_from_urls(["http://phish-site.com/login", "https://legit-site.com/about"])
    assert "phish-site.com" in domains
    assert "legit-site.com" in domains

@pytest.mark.asyncio
async def test_threat_intel_enrichment():
    engine = ThreatIntelEngine()
    
    # Check IP check (mock)
    ip_rep = await engine.get_ip_reputation("198.51.100.42")
    assert ip_rep["is_malicious"] is True
    assert ip_rep["abuse_score"] == 85
    assert ip_rep["isp"] == "DigitalOcean"
    
    # Check Hash check (mock)
    hash_rep = await engine.get_hash_reputation("f5cf07c4bc4703a58d3419084fb59b13998b368798bfd4ce9c8dfbcfb2bcf1b5")
    assert hash_rep["is_malicious"] is True
    assert hash_rep["positives"] == 12
    assert "Invoice" in hash_rep["threat_category"]
    
    # Check WHOIS (mock)
    whois_rep = engine.get_domain_whois("secure-verify-invoice.com")
    assert whois_rep["is_newly_registered"] is True
    assert whois_rep["age_days"] == 7
    assert whois_rep["registrar"] == "NameCheap, Inc."
