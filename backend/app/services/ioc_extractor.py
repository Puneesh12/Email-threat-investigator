import re
import logging
from typing import Dict, Any, List, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class IOCExtractor:
    """
    IOC Extraction Engine.
    Regexes and patterns to extract IP addresses, domains, URLs, and hashes from
    email bodies and headers. Also provides defanging capability for security safety.
    """

    # Regex patterns
    IPV4_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    # Basic IPv6 regex
    IPV6_REGEX = re.compile(r'\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b')
    # Hash regexes
    SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
    MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')

    # Private IP blocks to ignore in external threat intel lookups
    PRIVATE_IP_PATTERNS = [
        re.compile(r'^127\b'),
        re.compile(r'^10\b'),
        re.compile(r'^192\.168\b'),
        re.compile(r'^172\.(?:1[6-9]|2[0-9]|3[0-1])\b'),
        re.compile(r'^169\.254\b'),
        re.compile(r'^0\b'),
        re.compile(r'^224\b'),
        re.compile(r'^255\b')
    ]

    @classmethod
    def defang_url(cls, url: str) -> str:
        """Defangs a URL to prevent accidental clicks (e.g. hxxps[://]evil[.]com/path)."""
        if not url:
            return ""
        
        # Parse protocol
        protocol = ""
        rest = url
        if url.lower().startswith("https://"):
            protocol = "hxxps[://]"
            rest = url[8:]
        elif url.lower().startswith("http://"):
            protocol = "hxxp[://]"
            rest = url[7:]
            
        # Split host and path
        parts = rest.split("/", 1)
        host = parts[0]
        # Defang dots in host
        defanged_host = host.replace(".", "[.]")
        
        if len(parts) > 1:
            return f"{protocol}{defanged_host}/{parts[1]}"
        return f"{protocol}{defanged_host}"

    @classmethod
    def defang_ip_or_domain(cls, val: str) -> str:
        """Defangs an IP address or domain (e.g. 192[.]0[.]2[.]1 or evil[.]com)."""
        if not val:
            return ""
        return val.replace(".", "[.]")

    def is_private_ip(self, ip: str) -> bool:
        """Checks if an IPv4 is in a private subnet."""
        return any(pattern.match(ip) for pattern in self.PRIVATE_IP_PATTERNS)

    def extract_ips(self, text: str) -> List[str]:
        """Extracts public IPv4 and IPv6 addresses."""
        ips = set()
        
        # IPv4
        for ip in self.IPV4_REGEX.findall(text):
            if not self.is_private_ip(ip):
                ips.add(ip)
                
        # IPv6
        for ip in self.IPV6_REGEX.findall(text):
            # Exclude loopback/link-local basic checks
            if not ip.startswith("::1") and not ip.lower().startswith("fe80"):
                ips.add(ip.lower())
                
        return sorted(list(ips))

    def extract_hashes_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extracts MD5 and SHA-256 hashes from body text."""
        return {
            "sha256": sorted(list(set(self.SHA256_REGEX.findall(text)))),
            "md5": sorted(list(set(self.MD5_REGEX.findall(text))))
        }

    def extract_domains_from_urls(self, urls: List[str]) -> List[str]:
        """Extracts unique domain names from a list of URLs."""
        domains = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                netloc = parsed.netloc.split(":")[0]  # strip port
                if netloc:
                    domains.add(netloc.lower())
            except Exception:
                pass
        return sorted(list(domains))

    def run_extraction(self, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs the full extraction suite on parsed email bodies, headers, and attachments.
        """
        # Combine text and HTML body
        body_content = (parsed_email["body"]["text"] or "") + "\n" + (parsed_email["body"]["html"] or "")
        
        # 1. Extract IPs from body and trace hops
        raw_ips = self.extract_ips(body_content)
        
        # Also extract IPs from Received hop headers
        hop_ips = []
        for hop in parsed_email["hops"]:
            ip = hop.get("from_ip")
            if ip and not self.is_private_ip(ip):
                hop_ips.append(ip)
                
        all_ips = sorted(list(set(raw_ips + hop_ips)))
        
        # 2. Extract hashes from text and compile attachment hashes
        body_hashes = self.extract_hashes_from_text(body_content)
        
        attachment_hashes = []
        for attachment in parsed_email["attachments"]:
            sha256 = attachment.get("sha256")
            if sha256:
                attachment_hashes.append(sha256.lower())
                
        all_sha256 = sorted(list(set(body_hashes["sha256"] + attachment_hashes)))
        all_md5 = body_hashes["md5"]
        
        # 3. Compile URLs from parsed output
        urls = parsed_email.get("urls", [])
        
        # 4. Extract domains from URLs
        domains = self.extract_domains_from_urls(urls)
        
        # Defanged lists for analyst presentation
        defanged_ips = [self.defang_ip_or_domain(ip) for ip in all_ips]
        defanged_domains = [self.defang_ip_or_domain(dom) for dom in domains]
        defanged_urls = [self.defang_url(url) for url in urls]

        return {
            "raw": {
                "ips": all_ips,
                "domains": domains,
                "urls": urls,
                "sha256": all_sha256,
                "md5": all_md5
            },
            "defanged": {
                "ips": defanged_ips,
                "domains": defanged_domains,
                "urls": defanged_urls
            }
        }
