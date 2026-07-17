import email
import re
import hashlib
import logging
from email.message import Message
from email.utils import parseaddr, getaddresses
from email.header import decode_header
from typing import List, Dict, Any, Optional, Tuple
from bs4 import BeautifulSoup
from datetime import datetime
import dateutil.parser

logger = logging.getLogger(__name__)

class EmailParserError(Exception):
    """Custom exception for Email Parser Engine errors."""
    pass

class EmailParser:
    """
    Email Parser Engine responsible for parsing .eml content,
    decoding MIME bodies, extracting metadata, trace headers, URLs, and attachments.
    """
    
    # URL extraction regex for plain text
    URL_REGEX = re.compile(
        r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s<>"]*)?'
    )
    
    # IP address extraction regex (for parsing Received headers)
    IP_REGEX = re.compile(
        r'\[(?:[0-9]{1,3}\.){3}[0-9]{1,3}\]|(?:\b[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    )

    @classmethod
    def decode_mime_header(cls, header_value: Optional[str]) -> str:
        """Decodes RFC 2047 encoded-word headers safely."""
        if not header_value:
            return ""
        try:
            decoded_parts = decode_header(header_value)
            header_text = []
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    charset = encoding or 'utf-8'
                    try:
                        header_text.append(part.decode(charset, errors='replace'))
                    except Exception:
                        header_text.append(part.decode('latin1', errors='replace'))
                else:
                    header_text.append(str(part))
            return "".join(header_text).strip()
        except Exception as e:
            logger.warning(f"Error decoding header {header_value}: {e}")
            return str(header_value).strip()

    @classmethod
    def parse_address_field(cls, header_value: Optional[str]) -> List[Dict[str, str]]:
        """Parses email headers containing address fields (e.g. From, To, CC, BCC)."""
        if not header_value:
            return []
        
        decoded = cls.decode_mime_header(header_value)
        addresses = getaddresses([decoded])
        result = []
        for name, addr in addresses:
            result.append({
                "name": name.strip(),
                "email": addr.strip().lower()
            })
        return result

    @classmethod
    def parse_single_address(cls, header_value: Optional[str]) -> Dict[str, str]:
        """Parses a single address field (e.g. Return-Path, Reply-To)."""
        parsed = cls.parse_address_field(header_value)
        if parsed:
            return parsed[0]
        return {"name": "", "email": ""}

    def parse_received_headers(self, msg: Message) -> List[Dict[str, Any]]:
        """
        Parses all 'Received' headers to trace the hop path of the email.
        The returned list is ordered chronologically (oldest hop to newest hop).
        Historically, the bottom 'Received' header in an EML file is the first hop (sender).
        The top 'Received' header is the last hop (destination server).
        """
        raw_received = msg.get_all('received', [])
        hops = []
        
        for idx, rec_val in enumerate(raw_received):
            decoded_val = self.decode_mime_header(rec_val)
            hop_info = self.parse_single_received_header(decoded_val)
            hop_info["hop_index"] = len(raw_received) - idx # index 1 is oldest, N is newest
            hop_info["raw"] = decoded_val
            hops.append(hop_info)
            
        # Reverse list to make it chronological (oldest first)
        hops.reverse()
        return hops

    def parse_single_received_header(self, received_str: str) -> Dict[str, Any]:
        """
        Parses a single Received header value to extract the declared 'from' host,
        the identified sender IP, the receiving 'by' host, and the timestamp.
        """
        data = {
            "from_host": "",
            "from_ip": "",
            "by_host": "",
            "timestamp": None,
            "timestamp_raw": ""
        }
        
        # Clean whitespaces
        cleaned = " ".join(received_str.split())
        
        # Extract timestamp (usually at the end after a semicolon ';')
        parts = cleaned.split(';')
        if len(parts) > 1:
            timestamp_raw = parts[-1].strip()
            data["timestamp_raw"] = timestamp_raw
            try:
                dt = dateutil.parser.parse(timestamp_raw)
                data["timestamp"] = dt.isoformat()
            except Exception:
                pass
            
            # The body of the received header is before the semicolon
            body = ";".join(parts[:-1]).strip()
        else:
            body = cleaned
            
        # Extract 'from' section
        # Format: from host (rdns [IP])
        from_match = re.search(r'from\s+(.*?)\s+(?:by\s+|with\s+|id\s+|for\s+|$)', body, re.IGNORECASE)
        if from_match:
            data["from_host"] = from_match.group(1).strip()
            
            # Try to extract the IP address inside the 'from' statement
            ip_matches = self.IP_REGEX.findall(data["from_host"])
            if ip_matches:
                # Clean brackets if any
                data["from_ip"] = ip_matches[0].strip('[]')
                
        # Extract 'by' section
        by_match = re.search(r'by\s+(.*?)\s+(?:with\s+|id\s+|for\s+|$)', body, re.IGNORECASE)
        if by_match:
            data["by_host"] = by_match.group(1).strip()
            
        return data

    def extract_urls(self, text_body: str, html_body: str) -> List[str]:
        """Extracts unique URLs from both text and HTML bodies."""
        urls = set()
        
        # 1. Extract from html via BeautifulSoup
        if html_body:
            try:
                soup = BeautifulSoup(html_body, 'html.parser')
                for a in soup.find_all('a', href=True):
                    href = a['href'].strip()
                    if href.startswith(('http://', 'https://')):
                        urls.add(href)
            except Exception as e:
                logger.warning(f"Error parsing HTML with BeautifulSoup: {e}")
                
        # 2. Extract from text using regex (and HTML in case it has raw URLs in text)
        for text in [text_body, html_body]:
            if text:
                matches = self.URL_REGEX.findall(text)
                for match in matches:
                    urls.add(match.strip())
                    
        return sorted(list(urls))

    def parse_message_body_and_attachments(self, msg: Message) -> Tuple[str, str, List[Dict[str, Any]]]:
        """
        Recursively extracts text body, HTML body, and attachments from MIME parts.
        """
        text_parts = []
        html_parts = []
        attachments = []
        
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = part.get("Content-Disposition", "")
            
            # Check if this part is an attachment
            is_attachment = False
            filename = part.get_filename()
            
            if filename:
                is_attachment = True
                filename = self.decode_mime_header(filename)
            elif "attachment" in content_disposition.lower():
                is_attachment = True
                filename = filename or "unnamed_attachment"
                
            if is_attachment:
                # Decode attachment data
                try:
                    payload = part.get_payload(decode=True)
                    if payload is not None:
                        sha256_hash = hashlib.sha256(payload).hexdigest()
                        size = len(payload)
                        attachments.append({
                            "filename": filename,
                            "content_type": content_type,
                            "size_bytes": size,
                            "sha256": sha256_hash,
                            # We don't store the full attachment in memory for standard analysis reports,
                            # but we expose these metadata for Threat Intel checks
                        })
                except Exception as e:
                    logger.error(f"Failed to process attachment {filename}: {e}")
                continue
                
            # If not an attachment, read text/html bodies
            if content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        text_parts.append(payload.decode(charset, errors="replace"))
                except Exception as e:
                    logger.warning(f"Error decoding text/plain part: {e}")
            elif content_type == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        html_parts.append(payload.decode(charset, errors="replace"))
                except Exception as e:
                    logger.warning(f"Error decoding text/html part: {e}")
                    
        text_body = "\n".join(text_parts).strip()
        html_body = "\n".join(html_parts).strip()
        
        return text_body, html_body, attachments

    def parse(self, raw_eml_content: str) -> Dict[str, Any]:
        """
        Parses raw EML string content and compiles a structured email representation.
        """
        try:
            msg = email.message_from_string(raw_eml_content)
        except Exception as e:
            raise EmailParserError(f"Failed to parse raw email content: {e}")
            
        # Parse envelope
        subject = self.decode_mime_header(msg.get("Subject", ""))
        date_str = self.decode_mime_header(msg.get("Date", ""))
        message_id = self.decode_mime_header(msg.get("Message-ID", ""))
        
        # Address parsing
        sender_list = self.parse_address_field(msg.get("From"))
        sender = sender_list[0] if sender_list else {"name": "", "email": ""}
        
        recipients = self.parse_address_field(msg.get("To"))
        cc = self.parse_address_field(msg.get("Cc"))
        bcc = self.parse_address_field(msg.get("Bcc"))
        
        return_path = self.parse_single_address(msg.get("Return-Path"))
        reply_to = self.parse_single_address(msg.get("Reply-To"))
        
        # Parse bodies & attachments
        text_body, html_body, attachments = self.parse_message_body_and_attachments(msg)
        
        # Extract URLs
        urls = self.extract_urls(text_body, html_body)
        
        # Parse trace hops
        hops = self.parse_received_headers(msg)
        
        # Determine the source IP (first hop IP)
        source_ip = ""
        for hop in hops:
            if hop.get("from_ip"):
                source_ip = hop["from_ip"]
                break  # The oldest hop with an IP is our best guess for the sending origin
                
        return {
            "envelope": {
                "sender": sender,
                "recipients": recipients,
                "cc": cc,
                "bcc": bcc,
                "subject": subject,
                "date": date_str,
                "message_id": message_id,
                "return_path": return_path,
                "reply_to": reply_to
            },
            "hops": hops,
            "source_ip": source_ip,
            "body": {
                "text": text_body,
                "html": html_body
            },
            "attachments": attachments,
            "urls": urls
        }
