"""
HTTP Sender

Handles HTTP communication with OFX servers including proxy support,
SSL verification, timeout handling, and response tracking.
"""

import requests
import urllib3
import hashlib
import time
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.protocol import OFXResponse

# Disable SSL warnings when using proxy
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OFXSender:
    """HTTP client for sending OFX requests"""

    def __init__(self, config: Config, logger: Logger):
        """Initialize sender

        Args:
            config: Configuration object
            logger: Logger object
        """
        self.config = config
        self.logger = logger

        # Statistics tracking
        self.request_count = 0
        self.response_hashes = set()
        self.start_time = datetime.now()

    def send_request(
        self,
        body: str,
        save_name: Optional[str] = None,
        content_type: str = "application/x-ofx"
    ) -> Dict[str, Any]:
        """Send OFX request

        Args:
            body: OFX request body
            save_name: Optional name for saving request/response
            content_type: HTTP Content-Type header

        Returns:
            Dictionary with response data
        """
        target_url = self.config.get_target_url()
        proxies = self._get_proxies()
        verify_ssl = self.config.get_proxy_verify_ssl() if proxies else True

        headers = {
            'Content-Type': content_type,
            'Accept': '*/*, application/x-ofx',
            'User-Agent': 'OFXpwn/1.0',
        }

        # Log request
        self.logger.log_request('POST', target_url, headers, body)

        # Send request
        start_time = time.time()
        try:
            response = requests.post(
                target_url,
                headers=headers,
                data=body.encode('utf-8'),
                proxies=proxies,
                verify=verify_ssl,
                timeout=self.config.get_timeout()
            )
            elapsed = time.time() - start_time

        except requests.exceptions.Timeout:
            self.logger.error(f"Request timeout after {self.config.get_timeout()}s")
            return {
                'success': False,
                'error': 'timeout',
                'elapsed': self.config.get_timeout()
            }

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'elapsed': time.time() - start_time
            }

        # Log response
        self.logger.log_response(
            response.status_code,
            dict(response.headers),
            response.text,
            elapsed
        )

        # Parse OFX response
        ofx_response = OFXResponse(response.text)

        # Track statistics
        self.request_count += 1
        response_hash = self._hash_response(response.text)

        # Save if configured
        if self.config.should_save_requests() or self.config.should_save_responses():
            self._save_transaction(
                body,
                response.text,
                response.status_code,
                ofx_response,
                save_name,
                response_hash
            )

        # Build result
        result = {
            'success': True,
            'http_status': response.status_code,
            'ofx_status': ofx_response.get_status_code(),
            'ofx_message': ofx_response.get_status_message(),
            'ofx_severity': ofx_response.get_severity(),
            'is_success': ofx_response.is_success(),
            'is_auth_failure': ofx_response.is_auth_failure(),
            'elapsed': elapsed,
            'response_hash': response_hash,
            'response_text': response.text,
            'headers': dict(response.headers)
        }

        # Check if unique
        if response_hash not in self.response_hashes:
            result['is_unique'] = True
            self.response_hashes.add(response_hash)
        else:
            result['is_unique'] = False

        return result

    def _get_proxies(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration"""
        if self.config.is_proxy_enabled():
            proxy_url = self.config.get_proxy_url()
            return {
                'http': proxy_url,
                'https': proxy_url
            }
        return None

    def _hash_response(self, response_text: str) -> str:
        """Generate SHA256 hash of response"""
        return hashlib.sha256(response_text.encode()).hexdigest()

    def _save_transaction(
        self,
        request_body: str,
        response_body: str,
        http_status: int,
        ofx_response: OFXResponse,
        save_name: Optional[str],
        response_hash: str
    ):
        """Save request/response to disk"""
        if not save_name:
            save_name = f"request_{self.request_count}"

        # Create evidence directory
        evidence_dir = self.config.get_output_dir() / "evidence" / save_name
        evidence_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save request
        if self.config.should_save_requests():
            request_file = evidence_dir / f"{timestamp}_request.ofx"
            request_file.write_text(request_body)

        # Save response
        if self.config.should_save_responses():
            # Check if we should only save unique responses
            if self.config.get("output.save_unique_only", True):
                if response_hash in self.response_hashes and len(self.response_hashes) > 1:
                    return  # Skip saving duplicate

            response_file = evidence_dir / f"{timestamp}_response.txt"
            response_content = (
                f"HTTP Status: {http_status}\n"
                f"OFX Status: {ofx_response.get_status_code()}\n"
                f"Response Hash: {response_hash}\n\n"
                f"{'='*80}\n\n"
                f"{response_body}\n"
            )
            response_file.write_text(response_content)

    def get_stats(self) -> Dict[str, Any]:
        """Get sender statistics"""
        elapsed = (datetime.now() - self.start_time).total_seconds()

        return {
            'requests_sent': self.request_count,
            'unique_responses': len(self.response_hashes),
            'elapsed_seconds': elapsed,
            'requests_per_second': self.request_count / elapsed if elapsed > 0 else 0
        }
