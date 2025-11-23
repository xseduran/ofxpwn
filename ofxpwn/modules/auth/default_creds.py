"""
Default Credentials Testing Module

Tests common default credentials against the OFX server.
"""

from pathlib import Path
from typing import Dict, Any, List, Tuple
import time

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.protocol import OFXRequest
from ofxpwn.core.sender import OFXSender


class DefaultCredsModule(BaseModule):
    """Test default credentials"""

    @classmethod
    def get_description(cls) -> str:
        return "Test common default credentials against OFX server"

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run default credential testing"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("Default Credentials Testing")
        logger.info("="*60)

        # Load default credentials
        creds = self._load_default_creds()
        logger.info(f"Loaded {len(creds)} default credential pairs")

        # Initialize components
        ofx = OFXRequest(
            org=config.get_target_org(),
            fid=config.get_target_fid()
        )
        sender = OFXSender(config, logger)

        # Test credentials
        results = []
        success_count = 0

        for idx, (username, password) in enumerate(creds, 1):
            logger.info(f"[{idx}/{len(creds)}] Testing {username}:{password}")

            # Build authentication request (SGML)
            request_body = ofx.build_sgml_header() + "<OFX>\n"
            request_body += ofx.build_signon_sgml(username, password)
            request_body += "</OFX>\n"

            # Send request
            result = sender.send_request(
                request_body,
                save_name=f"default_creds_{username}"
            )

            if not result.get('success'):
                logger.warning(f"Request failed: {result.get('error')}")
                continue

            # Check result
            ofx_status = result.get('ofx_status')
            http_status = result.get('http_status')

            if result.get('is_success'):
                # SUCCESS!
                logger.finding(
                    'CRITICAL',
                    'Default Credentials Found',
                    f'Valid credentials: {username}:{password}',
                    f'OFX Status: {ofx_status}, HTTP Status: {http_status}'
                )
                success_count += 1
                results.append({
                    'username': username,
                    'password': password,
                    'status': 'success'
                })

            elif ofx_status == 15500:
                # Auth failure (expected)
                logger.debug(f"Invalid credentials (OFX 15500)")
                results.append({
                    'username': username,
                    'password': password,
                    'status': 'invalid'
                })

            elif ofx_status and ofx_status != 15500:
                # Different error - interesting!
                logger.finding(
                    'MEDIUM',
                    'Non-Standard Auth Response',
                    f'Credentials {username}:{password} returned OFX {ofx_status}',
                    f'Message: {result.get("ofx_message")}'
                )
                results.append({
                    'username': username,
                    'password': password,
                    'status': f'error_{ofx_status}'
                })

            # Rate limiting
            time.sleep(0.5)  # Half second between attempts

        # Summary
        logger.info("\n" + "="*60)
        logger.info("Default Credentials Testing Complete")
        logger.info("="*60)
        logger.info(f"Credentials tested: {len(creds)}")
        logger.info(f"Valid credentials found: {success_count}")

        if success_count > 0:
            logger.success(f"Found {success_count} valid credential(s)!")
        else:
            logger.info("No default credentials found")

        # Statistics
        stats = sender.get_stats()
        logger.info(f"\nRequests sent: {stats['requests_sent']}")
        logger.info(f"Elapsed time: {stats['elapsed_seconds']:.2f}s")

        return {
            'tested': len(creds),
            'success': success_count,
            'results': results,
            'stats': stats
        }

    def _load_default_creds(self) -> List[Tuple[str, str]]:
        """Load default credentials from file"""
        creds_file = self.config.get('auth.default_creds_file')

        if not creds_file:
            # Use built-in defaults
            creds_file = Path(__file__).parent.parent.parent / "payloads" / "default_creds.txt"

        creds = []

        try:
            with open(creds_file, 'r') as f:
                for line in f:
                    line = line.strip()

                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue

                    # Parse username:password
                    if ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            creds.append((parts[0], parts[1]))

        except FileNotFoundError:
            self.logger.warning(f"Credentials file not found: {creds_file}")
            # Return minimal defaults
            creds = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('test', 'test'),
                ('guest', 'guest')
            ]

        return creds
