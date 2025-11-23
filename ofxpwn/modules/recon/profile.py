"""
Profile Request Module (PROFRQ)

Tests unauthenticated profile requests to gather server capabilities and configuration.
Many OFX servers expose this information without authentication.
"""

from typing import Dict, Any
import re

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.protocol import OFXRequest
from ofxpwn.core.sender import OFXSender


class ProfileModule(BaseModule):
    """Unauthenticated profile request testing"""

    @classmethod
    def get_description(cls) -> str:
        return "Test for unauthenticated profile information disclosure (PROFRQ)"

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run profile request testing"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("Profile Request (PROFRQ) Testing")
        logger.info("="*60)
        logger.warning("Testing unauthenticated access to server capabilities...")

        ofx = OFXRequest(
            org=config.get_target_org(),
            fid=config.get_target_fid()
        )
        sender = OFXSender(config, logger)

        results = {
            'anonymous_access': False,
            'capabilities': [],
            'message_sets': [],
            'server_info': {}
        }

        # Test SGML profile request
        logger.info("\nTesting SGML profile request...")
        logger.info("Using credentials: anonymous:anonymous")

        request_body = ofx.build_profile_request(
            userid='anonymous',
            userpass='anonymous',
            use_xml=False
        )

        result = sender.send_request(
            request_body,
            save_name="profile_anonymous_sgml"
        )

        if not result.get('success'):
            logger.error(f"Request failed: {result.get('error')}")
            return results

        # Analyze response
        http_status = result.get('http_status')
        ofx_status = result.get('ofx_status')
        response_text = result.get('response_text', '')

        logger.info(f"HTTP Status: {http_status}")
        logger.info(f"OFX Status: {ofx_status}")

        # Check if profile info was returned
        if '<PROFRS>' in response_text or '<PROFTRNRS>' in response_text:
            logger.finding(
                'HIGH',
                'Unauthenticated Profile Disclosure',
                'Server returns profile information without authentication',
                f'HTTP {http_status}, OFX {ofx_status}'
            )
            results['anonymous_access'] = True

            # Extract capabilities
            capabilities = self._extract_capabilities(response_text)
            if capabilities:
                logger.info("\nServer Capabilities Disclosed:")
                for cap in capabilities:
                    logger.info(f"  - {cap}")
                results['capabilities'] = capabilities

            # Extract message sets
            message_sets = self._extract_message_sets(response_text)
            if message_sets:
                logger.info("\nSupported Message Sets:")
                for msgset in message_sets:
                    logger.info(f"  - {msgset}")
                results['message_sets'] = message_sets

            # Extract other server info
            server_info = self._extract_server_info(response_text)
            results['server_info'] = server_info

        elif ofx_status == 15500:
            logger.info("Authentication required (OFX 15500)")
            logger.info("Server properly requires authentication for profile requests")

        elif ofx_status == 0:
            logger.info("Request accepted (OFX 0) but no profile data in response")
            logger.info("Check saved response for details")

        else:
            logger.warning(f"Non-standard response: OFX {ofx_status}")
            if result.get('ofx_message'):
                logger.info(f"Message: {result.get('ofx_message')}")

        # Try with different fake credentials
        logger.info("\nTesting with fake credentials (test:test)...")

        request_body = ofx.build_profile_request(
            userid='test',
            userpass='test',
            use_xml=False
        )

        result2 = sender.send_request(
            request_body,
            save_name="profile_test_sgml"
        )

        if result2.get('success'):
            http_status2 = result2.get('http_status')
            ofx_status2 = result2.get('ofx_status')
            response_text2 = result2.get('response_text', '')

            logger.info(f"HTTP Status: {http_status2}")
            logger.info(f"OFX Status: {ofx_status2}")

            if '<PROFRS>' in response_text2:
                logger.finding(
                    'HIGH',
                    'Profile Info with Any Credentials',
                    'Server returns profile info with fake credentials',
                    'Weak/no authentication on PROFRQ endpoint'
                )

        # Summary
        logger.info("\n" + "="*60)
        logger.info("Profile Request Summary")
        logger.info("="*60)

        if results['anonymous_access']:
            logger.warning("VULNERABLE: Profile information disclosed without auth!")
            logger.info(f"Capabilities found: {len(results['capabilities'])}")
            logger.info(f"Message sets found: {len(results['message_sets'])}")
        else:
            logger.success("Profile requests properly require authentication")

        stats = sender.get_stats()
        logger.info(f"\nRequests sent: {stats['requests_sent']}")

        return results

    def _extract_capabilities(self, response: str) -> list:
        """Extract capabilities from profile response"""
        capabilities = []

        # Look for common capability tags
        cap_patterns = [
            r'<SIGNONINFO>',
            r'<BANKMSGSRQV1>',
            r'<CREDITCARDMSGSRQV1>',
            r'<INVSTMTMSGSRQV1>',
            r'<BILLPAY>',
            r'<EMAIL>',
        ]

        for pattern in cap_patterns:
            if re.search(pattern, response):
                cap_name = pattern.strip('<>').replace('MSGSRQV1', '').replace('INFO', '')
                capabilities.append(cap_name)

        return capabilities

    def _extract_message_sets(self, response: str) -> list:
        """Extract supported message sets"""
        message_sets = []

        # Common message set indicators
        msgset_patterns = [
            (r'<BANKMSGSETV1>', 'Banking'),
            (r'<CREDITCARDMSGSETV1>', 'Credit Card'),
            (r'<INVSTMTMSGSETV1>', 'Investment'),
            (r'<BILLPAYMSGSETV1>', 'Bill Pay'),
            (r'<EMAILMSGSETV1>', 'Email'),
            (r'<SECLISTMSGSETV1>', 'Security List'),
            (r'<PROFMSGSETV1>', 'Profile'),
            (r'<SIGNUPMSGSETV1>', 'Signup'),
        ]

        for pattern, name in msgset_patterns:
            if re.search(pattern, response):
                message_sets.append(name)

        return message_sets

    def _extract_server_info(self, response: str) -> dict:
        """Extract server information from response"""
        info = {}

        # Extract FI name
        fi_name_match = re.search(r'<FINAME>([^<]+)', response)
        if fi_name_match:
            info['fi_name'] = fi_name_match.group(1)

        # Extract FI org
        org_match = re.search(r'<ORG>([^<]+)', response)
        if org_match:
            info['org'] = org_match.group(1)

        # Extract FID
        fid_match = re.search(r'<FID>([^<]+)', response)
        if fid_match:
            info['fid'] = fid_match.group(1)

        # Extract server date/time
        dtserver_match = re.search(r'<DTSERVER>([^<]+)', response)
        if dtserver_match:
            info['server_time'] = dtserver_match.group(1)

        return info
