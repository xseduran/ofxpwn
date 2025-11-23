"""
Authentication Testing Module

Tests authentication with user-supplied credentials.
"""

from typing import Dict, Any

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.protocol import OFXRequest
from ofxpwn.core.sender import OFXSender


class LoginModule(BaseModule):
    """Test authentication with provided credentials"""

    @classmethod
    def get_description(cls) -> str:
        return "Test authentication with user-supplied credentials"

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Test login with provided credentials"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("Authentication Test")
        logger.info("="*60)

        # Get credentials from config
        username = config.get("credentials.username", "")
        password = config.get("credentials.password", "")
        clientuid = config.get("credentials.clientuid", "")

        if not username or not password:
            logger.error("No credentials provided!")
            logger.error("Set credentials.username and credentials.password in config")
            logger.error("Or pass via command line:")
            logger.error("  --username <user> --password <pass>")
            return {
                'success': False,
                'error': 'No credentials provided'
            }

        logger.info(f"\nTesting credentials:")
        logger.info(f"  Username: {username}")
        logger.info(f"  Password: {'*' * len(password)}")
        if clientuid:
            logger.info(f"  Client UID: {clientuid}")

        ofx = OFXRequest(
            org=config.get_target_org(),
            fid=config.get_target_fid()
        )
        sender = OFXSender(config, logger)

        # Test SGML login (most common)
        logger.info("\nAttempting SGML authentication (OFX 1.x)...")

        request_body = ofx.build_sgml_header() + "<OFX>\n"
        request_body += ofx.build_signon_sgml(username, password, clientuid=clientuid or None)
        request_body += "</OFX>\n"

        result = sender.send_request(request_body, save_name="login_test")

        if not result.get('success'):
            logger.error(f"Request failed: {result.get('error')}")
            return {
                'success': False,
                'error': result.get('error')
            }

        http_status = result.get('http_status')
        ofx_status = result.get('ofx_status')
        response = result.get('response_text', '')

        logger.info(f"\nResponse:")
        logger.info(f"  HTTP Status: {http_status}")
        logger.info(f"  OFX Status: {ofx_status}")

        results = {
            'http_status': http_status,
            'ofx_status': ofx_status,
            'authenticated': False,
            'message': ''
        }

        # Interpret results
        if ofx_status == 0:
            logger.success("\n" + "="*60)
            logger.success("AUTHENTICATION SUCCESSFUL!")
            logger.success("="*60)
            logger.success(f"Valid credentials: {username}:{password}")
            if clientuid:
                logger.success(f"Client UID: {clientuid}")
            
            results['authenticated'] = True
            results['message'] = 'Authentication successful'
            
            # Log as finding
            self.log_finding(
                'INFO',
                'Successful Authentication',
                f'Authenticated as user: {username}',
                'Credentials validated'
            )

        elif ofx_status == 15500:
            logger.error("\n" + "="*60)
            logger.error("AUTHENTICATION FAILED")
            logger.error("="*60)
            logger.error("Invalid username or password (OFX Status 15500)")
            
            results['authenticated'] = False
            results['message'] = 'Invalid credentials (15500)'

        elif ofx_status == 2000:
            logger.warning("\n" + "="*60)
            logger.warning("AUTHENTICATION STATUS UNCLEAR")
            logger.warning("="*60)
            logger.warning("OFX Status 2000 - General Error")
            logger.warning("This may indicate:")
            logger.warning("  - Server requires additional parameters")
            logger.warning("  - Wrong ORG or FID")
            logger.warning("  - Client UID required but not provided")
            
            results['authenticated'] = False
            results['message'] = 'General error (2000) - check ORG/FID/CLIENTUID'

        elif ofx_status == 15501:
            logger.error("\n" + "="*60)
            logger.error("CUSTOMER ACCOUNT IN USE")
            logger.error("="*60)
            logger.error("OFX Status 15501 - User account already logged in")
            
            results['authenticated'] = False
            results['message'] = 'Account in use (15501)'

        elif ofx_status == 15502:
            logger.error("\n" + "="*60)
            logger.error("CLIENT UID ERROR")
            logger.error("="*60)
            logger.error("OFX Status 15502 - Invalid or missing CLIENTUID")
            logger.warning("Try providing a CLIENTUID in config:")
            logger.warning("  credentials:")
            logger.warning("    clientuid: \"unique-device-id\"")
            
            results['authenticated'] = False
            results['message'] = 'Invalid CLIENTUID (15502)'

        elif ofx_status == 15503:
            logger.error("\n" + "="*60)
            logger.error("CLIENT UID LOCKED")
            logger.error("="*60)
            logger.error("OFX Status 15503 - CLIENTUID is locked")
            
            results['authenticated'] = False
            results['message'] = 'CLIENTUID locked (15503)'

        else:
            logger.warning("\n" + "="*60)
            logger.warning(f"UNEXPECTED OFX STATUS: {ofx_status}")
            logger.warning("="*60)
            logger.warning("Check response for details")
            
            results['authenticated'] = False
            results['message'] = f'Unexpected status ({ofx_status})'

        # Show response excerpt
        if response:
            logger.info("\nResponse excerpt:")
            excerpt = response[:500] if len(response) > 500 else response
            for line in excerpt.split('\n')[:10]:
                if line.strip():
                    logger.info(f"  {line}")
            if len(response) > 500:
                logger.info(f"  ... ({len(response)} bytes total)")

        # Summary
        logger.info("\n" + "="*60)
        logger.info("Authentication Test Summary")
        logger.info("="*60)
        logger.info(f"Username: {username}")
        logger.info(f"HTTP Status: {http_status}")
        logger.info(f"OFX Status: {ofx_status}")
        logger.info(f"Result: {results['message']}")
        
        if results['authenticated']:
            logger.success("\nCredentials are VALID")
        else:
            logger.error("\nCredentials are INVALID or additional parameters required")

        return results
