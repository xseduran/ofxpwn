"""
HTTP Security Headers Module

Analyzes HTTP security headers and identifies missing protections.
"""

from typing import Dict, Any

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.protocol import OFXRequest
from ofxpwn.core.sender import OFXSender


class HeadersModule(BaseModule):
    """HTTP security headers analysis"""

    @classmethod
    def get_description(cls) -> str:
        return "Analyze HTTP security headers"

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run header analysis"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("HTTP Security Headers Analysis")
        logger.info("="*60)

        ofx = OFXRequest(
            org=config.get_target_org(),
            fid=config.get_target_fid()
        )
        sender = OFXSender(config, logger)

        # Send a simple request to get headers
        request_body = ofx.build_sgml_header() + "<OFX>\n"
        request_body += ofx.build_signon_sgml('test', 'test')
        request_body += "</OFX>\n"

        result = sender.send_request(request_body, save_name="headers_test")

        if not result.get('success'):
            logger.error("Failed to retrieve headers")
            return {}

        headers = result.get('headers', {})

        results = {
            'present': [],
            'missing': [],
            'informational': [],
            'security_score': 0
        }

        # Security headers to check
        security_headers = {
            'Strict-Transport-Security': {
                'severity': 'MEDIUM',
                'description': 'HSTS - Forces HTTPS connections',
                'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
            },
            'X-Content-Type-Options': {
                'severity': 'LOW',
                'description': 'Prevents MIME-sniffing',
                'recommendation': 'Add: X-Content-Type-Options: nosniff'
            },
            'X-Frame-Options': {
                'severity': 'LOW',
                'description': 'Prevents clickjacking',
                'recommendation': 'Add: X-Frame-Options: DENY'
            },
            'Content-Security-Policy': {
                'severity': 'MEDIUM',
                'description': 'Controls resource loading',
                'recommendation': 'Add appropriate CSP policy'
            },
            'X-XSS-Protection': {
                'severity': 'INFO',
                'description': 'XSS filter (deprecated but still useful)',
                'recommendation': 'Add: X-XSS-Protection: 1; mode=block'
            }
        }

        # Information disclosure headers
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']

        logger.info("\nSecurity Headers Analysis:")
        logger.info("-" * 60)

        # Check security headers
        for header_name, info in security_headers.items():
            if header_name in headers:
                logger.success(f"✓ {header_name}: {headers[header_name]}")
                results['present'].append(header_name)
                results['security_score'] += 20
            else:
                severity = info['severity']
                logger.warning(f"✗ {header_name}: MISSING")
                logger.info(f"  {info['description']}")
                logger.info(f"  Recommendation: {info['recommendation']}")

                results['missing'].append(header_name)

                self.log_finding(
                    severity,
                    f'Missing Security Header: {header_name}',
                    info['description'],
                    info['recommendation']
                )

        # Check for information disclosure
        logger.info("\nInformation Disclosure Headers:")
        logger.info("-" * 60)

        for header_name in info_headers:
            if header_name in headers:
                value = headers[header_name]
                logger.warning(f"! {header_name}: {value}")

                results['informational'].append({
                    'header': header_name,
                    'value': value
                })

                self.log_finding(
                    'LOW',
                    f'Information Disclosure: {header_name}',
                    f'Server reveals technology information: {value}',
                    f'Remove or obfuscate {header_name} header'
                )

        # Additional header checks
        logger.info("\nAdditional Checks:")
        logger.info("-" * 60)

        # Check for CORS
        if 'Access-Control-Allow-Origin' in headers:
            cors_value = headers['Access-Control-Allow-Origin']
            logger.info(f"CORS: {cors_value}")

            if cors_value == '*':
                self.log_finding(
                    'MEDIUM',
                    'Overly Permissive CORS',
                    'Access-Control-Allow-Origin set to *',
                    'Restrict CORS to specific trusted origins'
                )

        # Check cache control
        cache_headers = ['Cache-Control', 'Pragma', 'Expires']
        has_cache_control = any(h in headers for h in cache_headers)

        if not has_cache_control:
            logger.warning("No cache control headers found")
            self.log_finding(
                'LOW',
                'Missing Cache Control',
                'No cache control headers present',
                'Add appropriate cache headers for sensitive data'
            )

        # Summary
        logger.info("\n" + "="*60)
        logger.info("Security Headers Summary")
        logger.info("="*60)
        logger.info(f"Security headers present: {len(results['present'])}/{ len(security_headers)}")
        logger.info(f"Security headers missing: {len(results['missing'])}")
        logger.info(f"Information disclosure headers: {len(results['informational'])}")
        logger.info(f"Security score: {results['security_score']}/100")

        if results['security_score'] < 60:
            logger.warning("Poor security header implementation")
        elif results['security_score'] < 80:
            logger.info("Moderate security header implementation")
        else:
            logger.success("Good security header implementation")

        return results
