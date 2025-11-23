"""
Protocol Fuzzing Module

Sends malformed OFX requests to test parser robustness.
"""

from typing import Dict, Any
import time

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.sender import OFXSender


class ProtocolFuzzModule(BaseModule):
    """OFX protocol fuzzing"""

    @classmethod
    def get_description(cls) -> str:
        return "Fuzz OFX protocol with malformed requests"

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run protocol fuzzing"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("OFX Protocol Fuzzing")
        logger.info("="*60)
        logger.warning("Testing parser with malformed requests...")

        sender = OFXSender(config, logger)

        results = {
            'tests_run': 0,
            'crashes': [],
            'errors': [],
            'interesting': []
        }

        # Test cases
        test_cases = [
            {
                'name': 'Missing closing tags',
                'payload': 'OFXHEADER:100\nDATA:OFXSGML\nVERSION:102\n\n<OFX><SIGNONMSGSRQV1><SONRQ><USERID>test\n'
            },
            {
                'name': 'Duplicate tags',
                'payload': 'OFXHEADER:100\nDATA:OFXSGML\nVERSION:102\n\n<OFX><USERID>test1<USERID>test2</USERID></OFX>\n'
            },
            {
                'name': 'Invalid nesting',
                'payload': 'OFXHEADER:100\nDATA:OFXSGML\nVERSION:102\n\n<OFX></USERID><USERID>test</USERID></OFX>\n'
            },
            {
                'name': 'Extremely long tag name',
                'payload': f'OFXHEADER:100\nDATA:OFXSGML\nVERSION:102\n\n<OFX><{"A"*10000}>test</{"A"*10000}></OFX>\n'
            },
            {
                'name': 'Invalid characters in tags',
                'payload': 'OFXHEADER:100\nDATA:OFXSGML\nVERSION:102\n\n<OFX><USER@#$ID>test</USER@#$ID></OFX>\n'
            },
            {
                'name': 'Empty OFX body',
                'payload': 'OFXHEADER:100\nDATA:OFXSGML\nVERSION:102\n\n<OFX></OFX>\n'
            },
            {
                'name': 'Invalid OFX version',
                'payload': 'OFXHEADER:100\nDATA:OFXSGML\nVERSION:999\n\n<OFX><USERID>test</USERID></OFX>\n'
            },
            {
                'name': 'Missing OFX header',
                'payload': '<OFX><USERID>test</USERID></OFX>\n'
            },
            {
                'name': 'Garbage data',
                'payload': 'GARBAGE\n\nRANDOM\n\nDATA\n\nHERE\n'
            },
        ]

        for test_case in test_cases:
            logger.info(f"\nTesting: {test_case['name']}")

            result = sender.send_request(
                test_case['payload'],
                save_name=f"fuzz_{test_case['name'].replace(' ', '_').lower()}"
            )

            results['tests_run'] += 1

            if not result.get('success'):
                error = result.get('error', 'unknown')

                if 'timeout' in error:
                    logger.finding(
                        'HIGH',
                        'Parser Timeout/Hang',
                        f'Malformed request caused timeout: {test_case["name"]}',
                        'Parser may be vulnerable to DoS'
                    )
                    results['crashes'].append(test_case['name'])
                else:
                    logger.warning(f"  Request failed: {error}")
                    results['errors'].append({
                        'test': test_case['name'],
                        'error': error
                    })
                continue

            http_status = result.get('http_status')
            ofx_status = result.get('ofx_status')

            logger.info(f"  HTTP: {http_status}, OFX: {ofx_status}")

            # Check for crashes/500 errors
            if http_status == 500:
                logger.finding(
                    'HIGH',
                    'Server Error on Malformed Input',
                    f'HTTP 500 with: {test_case["name"]}',
                    'Parser may crash or error on invalid input'
                )
                results['crashes'].append(test_case['name'])

            # Check for interesting responses
            elif http_status not in [200, 400]:
                logger.info(f"  Interesting HTTP status: {http_status}")
                results['interesting'].append({
                    'test': test_case['name'],
                    'http_status': http_status,
                    'ofx_status': ofx_status
                })

            time.sleep(0.5)

        # Summary
        logger.info("\n" + "="*60)
        logger.info("Protocol Fuzzing Summary")
        logger.info("="*60)
        logger.info(f"Tests run: {results['tests_run']}")
        logger.info(f"Crashes/500 errors: {len(results['crashes'])}")
        logger.info(f"Request errors: {len(results['errors'])}")
        logger.info(f"Interesting responses: {len(results['interesting'])}")

        if results['crashes']:
            logger.warning("Parser errors detected with malformed input!")
        else:
            logger.success("Parser handles malformed input gracefully")

        return results
