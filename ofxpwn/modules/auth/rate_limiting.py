"""
Rate Limiting Detection Module

Comprehensive testing for authentication rate limiting, account lockout,
and brute force protection mechanisms.
"""

from typing import Dict, Any, List
import time

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.protocol import OFXRequest
from ofxpwn.core.sender import OFXSender
from ofxpwn.core.response_parser import OFXResponseParser


class RateLimitingModule(BaseModule):
    """Test for rate limiting and account lockout mechanisms"""

    @classmethod
    def get_description(cls) -> str:
        return "Test for rate limiting, account lockout, and brute force protection"

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run rate limiting detection"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("Rate Limiting and Account Lockout Testing")
        logger.info("="*60)
        logger.warning("Testing brute force protection mechanisms...")
        logger.info("")

        # Get credentials
        username = config.get('auth', {}).get('username')

        if not username:
            logger.error("No username configured!")
            return {'error': 'No username configured'}

        ofx = OFXRequest(
            org=config.get_target_org(),
            fid=config.get_target_fid()
        )
        sender = OFXSender(config, logger)

        results = {
            'lockout_detected': False,
            'rate_limit_detected': False,
            'delay_injection_detected': False,
            'failed_attempts_before_lockout': 0,
            'response_times': [],
            'http_status_codes': [],
            'ofx_status_codes': []
        }

        # Test 1: Failed Authentication Attempts
        logger.info("="*60)
        logger.info("TEST 1: Account Lockout Detection")
        logger.info("="*60)
        logger.info(f"Sending {config.get('rate_limit_test_count', 20)} failed login attempts...")
        logger.info("")

        self._test_account_lockout(
            ofx, sender, username, results, config
        )

        # Test 2: Rate Limiting Headers
        logger.info("\n" + "="*60)
        logger.info("TEST 2: Rate Limiting Headers")
        logger.info("="*60)
        logger.info("Checking for rate limit indicators in responses...")
        logger.info("")

        self._check_rate_limit_headers(results)

        # Test 3: Delay Injection Detection
        logger.info("\n" + "="*60)
        logger.info("TEST 3: Progressive Delay Detection")
        logger.info("="*60)
        logger.info("Analyzing response times for delay injection...")
        logger.info("")

        self._analyze_delay_injection(results)

        # Summary
        logger.info("\n" + "="*60)
        logger.info("Rate Limiting Test Results")
        logger.info("="*60)

        if not results['lockout_detected'] and not results['rate_limit_detected']:
            logger.finding(
                'MEDIUM',
                'No Rate Limiting Detected',
                'Server allows unlimited failed authentication attempts',
                f'Tested {results["failed_attempts_before_lockout"]} attempts without lockout'
            )
            logger.warning("⚠️  VULNERABLE: No rate limiting or account lockout")
        else:
            logger.success("✓ Rate limiting mechanisms detected")

        if results['lockout_detected']:
            logger.info(f"  Account lockout after {results['failed_attempts_before_lockout']} attempts")

        if results['rate_limit_detected']:
            logger.info(f"  Rate limiting detected (HTTP 429 or similar)")

        if results['delay_injection_detected']:
            logger.info(f"  Progressive delays detected")
            logger.info(f"    First request: {results['response_times'][0]:.3f}s")
            logger.info(f"    Last request: {results['response_times'][-1]:.3f}s")

        # Response time statistics
        if results['response_times']:
            avg_time = sum(results['response_times']) / len(results['response_times'])
            min_time = min(results['response_times'])
            max_time = max(results['response_times'])

            logger.info(f"\nResponse Time Statistics:")
            logger.info(f"  Min: {min_time:.3f}s")
            logger.info(f"  Max: {max_time:.3f}s")
            logger.info(f"  Avg: {avg_time:.3f}s")

        stats = sender.get_stats()
        logger.info(f"\nRequests sent: {stats['requests_sent']}")

        return results

    def _test_account_lockout(
        self,
        ofx: OFXRequest,
        sender: OFXSender,
        username: str,
        results: Dict[str, Any],
        config: Config
    ):
        """Test for account lockout after failed attempts

        Args:
            ofx: OFX request builder
            sender: Request sender
            username: Username to test
            results: Results dict to update
            config: Configuration object
        """
        test_count = config.get('rate_limit_test_count', 20)
        wrong_password = "WrongPassword123!@#"

        for i in range(1, test_count + 1):
            self.logger.info(f"[{i}/{test_count}] Attempting with wrong password...")

            # Build request with wrong password
            request_body = self._build_auth_request(
                ofx, username, wrong_password
            )

            start_time = time.time()
            result = sender.send_request(
                request_body,
                save_name=f"rate_limit_{i}"
            )
            end_time = time.time()

            response_time = end_time - start_time
            results['response_times'].append(response_time)

            if not result.get('success'):
                self.logger.warning(f"  Request failed: {result.get('error')}")
                continue

            # Track HTTP and OFX status codes
            http_status = result.get('http_status')
            results['http_status_codes'].append(http_status)

            parser = OFXResponseParser(result.get('response_text', ''))
            statuses = parser.extract_all_status_codes()
            signon = statuses.get('signon', {})
            ofx_code = signon.get('code')
            ofx_message = signon.get('message', '').lower()

            results['ofx_status_codes'].append(ofx_code)

            # Check for lockout indicators
            if http_status == 429:
                self.logger.warning(f"  ⚠️  HTTP 429 (Too Many Requests) - Rate limited!")
                results['rate_limit_detected'] = True
                results['lockout_detected'] = True
                results['failed_attempts_before_lockout'] = i
                break

            if ofx_code == 15500:
                # Normal auth failure
                if ofx_message and any(word in ofx_message for word in ['locked', 'blocked', 'disabled', 'suspended']):
                    self.logger.warning(f"  ⚠️  Account locked: {ofx_message}")
                    results['lockout_detected'] = True
                    results['failed_attempts_before_lockout'] = i
                    break
                else:
                    self.logger.info(f"  Auth failed (15500) - {response_time:.3f}s")
            else:
                self.logger.info(f"  Status {ofx_code} - {response_time:.3f}s")

            # Small delay between attempts (be respectful)
            if config.get('rate_limit_delay', 0.1) > 0:
                time.sleep(config.get('rate_limit_delay', 0.1))

        if not results['lockout_detected']:
            results['failed_attempts_before_lockout'] = test_count
            self.logger.warning(f"  ⚠️  No lockout after {test_count} attempts")

    def _check_rate_limit_headers(self, results: Dict[str, Any]):
        """Check for rate limiting indicators in HTTP headers

        Args:
            results: Results dict to update
        """
        # Check for HTTP 429 in status codes
        if 429 in results['http_status_codes']:
            self.logger.warning("✓ HTTP 429 (Too Many Requests) detected")
            results['rate_limit_detected'] = True
        else:
            self.logger.info("No HTTP 429 responses observed")

        # Additional checks could include:
        # - X-RateLimit-* headers
        # - Retry-After headers
        # - Custom rate limit headers

    def _analyze_delay_injection(self, results: Dict[str, Any]):
        """Analyze response times for progressive delay injection

        Args:
            results: Results dict to update
        """
        if len(results['response_times']) < 5:
            self.logger.info("Not enough data for delay analysis")
            return

        # Calculate if response times are increasing
        times = results['response_times']
        first_half_avg = sum(times[:len(times)//2]) / (len(times)//2)
        second_half_avg = sum(times[len(times)//2:]) / (len(times) - len(times)//2)

        increase_percentage = ((second_half_avg - first_half_avg) / first_half_avg) * 100

        if increase_percentage > 50:  # More than 50% increase
            self.logger.warning(f"⚠️  Progressive delay detected: {increase_percentage:.1f}% increase")
            results['delay_injection_detected'] = True
        else:
            self.logger.info(f"No significant delay injection ({increase_percentage:.1f}% change)")

    def _build_auth_request(
        self,
        ofx: OFXRequest,
        username: str,
        password: str
    ) -> str:
        """Build simple authentication request

        Args:
            ofx: OFX request builder
            username: Username
            password: Password

        Returns:
            OFX request body
        """
        signon = ofx.build_signon(username, password)
        return ofx.wrap_request(signon)
