"""
OFX Parameter Fuzzer Module

Systematically fuzzes OFX authentication parameters to find working combinations.
Tests CLIENTUIDs, FIDs, ORGs, and APPID/APPVER combinations.
"""

import uuid
import threading
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.protocol import OFXRequest
from ofxpwn.core.sender import OFXSender


class ParamFuzzerModule(BaseModule):
    """Comprehensive OFX authentication parameter fuzzer"""

    @classmethod
    def get_description(cls) -> str:
        return "Systematically fuzz authentication parameters (CLIENTUID, FID, ORG, APPID/APPVER)"

    def __init__(self):
        """Initialize fuzzer"""
        super().__init__()
        self.successful_combinations = []
        self.success_lock = threading.Lock()
        self.stop_fuzzing = threading.Event()
        self.request_count = 0
        self.count_lock = threading.Lock()

    def _generate_clientuids(self, count: int = 10) -> List[Optional[str]]:
        """Generate different CLIENTUID formats to test"""
        clientuids = [
            None,  # No CLIENTUID
            '',    # Empty CLIENTUID
        ]

        # UUID v4 with hyphens (standard format)
        for _ in range(count // 2):
            clientuids.append(str(uuid.uuid4()))

        # UUID v4 without hyphens (Quicken/Intuit format - 32 char hex)
        for _ in range(count // 2):
            clientuids.append(str(uuid.uuid4()).replace('-', ''))

        # Some static/common values to test
        clientuids.extend([
            '00000000-0000-0000-0000-000000000000',  # Null UUID with hyphens
            '00000000000000000000000000000000',      # Null UUID without hyphens
            'QWIN',  # APPID as CLIENTUID
            'NONE',
        ])

        return clientuids

    def _generate_fids(self, base_fid: Optional[str] = None) -> List[Optional[str]]:
        """Generate FID values to test"""
        fids = [
            None,      # No FID
            '',        # Empty FID
            '0',       # Zero
            '1',       # Simple digit
            '1234',    # Generic FID
        ]

        # If we have a base FID from config, fuzz around it
        if base_fid and base_fid.isdigit():
            base_num = int(base_fid)
            # Add the base FID first
            fids.insert(0, base_fid)
            # Fuzz around it
            for offset in range(-10, 11):
                if offset == 0:
                    continue
                fid_num = base_num + offset
                if fid_num > 0 and str(fid_num) not in fids:
                    fids.append(str(fid_num))

        return fids

    def _generate_orgs(self, base_org: Optional[str] = None) -> List[Optional[str]]:
        """Generate ORG values to test"""
        orgs = [
            None,      # No ORG
            '',        # Empty ORG
        ]

        if base_org:
            orgs.insert(0, base_org)

            # Generate variations
            orgs.extend([
                base_org.upper(),
                base_org.lower(),
                base_org.replace(' ', ''),
                base_org.replace(' ', '_'),
            ])

        return orgs

    def _generate_appid_combinations(self) -> List[Dict[str, str]]:
        """Generate APPID/APPVER combinations"""
        return [
            # Quicken variations (most common)
            {'appid': 'QWIN', 'appver': '2700'},   # Quicken 2017
            {'appid': 'QWIN', 'appver': '2900'},   # Quicken 2019
            {'appid': 'QWIN', 'appver': '3000'},   # Quicken 2020+
            {'appid': 'QWIN', 'appver': '2600'},   # Quicken 2016
            {'appid': 'QWIN', 'appver': '2500'},   # Quicken 2015
            {'appid': 'QWIN', 'appver': '2400'},   # Quicken 2014
            {'appid': 'QWIN', 'appver': '1700'},   # Quicken older

            # Microsoft Money
            {'appid': 'Money', 'appver': '1700'},
            {'appid': 'Money', 'appver': '1600'},

            # Generic OFX
            {'appid': 'OFX', 'appver': '0100'},

            # Moneydance
            {'appid': 'Moneydance', 'appver': '2021'},

            # GnuCash
            {'appid': 'GNUCASH', 'appver': '5.0'},
        ]

    def _test_combination(
        self,
        sender: OFXSender,
        ofx: OFXRequest,
        username: str,
        password: str,
        clientuid: Optional[str],
        fid: Optional[str],
        org: Optional[str],
        appid: str,
        appver: str
    ) -> Optional[Dict]:
        """Test a specific combination of parameters"""
        # Check if we should stop
        if self.stop_fuzzing.is_set():
            return None

        # Build request with custom parameters
        request_body = ofx.build_sgml_header()
        request_body += "<OFX>\n"

        # Build signon with custom ORG/FID
        signon = ofx.build_signon_sgml(
            username,
            password,
            clientuid=clientuid,
            appid=appid,
            appver=appver,
            org=org,
            fid=fid
        )

        request_body += signon
        request_body += "</OFX>\n"

        # Create descriptive name
        combo_name = f"{appid}_{appver}_fid{fid or 'none'}_org{org or 'none'}_uid{('yes' if clientuid else 'no')}"

        # Send request
        result = sender.send_request(request_body, save_name=f"fuzz_{combo_name}")

        # Increment counter (thread-safe)
        with self.count_lock:
            self.request_count += 1
            current_count = self.request_count

        # Check for success (OFX status 0)
        if result.get('success') and result.get('ofx_status') == 0:
            # SUCCESS! Stop all fuzzing
            self.stop_fuzzing.set()

            with self.success_lock:
                self.logger.success(f"\n{'='*60}")
                self.logger.success("🎉 SUCCESSFUL AUTHENTICATION FOUND!")
                self.logger.success(f"{'='*60}")
                self.logger.success(f"FID: {fid}")
                self.logger.success(f"ORG: {org}")
                self.logger.success(f"CLIENTUID: {clientuid}")
                self.logger.success(f"APPID/APPVER: {appid}/{appver}")
                self.logger.success(f"{'='*60}\n")

                self.successful_combinations.append({
                    'username': username,
                    'fid': fid,
                    'org': org,
                    'clientuid': clientuid,
                    'appid': appid,
                    'appver': appver,
                    'result': result
                })

                # Log as finding
                self.log_finding(
                    'HIGH',
                    'Successful Authentication',
                    f'Found working parameter combination',
                    f'FID={fid}, ORG={org}, CLIENTUID={bool(clientuid)}, APPID={appid}/{appver}'
                )

        return result

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run parameter fuzzing"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("OFX Authentication Parameter Fuzzer")
        logger.info("="*60)

        # Get credentials
        username = config.get("credentials.username", "")
        password = config.get("credentials.password", "")

        if not username or not password:
            logger.error("No credentials provided!")
            logger.error("Set credentials.username and credentials.password in config")
            return {
                'success': False,
                'error': 'No credentials provided'
            }

        # Get fuzzing configuration
        max_requests = config.get("fuzzing.max_requests", 1000)
        max_threads = config.get("fuzzing.max_threads", 20)

        logger.info(f"\nConfiguration:")
        logger.info(f"  Username: {username}")
        logger.info(f"  Max Requests: {max_requests}")
        logger.info(f"  Max Threads: {max_threads}")

        # Get base parameters from config
        base_fid = config.get_target_fid()
        base_org = config.get_target_org()

        # Generate parameter space
        clientuids = self._generate_clientuids(10)
        fids = self._generate_fids(base_fid)
        orgs = self._generate_orgs(base_org)
        app_combos = self._generate_appid_combinations()

        logger.info(f"\nParameter space:")
        logger.info(f"  CLIENTUIDs: {len(clientuids)}")
        logger.info(f"  FIDs: {len(fids)}")
        logger.info(f"  ORGs: {len(orgs)}")
        logger.info(f"  APPID/APPVER: {len(app_combos)}")

        total_combinations = len(clientuids) * len(fids) * len(orgs) * len(app_combos)
        logger.info(f"  Total combinations: {total_combinations}")
        logger.info(f"  Will test: {min(total_combinations, max_requests)}")

        # Build test queue with phased approach
        test_queue = []

        # Phase 1: Base FID with CLIENTUIDs (highest priority)
        if base_fid:
            logger.info(f"\nPhase 1: Testing base FID {base_fid} with CLIENTUIDs...")
            for clientuid in [c for c in clientuids if c]:
                for app in app_combos[:3]:  # Top 3 APPID combos
                    test_queue.append((username, password, clientuid, base_fid, base_org, app['appid'], app['appver']))

        # Phase 2: Base FID without CLIENTUID
        if base_fid:
            logger.info(f"Phase 2: Testing base FID {base_fid} without CLIENTUID...")
            for org in [base_org, None]:
                for app in app_combos[:5]:  # Top 5 APPID combos
                    test_queue.append((username, password, None, base_fid, org, app['appid'], app['appver']))

        # Phase 3: FID fuzzing with base ORG
        logger.info(f"Phase 3: Fuzzing FIDs with base ORG...")
        for fid in fids:
            for clientuid in [None] + clientuids[:3]:  # No UID + top 3 UIDs
                for app in app_combos[:3]:
                    if len(test_queue) >= max_requests:
                        break
                    test_queue.append((username, password, clientuid, fid, base_org, app['appid'], app['appver']))
            if len(test_queue) >= max_requests:
                break

        # Phase 4: Broader fuzzing
        logger.info(f"Phase 4: Broader parameter fuzzing...")
        for fid in fids:
            for org in orgs:
                for clientuid in clientuids:
                    for app in app_combos:
                        if len(test_queue) >= max_requests:
                            break
                        test_queue.append((username, password, clientuid, fid, org, app['appid'], app['appver']))

        # Limit to max_requests
        test_queue = test_queue[:max_requests]

        logger.info(f"\n🚀 Starting fuzzing: {len(test_queue)} requests with {max_threads} threads...")

        # Initialize sender and OFX request builder
        sender = OFXSender(config, logger)
        ofx = OFXRequest(
            org=config.get_target_org(),
            fid=config.get_target_fid()
        )

        # Execute tests with threading
        results = []

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {
                executor.submit(
                    self._test_combination,
                    sender,
                    ofx,
                    *params
                ): i for i, params in enumerate(test_queue)
            }

            for future in as_completed(futures):
                if self.stop_fuzzing.is_set():
                    logger.info("\n🎉 SUCCESS FOUND! Cancelling remaining requests...")
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    break

                try:
                    result = future.result()
                    if result:
                        results.append(result)

                    # Progress update every 50 requests
                    with self.count_lock:
                        current = self.request_count

                    if current % 50 == 0:
                        logger.info(f"Progress: {current}/{len(test_queue)} requests completed")

                except Exception as e:
                    logger.error(f"Request failed: {str(e)}")

        # Summary
        logger.info(f"\n{'='*60}")
        logger.info("Fuzzing Complete")
        logger.info(f"{'='*60}")
        logger.info(f"Total requests sent: {self.request_count}")
        logger.info(f"Successful combinations: {len(self.successful_combinations)}")

        if self.successful_combinations:
            logger.success("\n✓ FOUND WORKING AUTHENTICATION COMBINATION(S)!\n")

            for i, combo in enumerate(self.successful_combinations, 1):
                logger.info(f"Success #{i}:")
                logger.info(f"  Username: {combo['username']}")
                logger.info(f"  FID: {combo['fid']}")
                logger.info(f"  ORG: {combo['org']}")
                logger.info(f"  CLIENTUID: {combo['clientuid']}")
                logger.info(f"  APPID/APPVER: {combo['appid']}/{combo['appver']}")
                logger.info(f"  OFX Status: {combo['result'].get('ofx_status')}")
                logger.info("")
        else:
            logger.warning("\n✗ No successful authentication combinations found")
            logger.info("\nSuggestions:")
            logger.info("  1. Verify credentials are correct")
            logger.info("  2. Check if account is enabled for OFX access")
            logger.info("  3. Verify IP is not blocked")
            logger.info("  4. Increase fuzzing.max_requests in config")
            logger.info("  5. Check if server requires specific CLIENTUID format")

        logger.info(f"{'='*60}\n")

        return {
            'success': len(self.successful_combinations) > 0,
            'requests_sent': self.request_count,
            'successful_combinations': self.successful_combinations,
            'total_results': len(results)
        }
