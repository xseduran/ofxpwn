"""
Account Enumeration Module

Discovers accessible accounts via ACCTINFORQ (Account Information Request).
This is critical reconnaissance for IDOR testing and understanding the
attack surface.
"""

from typing import Dict, Any, List
from datetime import datetime, timedelta

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.protocol import OFXRequest
from ofxpwn.core.sender import OFXSender
from ofxpwn.core.response_parser import OFXResponseParser


class AccountEnumerationModule(BaseModule):
    """Enumerate accessible accounts via ACCTINFORQ"""

    @classmethod
    def get_description(cls) -> str:
        return "Enumerate accessible accounts (ACCTINFORQ)"

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run account enumeration"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("Account Enumeration (ACCTINFORQ)")
        logger.info("="*60)
        logger.info("Discovering accessible accounts for authenticated user...")
        logger.info("")

        # Get credentials
        username = config.get('auth', {}).get('username')
        password = config.get('auth', {}).get('password')

        if not username or not password:
            logger.error("No credentials configured!")
            return {'error': 'No credentials configured'}

        ofx = OFXRequest(
            org=config.get_target_org(),
            fid=config.get_target_fid()
        )
        sender = OFXSender(config, logger)

        results = {
            'accounts_found': [],
            'account_count': 0,
            'banking_accounts': 0,
            'investment_accounts': 0,
            'creditcard_accounts': 0,
            'tests_run': 0
        }

        # Test 1: Basic account info request
        logger.info("="*60)
        logger.info("TEST 1: Basic Account Information Request")
        logger.info("="*60)
        logger.info("Requesting account list without date filter...")
        logger.info("")

        basic_accounts = self._test_basic_acct_info(
            ofx, sender, username, password
        )

        if basic_accounts:
            results['accounts_found'].extend(basic_accounts)
            logger.info(f"✓ Found {len(basic_accounts)} accounts")
        else:
            logger.info("No accounts returned")

        results['tests_run'] += 1

        # Test 2: Account info with various date parameters
        logger.info("\n" + "="*60)
        logger.info("TEST 2: Account Info with Date Filters")
        logger.info("="*60)
        logger.info("Testing different DTACCTUP values...")
        logger.info("")

        date_tests = [
            ("19900101000000", "Very old date (1990)"),
            ("20000101000000", "Y2K date (2000)"),
            ((datetime.now() - timedelta(days=365)).strftime("%Y%m%d000000"), "1 year ago"),
            ((datetime.now() - timedelta(days=30)).strftime("%Y%m%d000000"), "30 days ago"),
        ]

        for dtacctup, description in date_tests:
            logger.info(f"Testing: {description} ({dtacctup})")

            date_accounts = self._test_acct_info_with_date(
                ofx, sender, username, password, dtacctup
            )

            results['tests_run'] += 1

            if date_accounts:
                # Add any new accounts not already in list
                for acct in date_accounts:
                    if acct not in results['accounts_found']:
                        results['accounts_found'].append(acct)
                        logger.info(f"  ✓ Found new account: {acct['acctid']}")
            else:
                logger.info(f"  No new accounts")

        # Deduplicate and categorize accounts
        unique_accounts = self._deduplicate_accounts(results['accounts_found'])
        results['accounts_found'] = unique_accounts
        results['account_count'] = len(unique_accounts)

        # Categorize by type
        for acct in unique_accounts:
            acct_type = acct.get('type', '').upper()
            if acct_type == 'INVESTMENT':
                results['investment_accounts'] += 1
            elif acct_type == 'CREDITCARD':
                results['creditcard_accounts'] += 1
            elif acct_type in ['CHECKING', 'SAVINGS', 'MONEYMRKT', 'CREDITLINE']:
                results['banking_accounts'] += 1

        # Display results
        logger.info("\n" + "="*60)
        logger.info("Account Enumeration Results")
        logger.info("="*60)

        if results['account_count'] > 0:
            logger.success(f"✓ Found {results['account_count']} total accounts")
            logger.info(f"  Banking accounts: {results['banking_accounts']}")
            logger.info(f"  Investment accounts: {results['investment_accounts']}")
            logger.info(f"  Credit card accounts: {results['creditcard_accounts']}")

            logger.info("\nAccount Details:")
            for i, acct in enumerate(unique_accounts, 1):
                logger.info(f"\n[{i}] Account ID: {acct['acctid']}")
                logger.info(f"    Type: {acct['type']}")
                logger.info(f"    Status: {acct['status']}")
                if acct.get('bankid'):
                    logger.info(f"    Bank ID: {acct['bankid']}")
                if acct.get('brokerid'):
                    logger.info(f"    Broker ID: {acct['brokerid']}")

            # Save accounts for IDOR testing
            if config.get('auto_configure_idor', True):
                logger.info("\n✓ Accounts saved for IDOR testing")
                logger.info("  Run IDOR module with these discovered accounts")

        else:
            logger.warning("⚠️  No accounts found")
            logger.info("Possible reasons:")
            logger.info("  - ACCTINFORQ not supported by server")
            logger.info("  - Account has no linked accounts")
            logger.info("  - Different date range required")

        logger.info(f"\nTests run: {results['tests_run']}")

        stats = sender.get_stats()
        logger.info(f"Requests sent: {stats['requests_sent']}")

        return results

    def _test_basic_acct_info(
        self,
        ofx: OFXRequest,
        sender: OFXSender,
        username: str,
        password: str
    ) -> List[Dict[str, str]]:
        """Test basic account info request without date filter

        Args:
            ofx: OFX request builder
            sender: Request sender
            username: Username for auth
            password: Password for auth

        Returns:
            List of account dictionaries
        """
        request_body = self._build_acct_info_request(
            ofx, username, password, dtacctup=None
        )

        result = sender.send_request(
            request_body,
            save_name="acct_enum_basic"
        )

        if not result.get('success'):
            self.logger.error(f"Request failed: {result.get('error')}")
            return []

        # Parse response
        parser = OFXResponseParser(result.get('response_text', ''))
        accounts = parser.extract_accounts()

        return accounts

    def _test_acct_info_with_date(
        self,
        ofx: OFXRequest,
        sender: OFXSender,
        username: str,
        password: str,
        dtacctup: str
    ) -> List[Dict[str, str]]:
        """Test account info request with specific date

        Args:
            ofx: OFX request builder
            sender: Request sender
            username: Username for auth
            password: Password for auth
            dtacctup: Date string in YYYYMMDDHHMMSS format

        Returns:
            List of account dictionaries
        """
        request_body = self._build_acct_info_request(
            ofx, username, password, dtacctup=dtacctup
        )

        result = sender.send_request(
            request_body,
            save_name=f"acct_enum_{dtacctup[:8]}"
        )

        if not result.get('success'):
            return []

        # Parse response
        parser = OFXResponseParser(result.get('response_text', ''))
        accounts = parser.extract_accounts()

        return accounts

    def _build_acct_info_request(
        self,
        ofx: OFXRequest,
        username: str,
        password: str,
        dtacctup: str = None
    ) -> str:
        """Build ACCTINFORQ request

        Args:
            ofx: OFX request builder
            username: Username for signon
            password: Password for signon
            dtacctup: Optional date for accounts updated since

        Returns:
            OFX request body
        """
        # Build signon
        signon = ofx.build_signon(username, password)

        # Build account info request
        dtacctup_tag = f"<DTACCTUP>{dtacctup}" if dtacctup else ""

        acct_info = f"""<SIGNUPMSGSRQV1>
<ACCTINFOTRNRQ>
<TRNUID>1001
<ACCTINFORQ>
{dtacctup_tag}
</ACCTINFORQ>
</ACCTINFOTRNRQ>
</SIGNUPMSGSRQV1>
"""

        return ofx.wrap_request(signon + acct_info)

    def _deduplicate_accounts(self, accounts: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Remove duplicate accounts from list

        Args:
            accounts: List of account dictionaries

        Returns:
            List of unique account dictionaries
        """
        seen = set()
        unique = []

        for acct in accounts:
            # Use acctid as unique identifier
            acctid = acct.get('acctid')
            if acctid and acctid not in seen:
                seen.add(acctid)
                unique.append(acct)

        return unique
