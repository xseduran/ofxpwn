"""
Response Parser

Utility for parsing OFX responses and extracting status codes, messages,
and data from various message types. Critical for avoiding false positives.
"""

import re
from typing import Dict, Optional, List, Any


class OFXResponseParser:
    """Parser for OFX SGML and XML responses"""

    def __init__(self, response_text: str):
        """Initialize parser with response text

        Args:
            response_text: Raw OFX response (SGML or XML)
        """
        self.response_text = response_text
        self.is_xml = response_text.strip().startswith('<?xml')

    def extract_all_status_codes(self) -> Dict[str, Dict[str, Any]]:
        """Extract all status codes from different message sections

        Returns:
            Dictionary mapping message type to status info:
            {
                'signon': {'code': 0, 'severity': 'INFO', 'message': None},
                'bank_statement': {'code': 2003, 'severity': 'ERROR', 'message': 'Access denied'},
                ...
            }
        """
        statuses = {}

        # Signon status
        signon = self._extract_status('SIGNONMSGSRSV1', 'SONRS')
        if signon:
            statuses['signon'] = signon

        # Bank statement status
        bank_stmt = self._extract_status('BANKMSGSRSV1', 'STMTTRNRS')
        if bank_stmt:
            statuses['bank_statement'] = bank_stmt

        # Credit card statement status
        cc_stmt = self._extract_status('CREDITCARDMSGSRSV1', 'CCSTMTTRNRS')
        if cc_stmt:
            statuses['cc_statement'] = cc_stmt

        # Investment statement status
        inv_stmt = self._extract_status('INVSTMTMSGSRSV1', 'INVSTMTTRNRS')
        if inv_stmt:
            statuses['inv_statement'] = inv_stmt

        # Profile status
        profile = self._extract_status('PROFMSGSRSV1', 'PROFTRNRS')
        if profile:
            statuses['profile'] = profile

        # Account info status
        acct_info = self._extract_status('SIGNUPMSGSRSV1', 'ACCTINFOTRNRS')
        if acct_info:
            statuses['account_info'] = acct_info

        return statuses

    def _extract_status(self, msgset: str, trnrs: str) -> Optional[Dict[str, Any]]:
        """Extract status from specific message set

        Args:
            msgset: Message set name (e.g., 'BANKMSGSRSV1')
            trnrs: Transaction response name (e.g., 'STMTTRNRS')

        Returns:
            Dictionary with code, severity, message or None
        """
        # Pattern to match status block within specific transaction response
        pattern = rf'<{msgset}>.*?<{trnrs}>.*?<STATUS>(.*?)</STATUS>'
        match = re.search(pattern, self.response_text, re.DOTALL)

        if not match:
            return None

        status_block = match.group(1)

        # Extract code
        code_match = re.search(r'<CODE>(\d+)', status_block)
        code = int(code_match.group(1)) if code_match else None

        # Extract severity
        severity_match = re.search(r'<SEVERITY>([^<]+)', status_block)
        severity = severity_match.group(1) if severity_match else None

        # Extract message
        message_match = re.search(r'<MESSAGE>([^<]+)', status_block)
        message = message_match.group(1) if message_match else None

        return {
            'code': code,
            'severity': severity,
            'message': message
        }

    def has_data_disclosure(self, account_id: Optional[str] = None) -> Dict[str, bool]:
        """Check if response contains actual financial data

        Args:
            account_id: Optional account ID to verify

        Returns:
            Dictionary indicating what types of data were disclosed:
            {
                'transactions': True/False,
                'positions': True/False,
                'balances': True/False,
                'correct_account': True/False (if account_id provided)
            }
        """
        result = {
            'transactions': False,
            'positions': False,
            'balances': False,
            'correct_account': True  # Default true if not checking
        }

        # Check for transaction data (banking or investment)
        if '<STMTTRN>' in self.response_text or '<INVBANKTRAN>' in self.response_text:
            result['transactions'] = True

        # Check for position data (investments)
        if '<INVPOSLIST>' in self.response_text or '<POSMF>' in self.response_text:
            result['positions'] = True

        # Check for balance data
        if any(tag in self.response_text for tag in ['<INVBAL>', '<LEDGERBAL>', '<AVAILBAL>']):
            result['balances'] = True

        # Verify correct account ID if provided
        if account_id:
            result['correct_account'] = f'<ACCTID>{account_id}</ACCTID>' in self.response_text

        return result

    def extract_accounts(self) -> List[Dict[str, str]]:
        """Extract account information from ACCTINFOTRNRS response

        Returns:
            List of dictionaries with account details:
            [{
                'type': 'CHECKING'/'SAVINGS'/'INVESTMENT'/etc,
                'acctid': '1234567890',
                'bankid': '123456789',  # For bank accounts
                'brokerid': 'example.com',  # For investment accounts
                'status': 'ACTIVE'/'CLOSED'
            }, ...]
        """
        accounts = []

        # Extract banking accounts
        bank_pattern = r'<BANKACCTINFO>.*?<BANKACCTFROM>(.*?)</BANKACCTFROM>.*?<SVCSTATUS>([^<]+)'
        for match in re.finditer(bank_pattern, self.response_text, re.DOTALL):
            acct_block = match.group(1)
            status = match.group(2)

            bankid_match = re.search(r'<BANKID>([^<]+)', acct_block)
            acctid_match = re.search(r'<ACCTID>([^<]+)', acct_block)
            accttype_match = re.search(r'<ACCTTYPE>([^<]+)', acct_block)

            if acctid_match:
                accounts.append({
                    'type': accttype_match.group(1) if accttype_match else 'UNKNOWN',
                    'acctid': acctid_match.group(1),
                    'bankid': bankid_match.group(1) if bankid_match else None,
                    'brokerid': None,
                    'status': status
                })

        # Extract investment accounts
        inv_pattern = r'<INVACCTINFO>.*?<INVACCTFROM>(.*?)</INVACCTFROM>.*?<SVCSTATUS>([^<]+)'
        for match in re.finditer(inv_pattern, self.response_text, re.DOTALL):
            acct_block = match.group(1)
            status = match.group(2)

            brokerid_match = re.search(r'<BROKERID>([^<]+)', acct_block)
            acctid_match = re.search(r'<ACCTID>([^<]+)', acct_block)

            if acctid_match:
                accounts.append({
                    'type': 'INVESTMENT',
                    'acctid': acctid_match.group(1),
                    'bankid': None,
                    'brokerid': brokerid_match.group(1) if brokerid_match else None,
                    'status': status
                })

        # Extract credit card accounts
        cc_pattern = r'<CCACCTINFO>.*?<CCACCTFROM>(.*?)</CCACCTFROM>.*?<SVCSTATUS>([^<]+)'
        for match in re.finditer(cc_pattern, self.response_text, re.DOTALL):
            acct_block = match.group(1)
            status = match.group(2)

            acctid_match = re.search(r'<ACCTID>([^<]+)', acct_block)

            if acctid_match:
                accounts.append({
                    'type': 'CREDITCARD',
                    'acctid': acctid_match.group(1),
                    'bankid': None,
                    'brokerid': None,
                    'status': status
                })

        return accounts

    def is_authentication_failure(self) -> bool:
        """Check if response indicates authentication failure

        Returns:
            True if auth failed, False otherwise
        """
        statuses = self.extract_all_status_codes()
        signon = statuses.get('signon', {})
        return signon.get('code') == 15500

    def is_access_denied(self) -> bool:
        """Check if response indicates access denied (e.g., IDOR blocked)

        Returns:
            True if access denied (2003), False otherwise
        """
        statuses = self.extract_all_status_codes()

        # Check all statement types for access denied
        for key in ['bank_statement', 'cc_statement', 'inv_statement']:
            if key in statuses:
                if statuses[key].get('code') == 2003:
                    return True

        return False

    def is_successful_data_access(self) -> bool:
        """Check if response indicates successful data access

        Returns:
            True if data was successfully retrieved
        """
        statuses = self.extract_all_status_codes()

        # Check for successful signon
        signon = statuses.get('signon', {})
        if signon.get('code') != 0:
            return False

        # Check statement responses for success or warning (12253 = warning but data included)
        for key in ['bank_statement', 'cc_statement', 'inv_statement']:
            if key in statuses:
                code = statuses[key].get('code')
                if code in [0, 12253]:  # Success or warning with data
                    # Verify actual data is present
                    data_check = self.has_data_disclosure()
                    if any(data_check.values()):
                        return True

        return False

    def extract_error_indicators(self, error_keywords: List[str]) -> List[str]:
        """Extract error indicators from response text only

        Args:
            error_keywords: List of keywords to search for (e.g., ['sql', 'mysql'])

        Returns:
            List of found keywords (lowercase)

        Note:
            This only searches the actual response text, not metadata,
            to avoid false positives.
        """
        found = []
        response_lower = self.response_text.lower()

        for keyword in error_keywords:
            if keyword.lower() in response_lower:
                found.append(keyword.lower())

        return found

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of response

        Returns:
            Dictionary with response summary
        """
        statuses = self.extract_all_status_codes()
        data_disclosure = self.has_data_disclosure()
        accounts = self.extract_accounts()

        return {
            'statuses': statuses,
            'auth_failed': self.is_authentication_failure(),
            'access_denied': self.is_access_denied(),
            'data_accessed': self.is_successful_data_access(),
            'data_disclosure': data_disclosure,
            'accounts_found': len(accounts),
            'accounts': accounts
        }
