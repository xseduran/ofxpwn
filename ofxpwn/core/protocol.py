"""
OFX Protocol Implementation

Handles OFX 1.x (SGML) and 2.x (XML) request generation and response parsing.
"""

import re
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from xml.etree import ElementTree as ET


class OFXRequest:
    """OFX request builder supporting both SGML and XML formats"""

    def __init__(self, org: Optional[str] = None, fid: Optional[str] = None):
        """Initialize OFX request builder

        Args:
            org: Financial institution organization name
            fid: Financial institution ID
        """
        self.org = org
        self.fid = fid

    @staticmethod
    def generate_uuid() -> str:
        """Generate UUID v4 for CLIENTUID and TRNUID"""
        return str(uuid.uuid4())

    @staticmethod
    def generate_uuid_no_hyphens() -> str:
        """Generate UUID without hyphens (Quicken format)"""
        return str(uuid.uuid4()).replace('-', '')

    @staticmethod
    def generate_timestamp(offset_hours: int = 0) -> str:
        """Generate OFX timestamp: YYYYMMDDHHMMSS"""
        dt = datetime.now() + timedelta(hours=offset_hours)
        return dt.strftime("%Y%m%d%H%M%S")

    @staticmethod
    def generate_timestamp_xml(offset_hours: int = 0, timezone: str = "-5:EST") -> str:
        """Generate OFX 2.x timestamp with timezone"""
        ts = OFXRequest.generate_timestamp(offset_hours)
        return f"{ts}.000[{timezone}]"

    def build_sgml_header(self, version: str = "102") -> str:
        """Build OFX SGML header

        Args:
            version: OFX version (102, 103, 151, 160)

        Returns:
            SGML header string
        """
        return (
            f"OFXHEADER:100\n"
            f"DATA:OFXSGML\n"
            f"VERSION:{version}\n"
            f"SECURITY:NONE\n"
            f"ENCODING:USASCII\n"
            f"CHARSET:1252\n"
            f"COMPRESSION:NONE\n"
            f"OLDFILEUID:NONE\n"
            f"NEWFILEUID:NONE\n\n"
        )

    def build_xml_header(self, version: str = "200") -> str:
        """Build OFX XML header

        Args:
            version: OFX version (200, 202, 211, 220)

        Returns:
            XML header string
        """
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<?OFX OFXHEADER="200" VERSION="{version}" '
            f'SECURITY="NONE" OLDFILEUID="NONE" NEWFILEUID="NONE"?>\n'
        )

    def build_signon_sgml(
        self,
        userid: str,
        userpass: str,
        clientuid: Optional[str] = None,
        appid: str = "QWIN",
        appver: str = "2700",
        language: str = "ENG",
        dtclient: Optional[str] = None,
        org: Optional[str] = None,
        fid: Optional[str] = None
    ) -> str:
        """Build SIGNON message (SGML format)"""
        if dtclient is None:
            dtclient = self.generate_timestamp()

        # Use provided or default org/fid
        use_org = org if org is not None else self.org
        use_fid = fid if fid is not None else self.fid

        signon = (
            f"<SIGNONMSGSRQV1>\n"
            f"<SONRQ>\n"
            f"<DTCLIENT>{dtclient}\n"
            f"<USERID>{userid}\n"
            f"<USERPASS>{userpass}\n"
            f"<LANGUAGE>{language}\n"
        )

        # Add FI block
        if use_org or use_fid:
            signon += "<FI>\n"
            if use_org:
                signon += f"<ORG>{use_org}\n"
            if use_fid:
                signon += f"<FID>{use_fid}\n"
            signon += "</FI>\n"

        signon += f"<APPID>{appid}\n<APPVER>{appver}\n"

        if clientuid:
            signon += f"<CLIENTUID>{clientuid}\n"

        signon += "</SONRQ>\n</SIGNONMSGSRQV1>\n"

        return signon

    def build_signon_xml(
        self,
        userid: str,
        userpass: str,
        clientuid: Optional[str] = None,
        appid: str = "QWIN",
        appver: str = "2700",
        language: str = "ENG",
        dtclient: Optional[str] = None,
        org: Optional[str] = None,
        fid: Optional[str] = None
    ) -> str:
        """Build SIGNON message (XML format)"""
        if dtclient is None:
            dtclient = self.generate_timestamp_xml()

        use_org = org if org is not None else self.org
        use_fid = fid if fid is not None else self.fid

        signon = (
            f"<SIGNONMSGSRQV1>\n"
            f"  <SONRQ>\n"
            f"    <DTCLIENT>{dtclient}</DTCLIENT>\n"
            f"    <USERID>{userid}</USERID>\n"
            f"    <USERPASS>{userpass}</USERPASS>\n"
            f"    <LANGUAGE>{language}</LANGUAGE>\n"
        )

        if use_org or use_fid:
            signon += "    <FI>\n"
            if use_org:
                signon += f"      <ORG>{use_org}</ORG>\n"
            if use_fid:
                signon += f"      <FID>{use_fid}</FID>\n"
            signon += "    </FI>\n"

        signon += (
            f"    <APPID>{appid}</APPID>\n"
            f"    <APPVER>{appver}</APPVER>\n"
        )

        if clientuid:
            signon += f"    <CLIENTUID>{clientuid}</CLIENTUID>\n"

        signon += "  </SONRQ>\n</SIGNONMSGSRQV1>\n"

        return signon

    def build_profile_request(
        self,
        userid: str = "anonymous",
        userpass: str = "anonymous",
        use_xml: bool = False,
        version: str = None
    ) -> str:
        """Build profile request (PROFRQ)

        Often works without authentication.
        """
        if version is None:
            version = "200" if use_xml else "102"

        trnuid = self.generate_uuid()

        if use_xml:
            header = self.build_xml_header(version)
            signon = self.build_signon_xml(userid, userpass)
            profile = (
                f"<PROFMSGSRQV1>\n"
                f"  <PROFTRNRQ>\n"
                f"    <TRNUID>{trnuid}</TRNUID>\n"
                f"    <PROFRQ>\n"
                f"      <CLIENTROUTING>NONE</CLIENTROUTING>\n"
                f"      <DTPROFUP>19700101000000</DTPROFUP>\n"
                f"    </PROFRQ>\n"
                f"  </PROFTRNRQ>\n"
                f"</PROFMSGSRQV1>\n"
            )
            return f"{header}<OFX>\n{signon}{profile}</OFX>"
        else:
            header = self.build_sgml_header(version)
            signon = self.build_signon_sgml(userid, userpass)
            profile = (
                f"<PROFMSGSRQV1>\n"
                f"<PROFTRNRQ>\n"
                f"<TRNUID>{trnuid}\n"
                f"<PROFRQ>\n"
                f"<CLIENTROUTING>NONE\n"
                f"<DTPROFUP>19700101000000\n"
                f"</PROFRQ>\n"
                f"</PROFTRNRQ>\n"
                f"</PROFMSGSRQV1>\n"
            )
            return f"{header}<OFX>\n{signon}{profile}</OFX>\n"

    def build_account_info_request(
        self,
        userid: str,
        userpass: str,
        clientuid: Optional[str] = None,
        use_xml: bool = False,
        version: str = None
    ) -> str:
        """Build account information request (ACCTINFORQ)"""
        if version is None:
            version = "200" if use_xml else "102"

        trnuid = self.generate_uuid()

        if use_xml:
            header = self.build_xml_header(version)
            signon = self.build_signon_xml(userid, userpass, clientuid)
            acctinfo = (
                f"<SIGNUPMSGSRQV1>\n"
                f"  <ACCTINFOTRNRQ>\n"
                f"    <TRNUID>{trnuid}</TRNUID>\n"
                f"    <ACCTINFORQ>\n"
                f"      <DTACCTUP>19700101000000</DTACCTUP>\n"
                f"    </ACCTINFORQ>\n"
                f"  </ACCTINFOTRNRQ>\n"
                f"</SIGNUPMSGSRQV1>\n"
            )
            return f"{header}<OFX>\n{signon}{acctinfo}</OFX>"
        else:
            header = self.build_sgml_header(version)
            signon = self.build_signon_sgml(userid, userpass, clientuid)
            acctinfo = (
                f"<SIGNUPMSGSRQV1>\n"
                f"<ACCTINFOTRNRQ>\n"
                f"<TRNUID>{trnuid}\n"
                f"<ACCTINFORQ>\n"
                f"<DTACCTUP>19700101000000\n"
                f"</ACCTINFORQ>\n"
                f"</ACCTINFOTRNRQ>\n"
                f"</SIGNUPMSGSRQV1>\n"
            )
            return f"{header}<OFX>\n{signon}{acctinfo}</OFX>\n"


class OFXResponse:
    """OFX response parser"""

    def __init__(self, response_text: str):
        """Initialize with response text

        Args:
            response_text: Raw OFX response
        """
        self.response_text = response_text
        self.is_xml = self._detect_format()

    def _detect_format(self) -> bool:
        """Detect if response is XML or SGML"""
        return self.response_text.strip().startswith('<?xml')

    def get_status_code(self) -> Optional[int]:
        """Extract OFX status code from response

        Returns:
            Status code or None if not found
        """
        # Try regex first (works for both SGML and XML)
        match = re.search(r'<CODE>(\d+)', self.response_text)
        if match:
            return int(match.group(1))

        # Try XML parsing
        if self.is_xml:
            try:
                root = ET.fromstring(self.response_text)
                code_elem = root.find('.//CODE')
                if code_elem is not None and code_elem.text:
                    return int(code_elem.text)
            except:
                pass

        return None

    def get_status_message(self) -> Optional[str]:
        """Extract status message from response"""
        match = re.search(r'<MESSAGE>([^<]+)', self.response_text)
        if match:
            return match.group(1)

        if self.is_xml:
            try:
                root = ET.fromstring(self.response_text)
                msg_elem = root.find('.//MESSAGE')
                if msg_elem is not None and msg_elem.text:
                    return msg_elem.text
            except:
                pass

        return None

    def get_severity(self) -> Optional[str]:
        """Extract severity from response"""
        match = re.search(r'<SEVERITY>([^<]+)', self.response_text)
        if match:
            return match.group(1)
        return None

    def is_success(self) -> bool:
        """Check if response indicates success"""
        code = self.get_status_code()
        return code == 0 if code is not None else False

    def is_auth_failure(self) -> bool:
        """Check if response is authentication failure"""
        code = self.get_status_code()
        return code == 15500 if code is not None else False

    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary"""
        return {
            'status_code': self.get_status_code(),
            'message': self.get_status_message(),
            'severity': self.get_severity(),
            'is_success': self.is_success(),
            'is_auth_failure': self.is_auth_failure(),
            'format': 'xml' if self.is_xml else 'sgml',
            'raw': self.response_text
        }
