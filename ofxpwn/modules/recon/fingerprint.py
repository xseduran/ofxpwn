"""
Server Fingerprinting Module

Identifies OFX server version, technology stack, and supported features.
"""

from typing import Dict, Any

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.protocol import OFXRequest
from ofxpwn.core.sender import OFXSender


class FingerprintModule(BaseModule):
    """Server fingerprinting and version detection"""

    @classmethod
    def get_description(cls) -> str:
        return "Fingerprint OFX server and detect version/technology"

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run server fingerprinting"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("OFX Server Fingerprinting")
        logger.info("="*60)

        ofx = OFXRequest(
            org=config.get_target_org(),
            fid=config.get_target_fid()
        )
        sender = OFXSender(config, logger)

        results = {
            'target_url': config.get_target_url(),
            'supported_versions': {
                'sgml': [],
                'xml': []
            },
            'server_info': {},
            'interesting_findings': []
        }

        # Test SGML versions
        logger.info("\nTesting SGML (OFX 1.x) versions...")
        sgml_versions = config.get('ofx.sgml_versions', ['102', '103', '151', '160'])

        for version in sgml_versions:
            logger.info(f"  Testing SGML version {version}...")

            request_body = ofx.build_sgml_header(version) + "<OFX>\n"
            request_body += ofx.build_signon_sgml('test', 'test')
            request_body += "</OFX>\n"

            result = sender.send_request(
                request_body,
                save_name=f"fingerprint_sgml_{version}"
            )

            if result.get('http_status') == 200:
                logger.success(f"    SGML {version}: ACCEPTED (HTTP 200)")
                results['supported_versions']['sgml'].append(version)
            elif result.get('http_status') == 400:
                logger.info(f"    SGML {version}: REJECTED (HTTP 400)")
            else:
                logger.info(f"    SGML {version}: HTTP {result.get('http_status')}")

        # Test XML versions
        logger.info("\nTesting XML (OFX 2.x) versions...")
        xml_versions = config.get('ofx.xml_versions', ['200', '202', '211', '220'])

        for version in xml_versions:
            logger.info(f"  Testing XML version {version}...")

            request_body = ofx.build_xml_header(version) + "<OFX>\n"
            request_body += ofx.build_signon_xml('test', 'test')
            request_body += "</OFX>"

            result = sender.send_request(
                request_body,
                save_name=f"fingerprint_xml_{version}"
            )

            if result.get('http_status') == 200:
                logger.success(f"    XML {version}: ACCEPTED (HTTP 200)")
                results['supported_versions']['xml'].append(version)
            elif result.get('http_status') == 400:
                logger.info(f"    XML {version}: REJECTED (HTTP 400)")
            else:
                logger.info(f"    XML {version}: HTTP {result.get('http_status')}")

        # Extract server information from headers
        logger.info("\nAnalyzing server headers...")
        if 'headers' in result:
            headers = result['headers']

            # Check for server identification
            if 'Server' in headers:
                server = headers['Server']
                logger.info(f"  Server: {server}")
                results['server_info']['server'] = server

                # Log as finding if version disclosed
                if any(v in server.lower() for v in ['iis', 'apache', 'nginx']):
                    self.log_finding(
                        'LOW',
                        'Server Version Disclosure',
                        f'Server header reveals: {server}',
                        'Server type and potentially version disclosed in headers'
                    )

            # Check for other identifying headers
            for header in ['X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']:
                if header in headers:
                    value = headers[header]
                    logger.info(f"  {header}: {value}")
                    results['server_info'][header.lower()] = value

                    self.log_finding(
                        'LOW',
                        'Technology Disclosure',
                        f'{header} header reveals: {value}',
                        'Framework/technology information disclosed'
                    )

        # Summary
        logger.info("\n" + "="*60)
        logger.info("Fingerprinting Summary")
        logger.info("="*60)

        sgml_count = len(results['supported_versions']['sgml'])
        xml_count = len(results['supported_versions']['xml'])

        logger.info(f"SGML versions supported: {sgml_count}")
        if sgml_count > 0:
            logger.info(f"  Versions: {', '.join(results['supported_versions']['sgml'])}")

        logger.info(f"XML versions supported: {xml_count}")
        if xml_count > 0:
            logger.info(f"  Versions: {', '.join(results['supported_versions']['xml'])}")

        # Recommendations based on findings
        if sgml_count > 0 and xml_count == 0:
            logger.warning("Server only supports legacy SGML format (OFX 1.x)")
            logger.warning("SGML format may have weaker security controls")
            results['interesting_findings'].append(
                'Server only supports legacy OFX 1.x (SGML) - no modern XML support'
            )

        if '102' in results['supported_versions']['sgml']:
            logger.warning("Server supports OFX 1.0.2 from 1997 - very old!")
            results['interesting_findings'].append(
                'Supports OFX 1.0.2 (from 1997) - likely no MFA support'
            )

        stats = sender.get_stats()
        logger.info(f"\nRequests sent: {stats['requests_sent']}")

        return results
