"""
SSL/TLS Security Assessment Module

Tests SSL/TLS configuration and certificate security.
"""

from typing import Dict, Any
import ssl
import socket
from urllib.parse import urlparse

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger


class SSLModule(BaseModule):
    """SSL/TLS security assessment"""

    @classmethod
    def get_description(cls) -> str:
        return "Assess SSL/TLS configuration and certificate security"

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run SSL/TLS assessment"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("SSL/TLS Security Assessment")
        logger.info("="*60)

        target_url = config.get_target_url()
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port or 443

        if parsed.scheme != 'https':
            logger.warning(f"Target uses {parsed.scheme}, not HTTPS")
            logger.warning("SSL/TLS assessment skipped")
            return {'skipped': True, 'reason': 'Not HTTPS'}

        results = {
            'hostname': hostname,
            'port': port,
            'protocols': {},
            'certificate': {},
            'issues': []
        }

        logger.info(f"\nTarget: {hostname}:{port}")

        # Test SSL/TLS protocol versions
        logger.info("\nTesting SSL/TLS Protocol Versions:")
        logger.info("-" * 60)

        protocols_to_test = [
            ('SSLv2', ssl.PROTOCOL_SSLv23, 'CRITICAL'),
            ('SSLv3', ssl.PROTOCOL_SSLv23, 'CRITICAL'),
            ('TLSv1.0', ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None, 'HIGH'),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None, 'MEDIUM'),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None, 'INFO'),
            ('TLSv1.3', ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None, 'INFO'),
        ]

        for protocol_name, protocol_const, severity in protocols_to_test:
            if protocol_const is None:
                continue

            try:
                context = ssl.SSLContext(protocol_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                # Try SSLv2/SSLv3 specific detection
                if protocol_name in ['SSLv2', 'SSLv3']:
                    if hasattr(ssl, 'OP_NO_SSLv2'):
                        context.options &= ~ssl.OP_NO_SSLv2
                    if hasattr(ssl, 'OP_NO_SSLv3'):
                        context.options &= ~ssl.OP_NO_SSLv3

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
                ssl_sock.connect((hostname, port))

                logger.warning(f"✗ {protocol_name}: ENABLED")
                results['protocols'][protocol_name] = True

                if severity in ['CRITICAL', 'HIGH']:
                    self.log_finding(
                        severity,
                        f'Weak SSL/TLS Protocol: {protocol_name}',
                        f'{protocol_name} is enabled and considered insecure',
                        f'Disable {protocol_name} and use TLS 1.2 or higher'
                    )
                    results['issues'].append({
                        'type': 'weak_protocol',
                        'protocol': protocol_name,
                        'severity': severity
                    })

                ssl_sock.close()

            except (ssl.SSLError, socket.error, OSError) as e:
                logger.success(f"✓ {protocol_name}: DISABLED")
                results['protocols'][protocol_name] = False

        # Get certificate information
        logger.info("\nCertificate Information:")
        logger.info("-" * 60)

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
            ssl_sock.connect((hostname, port))

            cert = ssl_sock.getpeercert()

            if cert:
                # Subject
                subject = dict(x[0] for x in cert.get('subject', ()))
                logger.info(f"Subject: {subject.get('commonName', 'N/A')}")
                results['certificate']['subject'] = subject.get('commonName')

                # Issuer
                issuer = dict(x[0] for x in cert.get('issuer', ()))
                logger.info(f"Issuer: {issuer.get('commonName', 'N/A')}")
                results['certificate']['issuer'] = issuer.get('commonName')

                # Validity
                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')
                logger.info(f"Valid From: {not_before}")
                logger.info(f"Valid Until: {not_after}")
                results['certificate']['not_before'] = not_before
                results['certificate']['not_after'] = not_after

                # Subject Alternative Names
                san = cert.get('subjectAltName', ())
                if san:
                    san_list = [x[1] for x in san]
                    logger.info(f"Subject Alt Names: {', '.join(san_list)}")
                    results['certificate']['san'] = san_list

                    # Check if hostname matches SAN
                    if hostname not in san_list and f"*.{'.'.join(hostname.split('.')[1:])}" not in san_list:
                        logger.warning(f"Hostname {hostname} not in certificate SAN")
                        self.log_finding(
                            'MEDIUM',
                            'Certificate Hostname Mismatch',
                            f'Hostname {hostname} does not match certificate SAN',
                            'Ensure certificate covers the hostname'
                        )
                        results['issues'].append({
                            'type': 'hostname_mismatch',
                            'hostname': hostname,
                            'san': san_list
                        })

                # Check for self-signed certificate
                if subject.get('commonName') == issuer.get('commonName'):
                    logger.warning("Self-signed certificate detected")
                    self.log_finding(
                        'LOW',
                        'Self-Signed Certificate',
                        'Server uses self-signed certificate',
                        'Use certificate from trusted CA in production'
                    )
                    results['issues'].append({'type': 'self_signed'})

            ssl_sock.close()

        except Exception as e:
            logger.warning(f"Could not retrieve certificate: {e}")
            results['certificate']['error'] = str(e)

        # Test cipher suites
        logger.info("\nCipher Suite Analysis:")
        logger.info("-" * 60)

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
            ssl_sock.connect((hostname, port))

            cipher = ssl_sock.cipher()
            if cipher:
                logger.info(f"Negotiated Cipher: {cipher[0]}")
                logger.info(f"Protocol Version: {cipher[1]}")
                logger.info(f"Encryption Strength: {cipher[2]} bits")

                results['cipher'] = {
                    'name': cipher[0],
                    'version': cipher[1],
                    'bits': cipher[2]
                }

                # Check for weak ciphers
                cipher_name = cipher[0].upper()
                weak_indicators = ['NULL', 'ANON', 'EXPORT', 'DES', 'MD5', 'RC4']

                for indicator in weak_indicators:
                    if indicator in cipher_name:
                        logger.warning(f"Weak cipher detected: {cipher_name}")
                        self.log_finding(
                            'HIGH',
                            'Weak Cipher Suite',
                            f'Weak cipher in use: {cipher_name}',
                            'Disable weak ciphers and use strong modern ciphers'
                        )
                        results['issues'].append({
                            'type': 'weak_cipher',
                            'cipher': cipher_name
                        })
                        break

            ssl_sock.close()

        except Exception as e:
            logger.warning(f"Could not test ciphers: {e}")

        # Summary
        logger.info("\n" + "="*60)
        logger.info("SSL/TLS Assessment Summary")
        logger.info("="*60)
        logger.info(f"Issues found: {len(results['issues'])}")

        if results['issues']:
            logger.warning("SSL/TLS configuration issues detected")
            critical = len([i for i in results['issues'] if i.get('severity') == 'CRITICAL'])
            high = len([i for i in results['issues'] if i.get('severity') == 'HIGH'])
            if critical:
                logger.warning(f"  Critical issues: {critical}")
            if high:
                logger.warning(f"  High issues: {high}")
        else:
            logger.success("No major SSL/TLS issues detected")

        return results
