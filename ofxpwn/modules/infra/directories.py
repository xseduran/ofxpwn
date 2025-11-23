"""
Directory Enumeration Module

Tests for common directories and files that may exist alongside OFX server.
"""

from typing import Dict, Any
import time

from ofxpwn.core.base_module import BaseModule
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.sender import OFXSender


class DirectoriesModule(BaseModule):
    """Directory and file enumeration"""

    @classmethod
    def get_description(cls) -> str:
        return "Enumerate common directories and files"

    def run(self, config: Config, logger: Logger) -> Dict[str, Any]:
        """Run directory enumeration"""
        self.config = config
        self.logger = logger

        logger.info("="*60)
        logger.info("Directory Enumeration")
        logger.info("="*60)
        logger.warning("Testing for common paths and files...")

        sender = OFXSender(config, logger)
        target_url = config.get_target_url()
        base_url = target_url.rsplit('/', 1)[0] if '/' in target_url else target_url

        results = {
            'total_tested': 0,
            'found': [],
            'interesting': []
        }

        # Common paths to test
        test_paths = [
            # Admin interfaces
            '/admin',
            '/admin.html',
            '/admin.php',
            '/administrator',
            '/manager',
            '/console',

            # Documentation
            '/docs',
            '/documentation',
            '/help',
            '/api',
            '/api-docs',
            '/swagger',
            '/openapi.json',

            # Configuration files
            '/web.config',
            '/Web.config',
            '/.env',
            '/config.xml',
            '/settings.xml',

            # Common files
            '/robots.txt',
            '/sitemap.xml',
            '/.git/config',
            '/.svn/entries',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml',

            # Backup files
            '/backup',
            '/backup.zip',
            '/backup.tar.gz',
            '/db.sql',
            '/database.sql',

            # Server files
            '/server-status',
            '/server-info',
            '/phpinfo.php',
            '/info.php',
            '/test.php',

            # OFX specific
            '/OFXServer',
            '/ofx',
            '/ofxserver',
            '/OFXServer/help',
            '/OFXServer/test',
            '/OFXServer/admin',

            # Common web dirs
            '/images',
            '/css',
            '/js',
            '/scripts',
            '/uploads',
            '/files',
            '/download',
            '/downloads',
        ]

        logger.info(f"\nTesting {len(test_paths)} common paths...")
        logger.info("-" * 60)

        for path in test_paths:
            test_url = f"{base_url}{path}"

            try:
                import requests

                proxies = {}
                verify_ssl = True

                if config.get('proxy.enabled'):
                    proxy_url = config.get('proxy.url')
                    proxies = {
                        'http': proxy_url,
                        'https': proxy_url
                    }
                    verify_ssl = config.get('proxy.verify_ssl', False)

                response = requests.get(
                    test_url,
                    proxies=proxies,
                    verify=verify_ssl,
                    timeout=10,
                    allow_redirects=False
                )

                results['total_tested'] += 1
                status = response.status_code

                # Check for found resources
                if status == 200:
                    size = len(response.content)
                    logger.success(f"✓ {path} [200] ({size} bytes)")

                    results['found'].append({
                        'path': path,
                        'status': status,
                        'size': size
                    })

                    # Check for interesting content
                    content_lower = response.text.lower()

                    if any(x in content_lower for x in ['password', 'username', 'credentials', 'api key', 'secret']):
                        logger.finding(
                            'HIGH',
                            'Sensitive Information in Accessible File',
                            f'Found potentially sensitive content at {path}',
                            'Review file contents and restrict access'
                        )
                        results['interesting'].append({
                            'path': path,
                            'reason': 'Contains sensitive keywords'
                        })

                    if 'index of' in content_lower or '<dir>' in content_lower:
                        logger.finding(
                            'MEDIUM',
                            'Directory Listing Enabled',
                            f'Directory listing at {path}',
                            'Disable directory listings'
                        )
                        results['interesting'].append({
                            'path': path,
                            'reason': 'Directory listing enabled'
                        })

                    # Check for backup files
                    if path.endswith(('.zip', '.tar.gz', '.sql', '.bak')):
                        logger.finding(
                            'CRITICAL',
                            'Backup File Accessible',
                            f'Backup file accessible at {path} ({size} bytes)',
                            'Remove backup files from web-accessible locations'
                        )
                        results['interesting'].append({
                            'path': path,
                            'reason': 'Backup file accessible'
                        })

                    # Check for config files
                    if any(x in path.lower() for x in ['config', 'web.config', '.env', 'settings']):
                        logger.finding(
                            'CRITICAL',
                            'Configuration File Accessible',
                            f'Configuration file at {path}',
                            'Restrict access to configuration files'
                        )
                        results['interesting'].append({
                            'path': path,
                            'reason': 'Configuration file accessible'
                        })

                elif status == 401:
                    logger.info(f"  {path} [401 - Auth Required]")
                    results['found'].append({
                        'path': path,
                        'status': status,
                        'note': 'Authentication required'
                    })

                elif status == 403:
                    logger.info(f"  {path} [403 - Forbidden]")
                    results['found'].append({
                        'path': path,
                        'status': status,
                        'note': 'Exists but forbidden'
                    })

                elif status in [301, 302, 307, 308]:
                    location = response.headers.get('Location', '')
                    logger.info(f"  {path} [{status} -> {location}]")
                    results['found'].append({
                        'path': path,
                        'status': status,
                        'redirect': location
                    })

                time.sleep(0.2)  # Rate limiting

            except requests.exceptions.Timeout:
                logger.warning(f"  {path} [TIMEOUT]")
            except requests.exceptions.RequestException as e:
                logger.debug(f"  {path} [ERROR: {e}]")
            except Exception as e:
                logger.debug(f"  {path} [ERROR: {e}]")

        # Summary
        logger.info("\n" + "="*60)
        logger.info("Directory Enumeration Summary")
        logger.info("="*60)
        logger.info(f"Paths tested: {results['total_tested']}")
        logger.info(f"Resources found: {len(results['found'])}")
        logger.info(f"Interesting findings: {len(results['interesting'])}")

        if results['found']:
            logger.info(f"\nAccessible resources:")
            for item in results['found'][:10]:  # Show first 10
                logger.info(f"  {item['path']} [{item['status']}]")

            if len(results['found']) > 10:
                logger.info(f"  ... and {len(results['found']) - 10} more")

        if results['interesting']:
            logger.warning(f"\nInteresting findings requiring review!")
        else:
            logger.success("No sensitive files or directories exposed")

        return results
