"""
Logging Framework

Unified logging with console and file output, color support, and session tracking.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from ofxpwn.core.config import Config


class ColorCodes:
    """ANSI color codes for terminal output"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    CYAN = '\033[36m'
    BG_RED = '\033[41m'
    WHITE = '\033[37m'


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support"""

    COLORS = {
        'DEBUG': ColorCodes.CYAN,
        'INFO': ColorCodes.GREEN,
        'WARNING': ColorCodes.YELLOW,
        'ERROR': ColorCodes.RED,
        'CRITICAL': ColorCodes.BG_RED + ColorCodes.WHITE + ColorCodes.BOLD,
    }

    def __init__(self, fmt: str, use_color: bool = True):
        super().__init__(fmt)
        self.use_color = use_color

    def format(self, record):
        if self.use_color and record.levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[record.levelname]}{record.levelname}{ColorCodes.RESET}"
            )
        return super().format(record)


class Logger:
    """Unified logging framework for OFXpwn

    Provides structured logging with console and file output,
    session tracking, and security finding logging.
    """

    def __init__(self, config: Config, verbose: bool = False, session_id: Optional[str] = None):
        """Initialize logger

        Args:
            config: Configuration object
            verbose: Enable verbose output
            session_id: Optional session ID (defaults to timestamp)
        """
        self.config = config
        self.verbose = verbose
        self.session_id = session_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.loggers = {}
        self._setup_loggers()

    def _setup_loggers(self):
        """Setup logger instances"""
        # Ensure output directory exists
        output_dir = self.config.get_output_dir()
        logs_dir = output_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        # Get log level
        level_name = self.config.get_log_level()
        level = getattr(logging, level_name, logging.INFO)

        # Main logger
        self.loggers['main'] = self._create_logger(
            'ofxpwn_main',
            level if not self.verbose else logging.DEBUG,
            logs_dir / f"main_{self.session_id}.log",
            console=True,
            use_color=True
        )

        # Request logger (detailed)
        self.loggers['requests'] = self._create_logger(
            'ofxpwn_requests',
            logging.DEBUG,
            logs_dir / f"requests_{self.session_id}.log",
            console=False,
            use_color=False
        )

        # Response logger (detailed)
        self.loggers['responses'] = self._create_logger(
            'ofxpwn_responses',
            logging.DEBUG,
            logs_dir / f"responses_{self.session_id}.log",
            console=False,
            use_color=False
        )

        # Findings logger
        self.loggers['findings'] = self._create_logger(
            'ofxpwn_findings',
            logging.INFO,
            logs_dir / f"findings_{self.session_id}.log",
            console=True,
            use_color=True
        )

    def _create_logger(
        self,
        name: str,
        level: int,
        log_file: Path,
        console: bool,
        use_color: bool
    ) -> logging.Logger:
        """Create and configure a logger instance"""
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.propagate = False
        logger.handlers.clear()

        # File handler
        file_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setLevel(level)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Console handler
        if console:
            console_formatter = ColoredFormatter(
                '%(levelname)-8s | %(message)s',
                use_color=use_color
            )
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)

        return logger

    # Main logger methods
    def debug(self, message: str):
        """Log debug message"""
        self.loggers['main'].debug(message)

    def info(self, message: str):
        """Log info message"""
        self.loggers['main'].info(message)

    def warning(self, message: str):
        """Log warning message"""
        self.loggers['main'].warning(message)

    def error(self, message: str):
        """Log error message"""
        self.loggers['main'].error(message)

    def critical(self, message: str):
        """Log critical message"""
        self.loggers['main'].critical(message)

    # Request/Response logging
    def log_request(self, method: str, url: str, headers: dict, body: str, truncate: int = 1000):
        """Log HTTP request details"""
        truncated_body = body[:truncate] + "..." if len(body) > truncate else body
        self.loggers['requests'].debug(
            f"\n{'='*80}\nREQUEST: {method} {url}\n"
            f"Headers: {headers}\n"
            f"Body:\n{truncated_body}\n{'='*80}"
        )

    def log_response(self, status_code: int, headers: dict, body: str, elapsed: float, truncate: int = 1000):
        """Log HTTP response details"""
        truncated_body = body[:truncate] + "..." if len(body) > truncate else body
        self.loggers['responses'].debug(
            f"\n{'='*80}\nRESPONSE: HTTP {status_code} ({elapsed:.2f}s)\n"
            f"Headers: {headers}\n"
            f"Body:\n{truncated_body}\n{'='*80}"
        )

    # Finding logging
    def finding(
        self,
        severity: str,
        title: str,
        description: str,
        evidence: Optional[str] = None
    ):
        """Log a security finding

        Args:
            severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
            title: Finding title
            description: Finding description
            evidence: Optional evidence
        """
        severity_upper = severity.upper()
        prefix = {
            'CRITICAL': f'{ColorCodes.BG_RED}{ColorCodes.WHITE}[!]{ColorCodes.RESET}',
            'HIGH': f'{ColorCodes.RED}[!]{ColorCodes.RESET}',
            'MEDIUM': f'{ColorCodes.YELLOW}[*]{ColorCodes.RESET}',
            'LOW': f'{ColorCodes.CYAN}[*]{ColorCodes.RESET}',
            'INFO': f'{ColorCodes.GREEN}[+]{ColorCodes.RESET}',
        }.get(severity_upper, '[*]')

        message = f"{prefix} {severity_upper} | {title}\n    {description}"
        if evidence:
            message += f"\n    Evidence: {evidence}"

        self.loggers['findings'].info(message)

    def success(self, message: str):
        """Log success message"""
        self.info(f"{ColorCodes.GREEN}[+]{ColorCodes.RESET} {message}")

    def get_session_id(self) -> str:
        """Get current session ID"""
        return self.session_id
