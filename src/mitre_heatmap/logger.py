"""
Logging module for MITRE ATT&CK Heatmap Generator.
Provides structured logging with context, metrics, and audit trails.
"""

import logging
import sys
import json
from typing import Any, Dict, Optional
from datetime import datetime
from pathlib import Path
from enum import Enum


class LogLevel(str, Enum):
    """Log level enumeration."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class StructuredLogger:
    """
    Structured logger that provides context-aware logging with metrics tracking.
    """
    
    def __init__(
        self,
        name: str,
        level: str = "INFO",
        log_file: Optional[str] = None,
        console_output: bool = True,
        json_format: bool = False,
    ):
        """
        Initialize the structured logger.
        
        Args:
            name: Logger name (typically module name)
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Optional path to log file
            console_output: Whether to output to console
            json_format: Whether to use JSON format for logs
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.logger.handlers = []  # Clear existing handlers
        
        self.json_format = json_format
        self.metrics: Dict[str, Any] = {}
        self.context: Dict[str, Any] = {}
        
        # Setup handlers
        self._setup_handlers(log_file, console_output)
        
    def _setup_handlers(self, log_file: Optional[str], console_output: bool):
        """Setup log handlers for file and console output."""
        
        formatter = self._get_formatter()
        
        # Console handler
        if console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        # File handler
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def _get_formatter(self) -> logging.Formatter:
        """Get the appropriate formatter based on configuration."""
        if self.json_format:
            return JsonFormatter()
        else:
            return ColoredFormatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
    
    def _add_context(self, message: str, extra: Optional[Dict] = None) -> str:
        """Add context information to log message."""
        if not self.context and not extra:
            return message
        
        context_str = ""
        if self.context:
            context_str = f" [Context: {json.dumps(self.context)}]"
        if extra:
            context_str += f" [Extra: {json.dumps(extra)}]"
        
        return f"{message}{context_str}"
    
    def set_context(self, **kwargs):
        """Set context that will be included in all subsequent logs."""
        self.context.update(kwargs)
    
    def clear_context(self):
        """Clear the logging context."""
        self.context.clear()
    
    def debug(self, message: str, extra: Optional[Dict] = None):
        """Log debug message."""
        self.logger.debug(self._add_context(message, extra))
    
    def info(self, message: str, extra: Optional[Dict] = None):
        """Log info message."""
        self.logger.info(self._add_context(message, extra))
    
    def warning(self, message: str, extra: Optional[Dict] = None):
        """Log warning message."""
        self.logger.warning(self._add_context(message, extra))
    
    def error(self, message: str, extra: Optional[Dict] = None, exc_info: bool = False):
        """Log error message."""
        self.logger.error(self._add_context(message, extra), exc_info=exc_info)
    
    def critical(self, message: str, extra: Optional[Dict] = None, exc_info: bool = False):
        """Log critical message."""
        self.logger.critical(self._add_context(message, extra), exc_info=exc_info)
    
    def metric(self, metric_name: str, value: Any):
        """Track a metric."""
        self.metrics[metric_name] = value
        self.debug(f"Metric recorded: {metric_name} = {value}")
    
    def increment_metric(self, metric_name: str, amount: int = 1):
        """Increment a counter metric."""
        self.metrics[metric_name] = self.metrics.get(metric_name, 0) + amount
        self.debug(f"Metric incremented: {metric_name} = {self.metrics[metric_name]}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all recorded metrics."""
        return self.metrics.copy()
    
    def log_function_call(self, func_name: str, args: Dict, result: Optional[Any] = None):
        """Log a function call with arguments and result."""
        self.debug(
            f"Function called: {func_name}",
            extra={"args": args, "result": str(result)[:100] if result else None}
        )
    
    def log_validation_error(self, field: str, value: Any, error: str):
        """Log a validation error."""
        self.error(
            f"Validation failed for field '{field}'",
            extra={"value": str(value), "error": error}
        )
    
    def log_operation_start(self, operation: str, details: Optional[Dict] = None):
        """Log the start of an operation."""
        self.info(f"Starting operation: {operation}", extra=details)
    
    def log_operation_end(self, operation: str, success: bool, details: Optional[Dict] = None):
        """Log the end of an operation."""
        status = "completed successfully" if success else "failed"
        if success:
            self.info(f"Operation {status}: {operation}", extra=details)
        else:
            self.error(f"Operation {status}: {operation}", extra=details)
    
    def log_data_quality(self, source: str, quality_metrics: Dict[str, Any]):
        """Log data quality metrics."""
        self.info(f"Data quality for {source}", extra=quality_metrics)


class ColoredFormatter(logging.Formatter):
    """Formatter that adds colors to console output."""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m',       # Reset
    }
    
    def format(self, record):
        """Format the log record with colors."""
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{log_color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)


class JsonFormatter(logging.Formatter):
    """Formatter that outputs logs as JSON."""
    
    def format(self, record):
        """Format the log record as JSON."""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


# Global logger instance
_logger: Optional[StructuredLogger] = None


def get_logger(
    name: str = "mitre_heatmap",
    level: str = "INFO",
    log_file: Optional[str] = None,
    console_output: bool = True,
) -> StructuredLogger:
    """
    Get or create a logger instance.
    
    Args:
        name: Logger name
        level: Logging level
        log_file: Optional path to log file
        console_output: Whether to output to console
        
    Returns:
        StructuredLogger instance
    """
    global _logger
    
    if _logger is None:
        _logger = StructuredLogger(
            name=name,
            level=level,
            log_file=log_file,
            console_output=console_output,
        )
    
    return _logger


def setup_logging(config):
    """
    Setup logging from configuration.
    
    Args:
        config: LoggingConfig instance
    """
    global _logger
    
    _logger = StructuredLogger(
        name="mitre_heatmap",
        level=config.level,
        log_file=config.file_path,
        console_output=config.console_output,
    )
    
    return _logger
