"""
Centralized logging configuration for VoidSeeker

Provides structured logging to both console and files with proper formatting
and log rotation to keep the logs directory manageable.
"""
import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path


def setup_logging(name: str = "voidseeker", log_dir: str = "logs") -> logging.Logger:
    """
    Configure logging for VoidSeeker with file and console handlers
    
    Args:
        name: Logger name (typically __name__ from calling module)
        log_dir: Directory to store log files
    
    Returns:
        Configured logger instance
    """
    # Create logs directory if it doesn't exist
    Path(log_dir).mkdir(exist_ok=True)
    
    # Get or create root logger for voidseeker
    root_logger = logging.getLogger("voidseeker")
    
    # Only configure if not already configured (prevent duplicate handlers)
    if root_logger.handlers:
        return root_logger
    
    root_logger.setLevel(logging.DEBUG)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create file handler with rotation (max 5MB per file, keep 5 backups)
    log_file = os.path.join(log_dir, f"voidseeker_{datetime.now().strftime('%Y%m%d')}.log")
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,  # 5MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    
    # Create console handler (disabled - logging only to file)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.CRITICAL + 1)  # Set to a level higher than CRITICAL to effectively disable it
    console_handler.setFormatter(detailed_formatter)
    
    # Add handlers to root logger
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a module (returns logger under voidseeker hierarchy)
    
    Args:
        name: Logger name (typically __name__)
    
    Returns:
        Logger instance under voidseeker hierarchy
    """
    # Ensure name is part of voidseeker hierarchy
    if not name.startswith("voidseeker"):
        if name == "__main__":
            name = "voidseeker.main"
        else:
            name = f"voidseeker.{name}"
    
    return logging.getLogger(name)
