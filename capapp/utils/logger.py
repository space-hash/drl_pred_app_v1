# capapp/utils/logger.py
import logging
import sys
from logging.handlers import RotatingFileHandler
from datetime import datetime
from capapp.config.settings import config

def setup_logger():
    """
    Configures and returns a centralized logger for the entire application.
    """
    logger = logging.getLogger("DDoSPipeline")
    if logger.hasHandlers():
        return logger # Avoid re-configuring if already set up

    logger.setLevel(logging.INFO)
    log_format = logging.Formatter('%(asctime)s - %(threadName)s - %(levelname)s - %(message)s')

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_format)
    logger.addHandler(console_handler)

    # File Handler
    log_file = config.LOG_DIR / f"pipeline_{datetime.now().strftime('%Y%m%d')}.log"
    try:
        file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5, errors='replace')
    except TypeError:
        # Fallback for older Python versions
        file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    file_handler.setFormatter(log_format)
    logger.addHandler(file_handler)

    return logger

logger = setup_logger()
