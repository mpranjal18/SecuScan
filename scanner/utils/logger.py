import logging
import sys
from datetime import datetime

def setup_logging():
    # Create logger
    logger = logging.getLogger('SecurityScanner')
    logger.setLevel(logging.INFO)
    
    # Create handlers
    console_handler = logging.StreamHandler(sys.stdout)
    file_handler = logging.FileHandler(
        f'scan_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    )
    
    # Create formatters
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger 