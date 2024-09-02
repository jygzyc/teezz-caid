from concurrent_log_handler import ConcurrentRotatingFileHandler
from logging.config import fileConfig
import logging

def init_ini_log(config_file) -> None:
    fileConfig(config_file)

def get_logger(logger_name) -> logging.Logger:
    logger = logging.getLogger(logger_name)
    return logger