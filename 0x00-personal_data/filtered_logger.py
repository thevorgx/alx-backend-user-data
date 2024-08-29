#!/usr/bin/env python3
"""Regex-ing given fields"""
import os
import mysql.connector
import logging
import re
from typing import List


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """Obfuscate fields using a ragex pattern(field + separator)"""
    for field in fields:
        ragex_patt = rf'({field}=)[^{separator}]*'
        message = re.sub(ragex_patt, rf'\1{redaction}', message)
    return (message)


def get_logger() -> logging.Logger:
    """Create and configure a logger for user data"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()

    handler.setFormatter(RedactingFormatter(PII_FIELDS))

    logger.addHandler(handler)
    return (logger)


def get_db() -> mysql.connector.connection.MySQLConnection:
    """place holder for now"""
    username = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    password = os.getenv('PERSONAL_DATA_DB_PASSWORD', 'localhost')
    host = os.getenv('PERSONAL_DATA_DB_HOST', '')
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')
    db_connect = mysql.connector.connect(host=host, user=username,
                                         password=password, database=db_name)
    return(db_connect)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Redacts sensitive info and formats the log record for output"""
        original_message = record.getMessage()
        redacted_message = filter_datum(self.fields, self.REDACTION,
                                        original_message, self.SEPARATOR)
        record.msg = redacted_message
        return super().format(record)
