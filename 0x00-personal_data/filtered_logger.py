#!/usr/bin/env python3
"""
filtered logger module
"""

import logging
import mysql.connector
import os
import re
from typing import List


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """
    The goal is to take a log message and hide or
    obscure certain sensitive information within it.
    """
    for field in fields:
        message = re.sub(f"{field}=.*?{separator}",
                         f"{field}={redaction}{separator}", message)
    return message


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        an init method
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        filter the values in log records using
        filter_datum implemented above
        """
        msg = super(RedactingFormatter, self).format(record)
        return filter_datum(self.fields, self.REDACTION, msg,
                            self.SEPARATOR)


def get_logger() -> logging.Logger:
    """
    function that takes no arguments and returns a
    logging.Logger object.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    str_handler = logging.StreamHandler()
    formatter = RedactingFormatter(list(PII_FIELDS))
    str_handler.setFormatter(formatter)
    logger.addHandler(str_handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Returns a connector to the database
    """
    username = os.environ.get("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.environ.get("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.environ.get("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.environ.get("PERSONAL_DATA_DB_NAME")

    return mysql.connector.connect(user=username,
                                   password=password,
                                   host=host,
                                   database=db_name)

def main():
    """
    obtain a database connection using get_db and retrieve all rows
    in the users table and display each row under a filtered format
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    fields = cursor.column_names
    logger = get_logger()
    for row in cursor:
        msg = "".join(f"{f}={str(r)}; "for f, r in zip(fields, row))
        logger.info(msg.strip())
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()