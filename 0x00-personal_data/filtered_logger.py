#!/usr/bin/env python3
"""Regex-ing given fields"""
import re
from typing import List


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """Obfuscate fields using a ragex pattern(field + separator)"""
    for field in fields:
        ragex_patt = rf'({field}=)[^{separator}]*'
        message = re.sub(ragex_patt, rf'\1{redaction}', message)
    return (message)
