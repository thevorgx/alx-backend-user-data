#!/usr/bin/env python3
"""Regex-ing given fields"""
import re


def filter_datum(fields, redaction, message, separator):
    """Obfuscate fields using a ragex pattern(field + separator)"""
    for field in fields:
        ragex_patt = rf'({field}=)[^{separator}]*'
        message = re.sub(ragex_patt, rf'\1{redaction}', message)
    return (message)
