"""Interpretation of INI values the way PHP's own parsers read them."""

from __future__ import annotations

import re
from typing import Optional

_TRUE_WORDS = {"on", "yes", "true"}
_LEADING_INT = re.compile(r"\s*([+-]?\d+)")
_QUANTITY = re.compile(
    r"^\s*([+-]?)(0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+|\d+)\s*([kKmMgG]?)\s*$"
)
_MULTIPLIERS = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}

ERROR_CONSTANTS = {
    "E_ERROR": 1,
    "E_WARNING": 2,
    "E_PARSE": 4,
    "E_NOTICE": 8,
    "E_CORE_ERROR": 16,
    "E_CORE_WARNING": 32,
    "E_COMPILE_ERROR": 64,
    "E_COMPILE_WARNING": 128,
    "E_USER_ERROR": 256,
    "E_USER_WARNING": 512,
    "E_USER_NOTICE": 1024,
    "E_STRICT": 2048,
    "E_RECOVERABLE_ERROR": 4096,
    "E_DEPRECATED": 8192,
    "E_USER_DEPRECATED": 16384,
    "E_ALL": 32767,
}


def atoi(text: Optional[str]) -> int:
    """C atoi(): leading integer, 0 when there is none."""
    match = _LEADING_INT.match(text or "")
    return int(match.group(1)) if match else 0


def to_bool(value: Optional[str]) -> bool:
    """zend_ini_parse_bool()."""
    if value is None:
        return False
    text = value.strip().lower()
    if text in _TRUE_WORDS:
        return True
    return atoi(text) != 0


def to_bytes(value: Optional[str]) -> Optional[int]:
    """zend_ini_parse_quantity(); None when the value is not a valid quantity."""
    if value is None:
        return None
    match = _QUANTITY.match(value)
    if not match:
        return None
    sign, digits, suffix = match.groups()
    prefix = digits[:2].lower()
    base = {"0x": 16, "0o": 8, "0b": 2}.get(prefix, 10)
    number = int(digits[2:] if base != 10 else digits, base)
    number *= _MULTIPLIERS[suffix.lower()]
    return -number if sign == "-" else number


def split_list(value: Optional[str]) -> list:
    """Comma/whitespace separated lists such as disable_functions."""
    if not value:
        return []
    return [item for item in re.split(r"[,\s]+", value) if item]


def parse_octal(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    text = value.strip()
    if not re.fullmatch(r"0?[0-7]{3,4}", text):
        return None
    return int(text, 8)


_TOKEN = re.compile(r"\s*(?:(\d+)|([A-Za-z_][A-Za-z0-9_]*)|(\S))")


def eval_error_reporting(expression: Optional[str]) -> Optional[int]:
    """Evaluate an error_reporting expression without eval().

    The INI grammar gives |, & and ^ equal precedence with left associativity.
    """
    if expression is None:
        return None
    tokens = []
    for number, name, op in _TOKEN.findall(expression):
        if number:
            tokens.append(("num", int(number)))
        elif name:
            if name not in ERROR_CONSTANTS:
                return None
            tokens.append(("num", ERROR_CONSTANTS[name]))
        elif op:
            tokens.append(("op", op))
    if not tokens:
        return None
    position = 0

    def peek():
        return tokens[position] if position < len(tokens) else (None, None)

    def unary() -> int:
        nonlocal position
        kind, token = peek()
        if kind == "op" and token in "~!":
            position += 1
            operand = unary()
            return ~operand if token == "~" else int(not operand)
        if kind == "op" and token == "(":
            position += 1
            result = binary()
            if peek() != ("op", ")"):
                raise ValueError("unbalanced parentheses")
            position += 1
            return result
        if kind == "num":
            position += 1
            return token
        raise ValueError("unexpected token")

    def binary() -> int:
        nonlocal position
        result = unary()
        while True:
            kind, token = peek()
            if kind != "op" or token not in "|&^":
                return result
            position += 1
            right = unary()
            if token == "|":
                result |= right
            elif token == "&":
                result &= right
            else:
                result ^= right

    try:
        value = binary()
    except ValueError:
        return None
    if position != len(tokens):
        return None
    return value
