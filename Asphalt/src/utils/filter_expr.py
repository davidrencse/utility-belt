"""Minimal filter expression parser/evaluator."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple


Token = Tuple[str, str]


def _tokenize(expr: str) -> List[Token]:
    tokens: List[Token] = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "()":
            tokens.append((ch, ch))
            i += 1
            continue
        if expr[i:i+2] in (">=", "<=", "!="):
            tokens.append(("OP", expr[i:i+2]))
            i += 2
            continue
        if ch in "=<>~":
            tokens.append(("OP", ch))
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            i += 1
            start = i
            while i < len(expr) and expr[i] != quote:
                i += 1
            tokens.append(("STRING", expr[start:i]))
            i += 1
            continue
        if ch.isdigit() or (ch == "." and i + 1 < len(expr) and expr[i+1].isdigit()):
            start = i
            i += 1
            while i < len(expr) and (expr[i].isdigit() or expr[i] == "."):
                i += 1
            tokens.append(("NUMBER", expr[start:i]))
            continue
        # identifiers/operators
        start = i
        i += 1
        while i < len(expr) and (expr[i].isalnum() or expr[i] in "_:."):
            i += 1
        ident = expr[start:i]
        low = ident.lower()
        if low in ("and", "or", "not"):
            tokens.append((low.upper(), low))
        else:
            tokens.append(("IDENT", ident))
    tokens.append(("EOF", ""))
    return tokens


def _coerce_value(val: str) -> Any:
    try:
        if "." in val:
            return float(val)
        return int(val)
    except Exception:
        return val


def _normalize(val: Any) -> Any:
    if isinstance(val, str):
        return val.lower()
    return val


def _field_value(record: Dict[str, Any], field: str) -> Any:
    return record.get(field)


def _compare(op: str, left: Any, right: Any) -> bool:
    if left is None:
        return False
    if isinstance(left, list):
        left_norm = [_normalize(x) for x in left]
    else:
        left_norm = _normalize(left)
    right_norm = _normalize(right)

    if op == "~":
        if isinstance(left_norm, list):
            return any(right_norm in str(x).lower() for x in left_norm)
        return right_norm in str(left_norm).lower()
    if op == "=":
        if isinstance(left_norm, list):
            return right_norm in left_norm
        return left_norm == right_norm
    if op == "!=":
        if isinstance(left_norm, list):
            return right_norm not in left_norm
        return left_norm != right_norm
    try:
        l = float(left_norm)
        r = float(right_norm)
    except Exception:
        return False
    if op == ">":
        return l > r
    if op == ">=":
        return l >= r
    if op == "<":
        return l < r
    if op == "<=":
        return l <= r
    return False


class _Parser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> Token:
        return self.tokens[self.pos]

    def _eat(self, kind: str) -> Token:
        tok = self._peek()
        if tok[0] != kind:
            raise ValueError(f"Expected {kind}, got {tok[0]}")
        self.pos += 1
        return tok

    def parse(self):
        return self._parse_or()

    def _parse_or(self):
        node = self._parse_and()
        while self._peek()[0] == "OR":
            self._eat("OR")
            right = self._parse_and()
            node = ("OR", node, right)
        return node

    def _parse_and(self):
        node = self._parse_not()
        while self._peek()[0] == "AND":
            self._eat("AND")
            right = self._parse_not()
            node = ("AND", node, right)
        return node

    def _parse_not(self):
        if self._peek()[0] == "NOT":
            self._eat("NOT")
            node = self._parse_not()
            return ("NOT", node)
        return self._parse_term()

    def _parse_term(self):
        kind, value = self._peek()
        if kind == "(":
            self._eat("(")
            node = self._parse_or()
            self._eat(")")
            return node
        return self._parse_comparison()

    def _parse_comparison(self):
        field = self._eat("IDENT")[1]
        op = self._eat("OP")[1]
        kind, val = self._peek()
        if kind == "STRING":
            self._eat("STRING")
            rhs = val
        elif kind == "NUMBER":
            self._eat("NUMBER")
            rhs = _coerce_value(val)
        elif kind == "IDENT":
            self._eat("IDENT")
            rhs = val
        else:
            raise ValueError("Expected comparison value")
        return ("CMP", field, op, rhs)


def _eval_ast(node, record: Dict[str, Any]) -> bool:
    if node is None:
        return True
    kind = node[0]
    if kind == "CMP":
        _, field, op, rhs = node
        left_val = _field_value(record, field)
        return _compare(op, left_val, rhs)
    if kind == "NOT":
        return not _eval_ast(node[1], record)
    if kind == "AND":
        return _eval_ast(node[1], record) and _eval_ast(node[2], record)
    if kind == "OR":
        return _eval_ast(node[1], record) or _eval_ast(node[2], record)
    return False


def build_predicate(expr: str, value_normalizers: Dict[str, Callable[[Any], Any]] | None = None) -> Callable[[Dict[str, Any]], bool]:
    if not expr:
        return lambda _r: True
    tokens = _tokenize(expr)
    parser = _Parser(tokens)
    ast = parser.parse()
    normalizers = value_normalizers or {}

    def _eval(record: Dict[str, Any]) -> bool:
        def _eval_node(node):
            if node is None:
                return True
            kind = node[0]
            if kind == "CMP":
                _, field, op, rhs = node
                if field in normalizers:
                    rhs = normalizers[field](rhs)
                left_val = _field_value(record, field)
                return _compare(op, left_val, rhs)
            if kind == "NOT":
                return not _eval_node(node[1])
            if kind == "AND":
                return _eval_node(node[1]) and _eval_node(node[2])
            if kind == "OR":
                return _eval_node(node[1]) or _eval_node(node[2])
            return False
        return _eval_node(ast)

    return _eval
