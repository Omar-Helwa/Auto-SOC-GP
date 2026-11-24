"""Parse the supported subset of SPL (a plain Splunk search) into a boolean tree.

Supported
  index= / sourcetype= / source= / earliest= / latest=   -> kept as scope
  field=value, field!=value, quoted values, '*' wildcards
  NOT, AND (also implicit, by space), OR, parentheses, field IN (a, b, c)
  a trailing '| table ...' or '| fields ...' (ignored)
Splunk precedence is respected: NOT binds first, then OR, then AND.

Everything else is refused with an explanation (pipes, eval, rex, regex, stats,
lookup, subsearches, macros, TERM(), CASE(), comparisons, free-text terms...).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .ast import And, Leaf, Not, Or, make_and, make_not, make_or
from .errors import SplError, SplUnsupported

SCOPE_FIELDS = ("index", "sourcetype", "source", "earliest", "latest")
_IGNORED_TAIL = {"table", "fields"}
_KNOWN_COMMANDS = {
    "eval": "eval computes new fields",
    "rex": "rex extracts fields with a regular expression",
    "regex": "regex filters with a regular expression",
    "stats": "stats aggregates events",
    "lookup": "lookup enriches events from a lookup table",
    "where": "where evaluates expressions",
    "search": "a second search stage",
    "join": "join combines searches",
    "append": "append combines searches",
    "transaction": "transaction groups events",
    "tstats": "tstats runs an accelerated aggregate search",
    "sort": "sort reorders results",
    "dedup": "dedup removes duplicates",
    "head": "head limits results",
    "rename": "rename changes field names",
    "bin": "bin buckets values",
    "timechart": "timechart aggregates over time",
    "top": "top aggregates values",
    "rare": "rare aggregates values",
    "inputlookup": "inputlookup reads a lookup table",
}


@dataclass
class SplSearch:
    scope: dict[str, list[str]] = field(default_factory=dict)
    node: object | None = None
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Tokenizer
# --------------------------------------------------------------------------- #
@dataclass
class _Tok:
    kind: str  # LP RP STR WORD EQ NEQ COMMA
    text: str = ""
    quoted: bool = False


_WORD_STOP = set(' \t\r\n(),=<>|[]"`')


def _split_pipes(text: str) -> tuple[str, list[str]]:
    """Return (search part, [pipe segments]); refuse macros / subsearches on the way."""
    segments: list[str] = []
    cur: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                raise SplError("a quoted value is not closed (missing closing quote)", construct="quote")
            cur.append(text[i:j + 1])
            i = j + 1
            continue
        if ch == "`":
            raise SplUnsupported("macros (`name`) are not supported: they hide logic Blue cannot see. "
                                 "Expand the macro in the search first.", construct="macro")
        if ch in "[]":
            raise SplUnsupported("subsearches ([...]) are not supported: Blue only reads a plain search.",
                                 construct="subsearch")
        if ch == "|":
            segments.append("".join(cur))
            cur = []
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            cur.append(text[i:i + 2])
            i += 2
            continue
        cur.append(ch)
        i += 1
    segments.append("".join(cur))
    return segments[0], segments[1:]


def _tokenize(text: str) -> list[_Tok]:
    toks: list[_Tok] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
        elif ch == "(":
            toks.append(_Tok("LP"))
            i += 1
        elif ch == ")":
            toks.append(_Tok("RP"))
            i += 1
        elif ch == ",":
            toks.append(_Tok("COMMA"))
            i += 1
        elif ch == '"':
            j = i + 1
            while text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            toks.append(_Tok("STR", text[i + 1:j], True))
            i = j + 1
        elif ch == "=":
            toks.append(_Tok("EQ"))
            i += 1
        elif ch == "!" and text[i + 1:i + 2] == "=":
            toks.append(_Tok("NEQ"))
            i += 2
        elif ch in "<>":
            raise SplUnsupported("comparison operators (<, >, <=, >=) are not supported: "
                                 "Blue handles equality and wildcard matches only.", construct="comparison")
        else:
            j = i
            while j < n and text[j] not in _WORD_STOP:
                if text[j] == "!" and text[j + 1:j + 2] == "=":
                    break
                j += 2 if text[j] == "\\" and j + 1 < n else 1
            if j == i:  # a stray character such as a lone '!'
                j = i + 1
            toks.append(_Tok("WORD", text[i:j]))
            i = j
    return toks


def _unescape(raw: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt in '\\"':
                out.append(nxt)
                i += 2
                continue
            if nxt == "*":
                raise SplUnsupported("an escaped wildcard (\\*) is not supported: "
                                     "the local matcher cannot tell a literal star from a wildcard.",
                                     construct="escaped_wildcard")
        out.append(ch)
        i += 1
    value = "".join(out)
    if "?" in value:
        raise SplUnsupported("a '?' in a value is not supported (Sigma treats it as a one-character "
                             "wildcard, SPL as a literal).", construct="question_mark")
    return value


# --------------------------------------------------------------------------- #
# Recursive descent
# --------------------------------------------------------------------------- #
class _Parser:
    def __init__(self, toks: list[_Tok]):
        self.t, self.i = toks, 0

    def peek(self) -> _Tok | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self) -> _Tok:
        tok = self.t[self.i]
        self.i += 1
        return tok

    def is_kw(self, word: str) -> bool:
        tok = self.peek()
        return tok is not None and tok.kind == "WORD" and tok.text == word

    def parse(self):
        if not self.t:
            raise SplError("the search is empty: no detection conditions found", construct="empty")
        node = self.and_seq()
        if self.peek() is not None:
            raise SplError("unexpected ')' in the search", construct="syntax")
        return node

    def and_seq(self):
        items = [self.or_expr()]
        while True:
            tok = self.peek()
            if tok is None or tok.kind == "RP":
                break
            if self.is_kw("AND"):
                self.take()
            items.append(self.or_expr())
        return make_and(items)

    def or_expr(self):
        items = [self.not_expr()]
        while self.is_kw("OR"):
            self.take()
            items.append(self.not_expr())
        return make_or(items)

    def not_expr(self):
        if self.is_kw("NOT"):
            self.take()
            return make_not(self.not_expr())
        return self.atom()

    def atom(self):
        tok = self.peek()
        if tok is None:
            raise SplError("the search ends unexpectedly (an operator has no right-hand side)", construct="syntax")
        if tok.kind == "LP":
            self.take()
            node = self.and_seq()
            if self.peek() is None or self.peek().kind != "RP":
                raise SplError("a '(' is never closed", construct="syntax")
            self.take()
            return node
        return self.term()

    def term(self):
        tok = self.take()
        if tok.kind != "WORD":
            raise SplError("expected a field name such as Image=\"...\" in the search", construct="syntax")
        name = tok.text
        nxt = self.peek()
        if nxt is not None and nxt.kind == "LP":
            if name in ("TERM", "CASE"):
                raise SplUnsupported(f"{name}() is not supported: it changes how Splunk tokenises the match.",
                                     construct=f"{name}()")
            raise SplUnsupported(f"the function-like term {name}(...) is not supported.", construct="function")
        is_in = nxt is not None and nxt.kind == "WORD" and nxt.text in ("IN", "in")
        if nxt is None or (nxt.kind not in ("EQ", "NEQ") and not is_in):
            if name in ("and", "or", "not"):
                raise SplError(f"'{name}' must be uppercase ({name.upper()}) in Splunk; lowercase is a search word.",
                               construct="lowercase_operator")
            raise SplUnsupported(f"the free-text term '{name}' is not supported: "
                                 "every condition must be field=value.", construct="free_text")
        if is_in:
            self.take()
            return self.in_list(name)
        kind = self.take().kind
        leaf = Leaf(name, self.value())
        return make_not(leaf) if kind == "NEQ" else leaf

    def value(self) -> str:
        tok = self.peek()
        if tok is None or tok.kind not in ("WORD", "STR"):
            raise SplError("a field is missing its value (nothing after '=')", construct="syntax")
        self.take()
        return _unescape(tok.text)

    def in_list(self, name: str):
        if self.peek() is None or self.peek().kind != "LP":
            raise SplError(f"{name} IN must be followed by a parenthesised list", construct="syntax")
        self.take()
        leaves = []
        while True:
            tok = self.peek()
            if tok is None:
                raise SplError("an IN (...) list is never closed", construct="syntax")
            if tok.kind == "RP":
                self.take()
                break
            if tok.kind == "COMMA":
                self.take()
                continue
            leaves.append(Leaf(name, self.value()))
        if not leaves:
            raise SplError(f"{name} IN () has no values", construct="syntax")
        return make_or(leaves)


# --------------------------------------------------------------------------- #
# Scope extraction
# --------------------------------------------------------------------------- #
def _leaves(node):
    if isinstance(node, Leaf):
        yield node
    elif isinstance(node, (And, Or)):
        for c in node.items:
            yield from _leaves(c)
    elif isinstance(node, Not):
        yield from _leaves(node.item)


def _split_scope(root) -> tuple[dict[str, list[str]], object]:
    top = list(root.items) if isinstance(root, And) else [root]
    scope: dict[str, list[str]] = {}
    rest = []
    for child in top:
        group = [child] if isinstance(child, Leaf) else (list(child.items) if isinstance(child, Or) else [])
        if group and all(isinstance(g, Leaf) and g.field in SCOPE_FIELDS and g.field == group[0].field
                         for g in group):
            scope.setdefault(group[0].field, []).extend(g.pattern for g in group)
        else:
            rest.append(child)
    for child in rest:
        for leaf in _leaves(child):
            if leaf.field in SCOPE_FIELDS:
                raise SplUnsupported(
                    f"'{leaf.field}=' is only supported as a plain top-level term (for example "
                    f"index=winlogs), not inside OR / NOT / != logic.", construct="scope_in_logic")
    if not rest:
        raise SplError("the search has scoping terms only (index/sourcetype/source): "
                       "no detection conditions found", construct="empty")
    return scope, make_and(rest)


def parse_spl(text: str) -> SplSearch:
    if not isinstance(text, str) or not text.strip():
        raise SplError("the search is empty", construct="empty")
    body, tails = _split_pipes(text.strip())
    notes: list[str] = []
    for seg in tails:
        words = seg.strip().split(None, 1)
        cmd = words[0].lower() if words else ""
        if cmd in _IGNORED_TAIL:
            notes.append(f"ignored trailing '| {seg.strip()}' (it only shapes the output)")
            continue
        if not cmd:
            raise SplError("an empty pipe segment ('| |' or a trailing '|')", construct="syntax")
        why = _KNOWN_COMMANDS.get(cmd, f"the command '{cmd}' changes the results")
        raise SplUnsupported(
            f"the pipe command '{cmd}' is not supported ({why}). Blue only reads a plain search; "
            "only a trailing '| table ...' or '| fields ...' is accepted (and ignored).",
            construct=f"| {cmd}")
    body = re.sub(r"^\s*search\s+", "", body, flags=re.IGNORECASE)
    first = body.split(None, 1)[0].lower() if body.strip() else ""
    if first in ("eval", "rex", "regex", "stats", "lookup", "where") and not re.match(r"\s*\w+\s*[=!]", body):
        raise SplUnsupported(f"'{first}' is a search command, not a plain search: not supported.", construct=first)
    root = _Parser(_tokenize(body)).parse()
    scope, node = _split_scope(root)
    return SplSearch(scope=scope, node=node, notes=notes)
