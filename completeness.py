"""Completeness gate: an artifact is accepted only if it ends at a statement
boundary, defines the symbol that was asked for, and was not cut off by a
token cap.

Why compiling is not enough: a generation cut at the cap ends mid-statement
(measured: a toposort file ending at ``for dep``). Depending on the cut point it
either raises SyntaxError — which the pipeline already caught — or lands on a
statement boundary that still parses, in which case ``py_compile`` passes and
the old pipeline reported success on a function that cannot work.

Truncation is a property of the REQUEST as well as the text, so both are
recorded: ``finish_reason`` ("length" is decisive) and the completion/budget
ratio when the backend reports usage.

    from completeness import check
    v = check(code, symbol="toposort", finish_reason="length")
    v["complete"]     # False
    v["reasons"]      # ["finish_reason=length"]

False-positive control: a correct artifact must pass, including one whose last
statement is ``return x``, a closing bracket, ``pass``, or a docstring.
"""
import ast
import io
import re
import token as T
import tokenize

# A statement cannot END with these.
DANGLING_KEYWORDS = {
    "for", "in", "if", "elif", "else", "while", "def", "class", "with", "as",
    "try", "except", "finally", "lambda", "yield", "await", "raise", "del",
    "assert", "global", "nonlocal", "not", "and", "or", "is", "import", "from",
    "continue", "break",
}
DANGLING_OPS = {
    "(", "[", "{", ",", ":", "+", "-", "*", "/", "//", "%", "**", "=", "==",
    "!=", "<", ">", "<=", ">=", "&", "|", "^", "~", "<<", ">>", "->", "+=",
    "-=", "*=", "/=", ".", "@", "\\",
}
_SKIP = {T.NEWLINE, T.NL, T.INDENT, T.DEDENT, T.ENDMARKER, T.COMMENT}


def last_statement(code, limit=120):
    """Last non-empty source line, redacted down to a short single line."""
    for line in reversed((code or "").splitlines()):
        s = line.strip()
        if s:
            return s[:limit]
    return ""


def _last_token(code):
    """Last meaningful token of the source, or None if it cannot be tokenised."""
    try:
        toks = [t for t in tokenize.generate_tokens(io.StringIO(code).readline)
                if t.type not in _SKIP]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None
    return toks[-1] if toks else None


_COMPOUND = re.compile(r"^(for|if|while|with|def|class|elif|else|try|except|finally)\b(.*)$")


def ends_at_boundary(code):
    """(bool, reason). Structural check, independent of finish_reason."""
    src = (code or "").rstrip()
    if not src:
        return False, "empty source"
    if src.endswith("\\"):
        return False, "ends with a line continuation"
    last = _last_token(src)
    if last is None:
        return False, "source does not tokenise (cut inside a string or bracket)"
    kind, text = last.type, last.string
    if kind == T.NAME and text in DANGLING_KEYWORDS:
        return False, f"ends on dangling keyword {text!r}"
    if kind == T.OP and text in DANGLING_OPS:
        return False, f"ends on dangling operator {text!r}"
    # Lexical tokenisation alone cannot see `for dep`: the last token is the
    # NAME dep, which looks like a complete expression. Check the head of the
    # final logical line instead — a compound header with no colon has no body
    # and cannot be a statement boundary.
    last_line = next((l.strip() for l in reversed(src.splitlines()) if l.strip()), "")
    if last_line and not last_line.startswith("#"):
        m = _COMPOUND.match(last_line)
        if m and ":" not in m.group(2):
            return False, f"ends on compound header {m.group(1)!r} with no body"
    return True, "ok"


_SYMBOL_DEF = r"^\s*(?:async\s+)?(?:def|class)\s+{sym}\b"
_SYMBOL_ASSIGN = r"^[ \t]*{sym}\s*(?::[^=\n]+)?=(?!=)"


def symbol_present(code, symbol):
    """True if a module-level def/class/assignment with this name exists."""
    if not symbol:
        return None
    s = re.escape(symbol)
    src = code or ""
    if re.search(_SYMBOL_DEF.format(sym=s), src, re.M):
        return True
    return bool(re.search(_SYMBOL_ASSIGN.format(sym=s), src, re.M))


def check(code, symbol=None, finish_reason=None, completion_tokens=None,
          budget_tokens=None, cap_ratio=0.98):
    """Return the verdict dict. ``complete`` False means: do not accept.

    ``completion_tokens``/``budget_tokens`` come from the backend's usage block
    when it reports one. A ratio at or above ``cap_ratio`` is treated as a cap
    hit even if ``finish_reason`` is missing — silence from a backend is not
    evidence of completeness.
    """
    reasons = []
    src = code or ""

    parse_error = None
    try:
        ast.parse(src)
    except SyntaxError as e:
        parse_error = f"SyntaxError line {e.lineno}: {e.msg}" if e.lineno else str(e)

    if parse_error:
        reasons.append(f"does not parse ({parse_error})")
    else:
        ok, why = ends_at_boundary(src)
        if not ok:
            reasons.append(why)

    sym = symbol_present(src, symbol)
    if symbol and sym is False:
        reasons.append(f"requested symbol {symbol!r} not found")

    if finish_reason == "length":
        reasons.append("finish_reason=length")

    ratio = None
    if completion_tokens and budget_tokens:
        ratio = round(float(completion_tokens) / float(budget_tokens), 3)
        if ratio >= cap_ratio:
            reasons.append(f"completion hit {ratio:.0%} of the token budget")

    return {
        "complete": not reasons,
        "reasons": reasons,
        "last_statement": last_statement(src),
        "parse_error": parse_error,
        "symbol_present": sym,
        "finish_reason": finish_reason,
        "budget_ratio": ratio,
    }
