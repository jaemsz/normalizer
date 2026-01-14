"""
Normalizer: Converts SIEM rules to generalized expressions.

Transformation rules:
- class:value stays as class:value
- Other field:value becomes has(field)
- Duplicate has(field) at the same parenthesis level are deduplicated
"""

import re
from dataclasses import dataclass
from typing import Union


# Token types
@dataclass
class FieldValue:
    field: str
    value: str


@dataclass
class FieldArray:
    """Field with array of values, e.g., field:[foo,bar]"""
    field: str
    values: list[str]


@dataclass
class Operator:
    op: str  # 'and', 'or'


@dataclass
class NotOperator:
    """Negation operator"""
    pass


@dataclass
class OpenParen:
    pass


@dataclass
class CloseParen:
    pass


@dataclass
class FunctionCall:
    """Function call with field argument, e.g., length(domain)>20"""
    func_name: str
    field: str
    operator: str
    value: str


Token = Union[FieldValue, FieldArray, Operator, NotOperator, OpenParen, CloseParen, FunctionCall]


def tokenize(rule: str) -> list[Token]:
    """Tokenize a SIEM rule string into tokens."""
    tokens = []
    i = 0
    rule = rule.strip()

    while i < len(rule):
        # Skip whitespace
        if rule[i].isspace():
            i += 1
            continue

        # Open parenthesis
        if rule[i] == '(':
            tokens.append(OpenParen())
            i += 1
            continue

        # Close parenthesis
        if rule[i] == ')':
            tokens.append(CloseParen())
            i += 1
            continue

        # Check for operators (!, not, and, or)
        if rule[i] == '!':
            tokens.append(NotOperator())
            i += 1
            continue

        if rule[i:i+3].lower() == 'not' and (i+3 >= len(rule) or not rule[i+3].isalnum()):
            tokens.append(NotOperator())
            i += 3
            continue

        if rule[i:i+3].lower() == 'and' and (i+3 >= len(rule) or not rule[i+3].isalnum()):
            tokens.append(Operator('and'))
            i += 3
            continue

        if rule[i:i+2].lower() == 'or' and (i+2 >= len(rule) or not rule[i+2].isalnum()):
            tokens.append(Operator('or'))
            i += 2
            continue

        # Function call pattern: func(field)operator value, e.g., length(domain)>20
        match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)\(([a-zA-Z_][a-zA-Z0-9_]*)\)\s*(>=|<=|!=|>|<|=)\s*([^\s()]+)', rule[i:])
        if match:
            tokens.append(FunctionCall(match.group(1), match.group(2), match.group(3), match.group(4)))
            i += len(match.group(0))
            continue

        # Colon-style function call: missing:field, has:field, etc.
        colon_functions = {'md5', 'sha1', 'sha256', 'sha384', 'sha512', 'has', 'missing', 'lower', 'upper', 'length', 'equal'}
        match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)[:=]([a-zA-Z_][a-zA-Z0-9_]*)\b', rule[i:])
        if match and match.group(1).lower() in colon_functions:
            tokens.append(FunctionCall(match.group(1), match.group(2), '', ''))
            i += len(match.group(0))
            continue

        # Field:[value1,value2,...] or Field=[value1,value2,...] or Field!:[...] or Field:&[...] array pattern
        match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)(!?[:=])&?\[([^\]]+)\]', rule[i:])
        if match:
            field = match.group(1)
            # Strip quotes (single, double, or backtick) from array values
            values = [v.strip().strip('"').strip("'").strip('`') for v in match.group(3).split(',')]
            tokens.append(FieldArray(field, values))
            i += len(match.group(0))
            continue

        # Field:/regex/ pattern (must come before other quoted patterns)
        match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)!?[:=](/[^/]*/)', rule[i:])
        if match:
            tokens.append(FieldValue(match.group(1), match.group(2)))
            i += len(match.group(0))
            continue

        # Field:"quoted value", Field='quoted value', Field=`quoted value`, or Field!:"..." pattern
        match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)!?[:=]"([^"]*)"', rule[i:])
        if match:
            tokens.append(FieldValue(match.group(1), match.group(2)))
            i += len(match.group(0))
            continue

        match = re.match(r"([a-zA-Z_][a-zA-Z0-9_]*)!?[:=]'([^']*)'", rule[i:])
        if match:
            tokens.append(FieldValue(match.group(1), match.group(2)))
            i += len(match.group(0))
            continue

        match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)!?[:=]`([^`]*)`', rule[i:])
        if match:
            tokens.append(FieldValue(match.group(1), match.group(2)))
            i += len(match.group(0))
            continue

        # Field:value, Field=value, or Field!:value pattern (unquoted)
        match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)!?[:=]([^\s()\[\]"\'`]+)', rule[i:])
        if match:
            tokens.append(FieldValue(match.group(1), match.group(2)))
            i += len(match.group(0))
            continue

        # Unknown character - skip
        i += 1

    return tokens


# AST node types
@dataclass
class FieldExpr:
    field: str
    value: str


@dataclass
class FieldArrayExpr:
    """Field with array of possible values."""
    field: str
    values: list[str]


@dataclass
class FunctionExpr:
    """Function call expression, e.g., length(domain)>20"""
    func_name: str
    field: str
    operator: str
    value: str


@dataclass
class HasExpr:
    field: str


@dataclass
class NotExpr:
    """Negation expression."""
    expr: 'Expr'


@dataclass
class BinaryExpr:
    left: 'Expr'
    op: str
    right: 'Expr'


@dataclass
class GroupExpr:
    expr: 'Expr'


Expr = Union[FieldExpr, FieldArrayExpr, FunctionExpr, HasExpr, NotExpr, BinaryExpr, GroupExpr, None]


class Parser:
    """Parse tokens into an AST."""

    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Token | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def consume(self) -> Token | None:
        token = self.peek()
        if token:
            self.pos += 1
        return token

    def parse(self) -> Expr:
        return self.parse_expr()

    def parse_expr(self) -> Expr:
        """Parse an expression with operators (including implicit AND)."""
        left = self.parse_primary()

        while True:
            token = self.peek()
            if isinstance(token, Operator):
                self.consume()
                right = self.parse_primary()
                left = BinaryExpr(left, token.op, right)
            elif isinstance(token, (FieldValue, FieldArray, FunctionCall, OpenParen, NotOperator)):
                # Implicit AND between consecutive terms
                right = self.parse_primary()
                left = BinaryExpr(left, 'and', right)
            else:
                break

        return left

    def parse_primary(self) -> Expr:
        """Parse a primary expression (field:value, not expr, or grouped expression)."""
        token = self.peek()

        # Handle 'not' operator
        if isinstance(token, NotOperator):
            self.consume()
            expr = self.parse_primary()
            return NotExpr(expr)

        if isinstance(token, OpenParen):
            self.consume()
            expr = self.parse_expr()
            # Consume closing paren
            if isinstance(self.peek(), CloseParen):
                self.consume()
            return GroupExpr(expr)

        if isinstance(token, FunctionCall):
            self.consume()
            return FunctionExpr(token.func_name, token.field, token.operator, token.value)

        if isinstance(token, FieldArray):
            self.consume()
            return FieldArrayExpr(token.field, token.values)

        if isinstance(token, FieldValue):
            self.consume()
            return FieldExpr(token.field, token.value)

        return None


def transform(expr: Expr, preserve_fields: set[str] = None, ignore_fields: set[str] = None) -> Expr:
    """
    Transform the AST to generalized form.

    - class:value stays as-is
    - Other field:value becomes has(field)
    - field:[a,b] becomes has(field)
    - not field:value becomes has(field)
    - ignored fields are removed completely
    """
    if preserve_fields is None:
        preserve_fields = {'class', 'metaclass'}
    if ignore_fields is None:
        ignore_fields = {'rawmsg'}

    if expr is None:
        return None

    if isinstance(expr, FieldExpr):
        if expr.field in ignore_fields:
            return None
        if expr.field in preserve_fields:
            return FieldExpr(expr.field, expr.value)
        else:
            return HasExpr(expr.field)

    if isinstance(expr, FieldArrayExpr):
        if expr.field in ignore_fields:
            return None
        if expr.field in preserve_fields:
            return FieldArrayExpr(expr.field, expr.values)
        else:
            return HasExpr(expr.field)

    if isinstance(expr, FunctionExpr):
        if expr.field in ignore_fields:
            return None
        # Function calls are transformed to has(field) for the field argument
        return HasExpr(expr.field)

    if isinstance(expr, NotExpr):
        # Negation is not needed in output - just check field existence
        return transform(expr.expr, preserve_fields, ignore_fields)

    if isinstance(expr, BinaryExpr):
        left = transform(expr.left, preserve_fields, ignore_fields)
        right = transform(expr.right, preserve_fields, ignore_fields)
        # Handle cases where one or both sides are None (ignored)
        if left is None and right is None:
            return None
        if left is None:
            return right
        if right is None:
            return left
        return BinaryExpr(left, expr.op, right)

    if isinstance(expr, GroupExpr):
        inner = transform(expr.expr, preserve_fields, ignore_fields)
        if inner is None:
            return None
        return GroupExpr(inner)

    return expr


def deduplicate(expr: Expr) -> Expr:
    """
    Deduplicate has() expressions at the same level.
    """
    if expr is None:
        return None

    if isinstance(expr, (FieldExpr, FieldArrayExpr, HasExpr)):
        return expr

    if isinstance(expr, NotExpr):
        return NotExpr(deduplicate(expr.expr))

    if isinstance(expr, GroupExpr):
        return GroupExpr(deduplicate(expr.expr))

    if isinstance(expr, BinaryExpr):
        # Collect all terms at this level with the same operator
        terms = []
        ops = set()
        collect_terms(expr, terms, ops)

        # Deduplicate HasExpr by field name
        seen_has = set()
        deduped = []
        for term in terms:
            if isinstance(term, HasExpr):
                if term.field not in seen_has:
                    seen_has.add(term.field)
                    deduped.append(term)
            else:
                # Recursively deduplicate nested expressions
                deduped.append(deduplicate(term))

        # Rebuild the expression tree
        if not deduped:
            return None

        result = deduped[0]
        # Use the most common operator or default to 'and'
        op = 'and' if 'and' in ops else ('or' if 'or' in ops else 'and')
        for term in deduped[1:]:
            result = BinaryExpr(result, op, term)

        return result

    return expr


def collect_terms(expr: Expr, terms: list, ops: set):
    """Collect all terms from a chain of binary expressions."""
    if isinstance(expr, BinaryExpr):
        ops.add(expr.op)
        collect_terms(expr.left, terms, ops)
        collect_terms(expr.right, terms, ops)
    else:
        terms.append(expr)


def to_string(expr: Expr) -> str:
    """Convert AST back to string representation."""
    if expr is None:
        return ''

    if isinstance(expr, FieldExpr):
        return f'{expr.field}:{expr.value}'

    if isinstance(expr, FieldArrayExpr):
        values = ','.join(expr.values)
        return f'{expr.field}:[{values}]'

    if isinstance(expr, HasExpr):
        return f'has({expr.field})'

    if isinstance(expr, NotExpr):
        inner = to_string(expr.expr)
        return f'not {inner}'

    if isinstance(expr, BinaryExpr):
        left = to_string(expr.left)
        right = to_string(expr.right)
        return f'{left} {expr.op} {right}'

    if isinstance(expr, GroupExpr):
        inner = to_string(expr.expr)
        return f'({inner})'

    return ''


def normalize(rule: str) -> str:
    """
    Main entry point: normalize a SIEM rule to its generalized form.

    Examples:
        >>> normalize("class:ms_windows_event")
        'class:ms_windows_event'

        >>> normalize("class:ms_windows_event eventid:1234")
        'class:ms_windows_event and has(eventid)'

        >>> normalize("class:ms_windows_event (eventid:1234 or eventid:2345)")
        'class:ms_windows_event and (has(eventid))'
    """
    tokens = tokenize(rule)
    parser = Parser(tokens)
    ast = parser.parse()
    transformed = transform(ast)
    deduped = deduplicate(transformed)
    return to_string(deduped)


if __name__ == '__main__':
    # Test examples from CLAUDE.md
    test_rules = [
        "class:ms_windows_event",
        "class:ms_windows_event eventid:1234",
        "class:ms_windows_event (eventid:1234 or eventid:2345)",
        # New syntax: array values
        "class:ms_windows_event status:[foo,bar]",
        # New syntax: negation
        "class:ms_windows_event not status:[foo,bar]",
        # Combined
        "class:ms_windows_event eventid:1234 not status:[error,warning]",
        # Exclamation mark negation
        "class:ms_windows_event !field:[abc,foo,123]",
        "class:ms_windows_event !eventid:1234",
        # Equals sign separator
        "class=ms_windows_event",
        "class=ms_windows_event eventid=1234",
        "class=ms_windows_event status=[foo,bar]",
        "class=ms_windows_event !status=[error,warning]",
        # Quoted values (double quotes)
        'class:ms_windows_event field="the value"',
        'class="ms_windows_event" message="hello world"',
        'class:ms_windows_event status=["error message", "warning text"]',
        # Single quotes
        "class:ms_windows_event field='the value'",
        "class='ms_windows_event' message='hello world'",
        # Backticks
        "class:ms_windows_event field=`the value`",
        "class=`ms_windows_event` message=`hello world`",
        # Mixed quotes in array
        "class:ms_windows_event status=['error', \"warning\", `info`]",
        # Complex nested parentheses
        "class:ms_windows_event (eventid:1234 or (status:error and level:critical))",
        "class:ms_windows_event ((eventid:1234 or eventid:5678) and (status:error or status:warning))",
        "class:ms_windows_event (((field1:a or field1:b) and field2:c) or (field3:d and (field4:e or field4:f)))",
        # Deep nesting with negation
        "class:ms_windows_event (eventid:123 and (!status:[error,warning] or (level:high and !source:internal)))",
        # Metaclass (preserved like class)
        "metaclass:network_event status:active",
        "class:ms_windows_event metaclass:security eventid:1234",
        # Not-equal separator (!:)
        "class:ms_windows_event action!:'block'",
        "class:ms_windows_event status!:error level!:critical",
        "class:ms_windows_event action!:[allow,deny]",
        # Dollar sign variable values
        "class:ms_windows_event srcipv4:$exclusions.global.srcipv4",
        "class:ms_windows_event srcip:$vars.ip dstip:$vars.target",
        "class:ms_windows_event !field:$some.variable",
        # Ampersand array syntax
        "class:ms_windows_event args:&[`fielssytem`,`--test`]",
        # Regex values (forward slashes)
        "class:ms_windows_event field:/foobar/",
        "class:ms_windows_event pattern:/^test.*end$/",
        # Complex combined test
        "metaclass:windows eventid=[1,2,3] (msg:/(service name:|the)\\s+(asdf|back|usb)\\s+service/ OR serviceid=['asdf','wer','oiuouo']) NOT srcipv4:$exclusions.global.srcipv4",
        # Ignored field (rawmsg)
        "class:ms_windows_event rawmsg:/test/",
        "class:ms_windows_event eventid:1234 rawmsg:'some message' status:error",
        "class:ms_windows_event (rawmsg:/pattern/ or eventid:123)",
        # Complex test with missing, wildcards, and multiple NOT
        "metaclass:http_proxy dstport=[80,443] missing:referrer useragent=\"Google\" NOT domain:'*.google.com' NOT dstdomain=google.com NOT rawmsg:\"*Google\" NOT srcipv4:$exclusions.global.srcipv4",
        # Colon-style functions
        "class:ms_windows_event has:username missing:domain",
        "class:ms_windows_event md5:filehash sha256:checksum",
        "class:ms_windows_event lower:hostname upper:status length:message",
        # Function calls
        "class=ms_windows_event length(domain)>20",
        "class=ms_windows_event length(username)>=10 and count(events)<100",
        "class=ms_windows_event (length(domain)>20 or size(payload)!=0)",
        "class=ms_windows_event !length(field)=0",
    ]

    print("Normalizer Test Results")
    print("=" * 60)

    for rule in test_rules:
        result = normalize(rule)
        print(f"Input:  {rule}")
        print(f"Output: {result}")
        print("-" * 60)
