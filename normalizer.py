"""
Normalizer: Converts SIEM rules to generalized expressions.

Transformation rules:
- class:value stays as class:value
- Other field:value becomes has(field)
- Duplicate has(field) at the same parenthesis level are deduplicated
"""

import re
from dataclasses import dataclass
from typing import FrozenSet, List, Optional, Set, Union


# Token types
@dataclass
class FieldValue:
    field: str
    value: str


@dataclass
class FieldArray:
    """Field with array of values, e.g., field:[foo,bar]"""
    field: str
    values: List[str]


@dataclass
class FieldsArray:
    """Array of fields with a single value, e.g., [field1,field2]:value or [field1,field2]&:value"""
    fields: List[str]
    value: str
    combine_op: str = 'or'  # 'or' for default, 'and' for & modifier


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


@dataclass
class ExplicitHas:
    """Explicit has(field) function call that should be preserved in output."""
    field: str


Token = Union[FieldValue, FieldArray, FieldsArray, Operator, NotOperator, OpenParen, CloseParen, FunctionCall, ExplicitHas]


def tokenize(rule: str) -> List[Token]:
    """Tokenize rule into tokens."""
    tokens: List[Token] = []
    i = 0
    rule = rule.strip()

    while i < len(rule):
        # Skip whitespace
        if rule[i].isspace():
            i += 1
            continue

        # [field1,field2]:value or [field1,field2]&:value pattern (array of fields with single value)
        # The & modifier indicates AND instead of OR
        # Must check before open parenthesis since both start with special chars
        if rule[i] == '[':
            # Try to match [fields](&)?:value pattern with various value types
            # Regex value: [field1,field2]:/pattern/ or [field1,field2]&:/pattern/
            match = re.match(r'\[([^\]]+)\](&?)[:=](/[^/]*/)', rule[i:])
            if match:
                fields = [f.strip() for f in match.group(1).split(',')]
                combine_op = 'and' if match.group(2) == '&' else 'or'
                tokens.append(FieldsArray(fields, match.group(3), combine_op))
                i += len(match.group(0))
                continue
            # Quoted value (double quotes): [field1,field2]:"value" or [field1,field2]&:"value"
            match = re.match(r'\[([^\]]+)\](&?)[:=]"([^"]*)"', rule[i:])
            if match:
                fields = [f.strip() for f in match.group(1).split(',')]
                combine_op = 'and' if match.group(2) == '&' else 'or'
                tokens.append(FieldsArray(fields, match.group(3), combine_op))
                i += len(match.group(0))
                continue
            # Quoted value (single quotes): [field1,field2]:'value' or [field1,field2]&:'value'
            match = re.match(r"\[([^\]]+)\](&?)[:=]'([^']*)'", rule[i:])
            if match:
                fields = [f.strip() for f in match.group(1).split(',')]
                combine_op = 'and' if match.group(2) == '&' else 'or'
                tokens.append(FieldsArray(fields, match.group(3), combine_op))
                i += len(match.group(0))
                continue
            # Quoted value (backticks): [field1,field2]:`value` or [field1,field2]&:`value`
            match = re.match(r'\[([^\]]+)\](&?)[:=]`([^`]*)`', rule[i:])
            if match:
                fields = [f.strip() for f in match.group(1).split(',')]
                combine_op = 'and' if match.group(2) == '&' else 'or'
                tokens.append(FieldsArray(fields, match.group(3), combine_op))
                i += len(match.group(0))
                continue
            # Unquoted value: [field1,field2]:value or [field1,field2]&:value
            match = re.match(r'\[([^\]]+)\](&?)[:=]([^\s()\[\]"\'`]+)', rule[i:])
            if match:
                fields = [f.strip() for f in match.group(1).split(',')]
                combine_op = 'and' if match.group(2) == '&' else 'or'
                tokens.append(FieldsArray(fields, match.group(3), combine_op))
                i += len(match.group(0))
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

        # Explicit has(field) or missing(field) pattern - should be preserved in output
        match = re.match(r'(has|missing)\(([a-zA-Z_][a-zA-Z0-9_]*)\)', rule[i:], re.IGNORECASE)
        if match:
            tokens.append(ExplicitHas(match.group(2)))
            i += len(match.group(0))
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
            func_name = match.group(1).lower()
            # has:field and missing:field should be treated as explicit has() calls
            if func_name in {'has', 'missing'}:
                tokens.append(ExplicitHas(match.group(2)))
            else:
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
    values: List[str]


@dataclass
class FieldsArrayExpr:
    """Array of fields with a single value, e.g., [field1,field2]:value or [field1,field2]&:value"""
    fields: List[str]
    value: str
    combine_op: str = 'or'  # 'or' for default, 'and' for & modifier


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
class ExplicitHasExpr:
    """Explicit has(field) that should be preserved in output regardless of ignore_fields."""
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


Expr = Union[FieldExpr, FieldArrayExpr, FieldsArrayExpr, FunctionExpr, HasExpr, ExplicitHasExpr, NotExpr, BinaryExpr, GroupExpr, None]


class Parser:
    """Parse tokens into an AST."""

    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Optional[Token]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def consume(self) -> Optional[Token]:
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
            elif isinstance(token, (FieldValue, FieldArray, FieldsArray, FunctionCall, ExplicitHas, OpenParen, NotOperator)):
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

        if isinstance(token, ExplicitHas):
            self.consume()
            return ExplicitHasExpr(token.field)

        if isinstance(token, FunctionCall):
            self.consume()
            return FunctionExpr(token.func_name, token.field, token.operator, token.value)

        if isinstance(token, FieldArray):
            self.consume()
            return FieldArrayExpr(token.field, token.values)

        if isinstance(token, FieldsArray):
            self.consume()
            return FieldsArrayExpr(token.fields, token.value, token.combine_op)

        if isinstance(token, FieldValue):
            self.consume()
            return FieldExpr(token.field, token.value)

        return None


def transform(expr: Expr, preserve_fields: Optional[Set[str]] = None, ignore_fields: Optional[Set[str]] = None) -> Expr:
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
        ignore_fields = {'rawmsg', 'srcipv4', 'dstipv4', 'srcipv6', 'dstipv6', 'srcport', 'dstport'}

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

    if isinstance(expr, FieldsArrayExpr):
        # [field1,field2]:value becomes (has(field1) or has(field2))
        # [field1,field2]&:value becomes (has(field1) and has(field2))
        # Filter out ignored fields
        valid_fields = [f for f in expr.fields if f not in ignore_fields]
        if not valid_fields:
            return None
        if len(valid_fields) == 1:
            return HasExpr(valid_fields[0])
        # Build expression using the combine_op (or/and)
        result: Expr = HasExpr(valid_fields[0])
        for field in valid_fields[1:]:
            result = BinaryExpr(result, expr.combine_op, HasExpr(field))
        return GroupExpr(result)

    if isinstance(expr, FunctionExpr):
        if expr.field in ignore_fields:
            return None
        # Function calls are transformed to has(field) for the field argument
        return HasExpr(expr.field)

    if isinstance(expr, ExplicitHasExpr):
        # Explicit has(field) is preserved regardless of ignore_fields
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
        # Unwrap single-element groups (not BinaryExpr)
        if not isinstance(inner, BinaryExpr):
            return inner
        return GroupExpr(inner)

    return expr


def get_field_signature(expr: Expr, preserve_fields: Optional[Set[str]] = None) -> FrozenSet[str]:
    """
    Get a canonical signature of has() fields referenced in an expression.
    Used for deduplicating OR branches that check the same fields.
    Excludes preserved fields (class, metaclass) from the signature.
    """
    if preserve_fields is None:
        preserve_fields = {'class', 'metaclass'}

    if expr is None:
        return frozenset()

    if isinstance(expr, HasExpr):
        return frozenset([expr.field])

    if isinstance(expr, FieldExpr):
        # Exclude preserved fields from signature
        if expr.field in preserve_fields:
            return frozenset()
        return frozenset([expr.field])

    if isinstance(expr, FieldArrayExpr):
        if expr.field in preserve_fields:
            return frozenset()
        return frozenset([expr.field])

    if isinstance(expr, (NotExpr, GroupExpr)):
        inner = expr.expr
        return get_field_signature(inner, preserve_fields)

    if isinstance(expr, BinaryExpr):
        left_sig = get_field_signature(expr.left, preserve_fields)
        right_sig = get_field_signature(expr.right, preserve_fields)
        return left_sig | right_sig

    return frozenset()


def is_and_only_group(expr: GroupExpr) -> bool:
    """Check if a group contains only AND-connected terms (no OR operators).

    Single-element groups are NOT flattenable - they represent semantic grouping
    from OR expressions that were deduplicated.
    """
    inner = expr.expr
    if inner is None:
        return False
    # Single-element groups should not be flattened
    if isinstance(inner, (FieldExpr, FieldArrayExpr, HasExpr)):
        return False
    if isinstance(inner, BinaryExpr):
        # Check if all operators in this expression tree are AND
        return _check_all_and(inner)
    return False


def _check_all_and(expr: Expr) -> bool:
    """Recursively check if all binary operators in the expression are AND."""
    if expr is None:
        return True
    if isinstance(expr, (FieldExpr, FieldArrayExpr, HasExpr)):
        return True
    if isinstance(expr, GroupExpr):
        # Groups inside can have OR, don't flatten those
        return False
    if isinstance(expr, BinaryExpr):
        if expr.op == 'or':
            return False
        return _check_all_and(expr.left) and _check_all_and(expr.right)
    return True


def deduplicate(expr: Expr) -> Expr:
    """
    Deduplicate has() expressions at the same level.
    For OR expressions, also deduplicate branches with identical field signatures.
    """
    if expr is None:
        return None

    if isinstance(expr, (FieldExpr, FieldArrayExpr, HasExpr)):
        return expr

    if isinstance(expr, NotExpr):
        return NotExpr(deduplicate(expr.expr))

    if isinstance(expr, GroupExpr):
        inner = deduplicate(expr.expr)
        # Unwrap single-element groups (when inner is not a BinaryExpr)
        if inner is None:
            return None
        if not isinstance(inner, BinaryExpr):
            return inner
        return GroupExpr(inner)

    if isinstance(expr, BinaryExpr):
        # Collect all terms at this level with the SAME operator
        terms: List[Expr] = []
        op = expr.op
        collect_terms_with_op(expr, terms, op)

        # First, recursively deduplicate all nested expressions
        deduped_terms: List[Expr] = []
        for term in terms:
            deduped_terms.append(deduplicate(term))

        # For AND expressions, flatten groups only when there are multiple groups
        # This allows merging overlapping groups while preserving single groups
        if op == 'and':
            # Count how many GroupExpr terms we have that can be flattened
            flattenable_groups = [t for t in deduped_terms if isinstance(t, GroupExpr) and is_and_only_group(t)]
            # Only flatten if there are 2+ groups that can be merged
            if len(flattenable_groups) >= 2:
                flattened: List[Expr] = []
                for term in deduped_terms:
                    if isinstance(term, GroupExpr) and is_and_only_group(term):
                        # Flatten the group's contents
                        inner_terms: List[Expr] = []
                        collect_terms_with_op(term.expr, inner_terms, 'and')
                        flattened.extend(inner_terms)
                    else:
                        flattened.append(term)
                deduped_terms = flattened

        # Deduplicate based on operator type
        seen_has: Set[str] = set()
        seen_field_expr: Set[tuple] = set()  # (field, value) tuples for FieldExpr
        seen_signatures: Set[FrozenSet[str]] = set()
        deduped: List[Expr] = []

        for term in deduped_terms:
            if term is None:
                continue
            if isinstance(term, HasExpr):
                # For HasExpr, deduplicate by field name (both AND and OR)
                if term.field not in seen_has:
                    seen_has.add(term.field)
                    deduped.append(term)
            elif isinstance(term, FieldExpr):
                # FieldExpr (preserved fields like class/metaclass) - deduplicate by field+value
                key = (term.field, term.value)
                if key not in seen_field_expr:
                    seen_field_expr.add(key)
                    deduped.append(term)
            else:
                # For both AND and OR branches, deduplicate by field signature
                sig = get_field_signature(term)
                if sig not in seen_signatures:
                    seen_signatures.add(sig)
                    deduped.append(term)

        # Rebuild the expression tree
        if not deduped:
            return None

        if len(deduped) == 1:
            return deduped[0]

        result: Expr = deduped[0]
        for term in deduped[1:]:
            result = BinaryExpr(result, op, term)

        return result

    return expr


def collect_terms_with_op(expr: Expr, terms: List[Expr], op: str) -> None:
    """Collect all terms from a chain of binary expressions with the same operator."""
    if isinstance(expr, BinaryExpr) and expr.op == op:
        collect_terms_with_op(expr.left, terms, op)
        collect_terms_with_op(expr.right, terms, op)
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
        # Use implicit AND (space) instead of explicit "and"
        if expr.op == 'and':
            return f'{left} {right}'
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
    import sys
    if len(sys.argv) > 1:
        rule = ' '.join(sys.argv[1:])
        print(normalize(rule))
    else:
        print("Usage: python normalizer.py <rule>")
        print("Example: python normalizer.py 'class:ms_windows_event eventid:1234'")
