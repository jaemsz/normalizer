"""Unit tests for the Normalizer module."""

import unittest
from normalizer import normalize, tokenize, Parser, transform, deduplicate


class TestNormalize(unittest.TestCase):
    """Test the main normalize function."""

    def test_class_only(self):
        """class:value stays as class:value."""
        self.assertEqual(normalize("class:ms_windows_event"), "class:ms_windows_event")

    def test_class_with_field(self):
        """Other field:value becomes has(field)."""
        self.assertEqual(
            normalize("class:ms_windows_event eventid:1234"),
            "class:ms_windows_event and has(eventid)"
        )

    def test_class_with_or_expression(self):
        """Duplicate has(field) at same parenthesis level are deduplicated."""
        self.assertEqual(
            normalize("class:ms_windows_event (eventid:1234 or eventid:2345)"),
            "class:ms_windows_event and (has(eventid))"
        )


class TestArraySyntax(unittest.TestCase):
    """Test array value syntax."""

    def test_array_values(self):
        self.assertEqual(
            normalize("class:ms_windows_event status:[foo,bar]"),
            "class:ms_windows_event and has(status)"
        )

    def test_negated_array(self):
        self.assertEqual(
            normalize("class:ms_windows_event not status:[foo,bar]"),
            "class:ms_windows_event and has(status)"
        )

    def test_combined_with_array(self):
        self.assertEqual(
            normalize("class:ms_windows_event eventid:1234 not status:[error,warning]"),
            "class:ms_windows_event and has(eventid) and has(status)"
        )

    def test_exclamation_negation_array(self):
        self.assertEqual(
            normalize("class:ms_windows_event !field:[abc,foo,123]"),
            "class:ms_windows_event and has(field)"
        )

    def test_exclamation_negation_single(self):
        self.assertEqual(
            normalize("class:ms_windows_event !eventid:1234"),
            "class:ms_windows_event and has(eventid)"
        )


class TestEqualsSyntax(unittest.TestCase):
    """Test equals sign separator syntax."""

    def test_equals_class(self):
        self.assertEqual(normalize("class=ms_windows_event"), "class:ms_windows_event")

    def test_equals_with_field(self):
        self.assertEqual(
            normalize("class=ms_windows_event eventid=1234"),
            "class:ms_windows_event and has(eventid)"
        )

    def test_equals_with_array(self):
        self.assertEqual(
            normalize("class=ms_windows_event status=[foo,bar]"),
            "class:ms_windows_event and has(status)"
        )

    def test_equals_negation_array(self):
        self.assertEqual(
            normalize("class=ms_windows_event !status=[error,warning]"),
            "class:ms_windows_event and has(status)"
        )


class TestQuotedValues(unittest.TestCase):
    """Test quoted value syntax."""

    def test_double_quotes(self):
        self.assertEqual(
            normalize('class:ms_windows_event field="the value"'),
            "class:ms_windows_event and has(field)"
        )

    def test_double_quotes_class(self):
        self.assertEqual(
            normalize('class="ms_windows_event" message="hello world"'),
            "class:ms_windows_event and has(message)"
        )

    def test_quoted_array(self):
        self.assertEqual(
            normalize('class:ms_windows_event status=["error message", "warning text"]'),
            "class:ms_windows_event and has(status)"
        )

    def test_single_quotes(self):
        self.assertEqual(
            normalize("class:ms_windows_event field='the value'"),
            "class:ms_windows_event and has(field)"
        )

    def test_single_quotes_class(self):
        self.assertEqual(
            normalize("class='ms_windows_event' message='hello world'"),
            "class:ms_windows_event and has(message)"
        )

    def test_backticks(self):
        self.assertEqual(
            normalize("class:ms_windows_event field=`the value`"),
            "class:ms_windows_event and has(field)"
        )

    def test_backticks_class(self):
        self.assertEqual(
            normalize("class=`ms_windows_event` message=`hello world`"),
            "class:ms_windows_event and has(message)"
        )

    def test_mixed_quotes_array(self):
        self.assertEqual(
            normalize("class:ms_windows_event status=['error', \"warning\", `info`]"),
            "class:ms_windows_event and has(status)"
        )


class TestNestedParentheses(unittest.TestCase):
    """Test complex nested parentheses."""

    def test_nested_or_and(self):
        self.assertEqual(
            normalize("class:ms_windows_event (eventid:1234 or (status:error and level:critical))"),
            "class:ms_windows_event and (has(eventid) or (has(status) and has(level)))"
        )

    def test_double_nested(self):
        self.assertEqual(
            normalize("class:ms_windows_event ((eventid:1234 or eventid:5678) and (status:error or status:warning))"),
            "class:ms_windows_event and ((has(eventid)) and (has(status)))"
        )

    def test_triple_nested(self):
        self.assertEqual(
            normalize("class:ms_windows_event (((field1:a or field1:b) and field2:c) or (field3:d and (field4:e or field4:f)))"),
            "class:ms_windows_event and (((has(field1)) and has(field2)) or (has(field3) and (has(field4))))"
        )

    def test_deep_nesting_with_negation(self):
        self.assertEqual(
            normalize("class:ms_windows_event (eventid:123 and (!status:[error,warning] or (level:high and !source:internal)))"),
            "class:ms_windows_event and (has(eventid) and (has(status) or (has(level) and has(source))))"
        )


class TestMetaclass(unittest.TestCase):
    """Test metaclass (preserved like class)."""

    def test_metaclass_preserved(self):
        self.assertEqual(
            normalize("metaclass:network_event status:active"),
            "metaclass:network_event and has(status)"
        )

    def test_class_and_metaclass(self):
        self.assertEqual(
            normalize("class:ms_windows_event metaclass:security eventid:1234"),
            "class:ms_windows_event and metaclass:security and has(eventid)"
        )


class TestNotEqualSeparator(unittest.TestCase):
    """Test not-equal separator (!:)."""

    def test_not_equal_single_quoted(self):
        self.assertEqual(
            normalize("class:ms_windows_event action!:'block'"),
            "class:ms_windows_event and has(action)"
        )

    def test_not_equal_multiple(self):
        self.assertEqual(
            normalize("class:ms_windows_event status!:error level!:critical"),
            "class:ms_windows_event and has(status) and has(level)"
        )

    def test_not_equal_array(self):
        self.assertEqual(
            normalize("class:ms_windows_event action!:[allow,deny]"),
            "class:ms_windows_event and has(action)"
        )


class TestVariableValues(unittest.TestCase):
    """Test dollar sign variable values."""

    def test_variable_value(self):
        # srcipv4 is in ignore_fields, so use a different field
        self.assertEqual(
            normalize("class:ms_windows_event hostname:$exclusions.global.hostname"),
            "class:ms_windows_event and has(hostname)"
        )

    def test_multiple_variables(self):
        self.assertEqual(
            normalize("class:ms_windows_event srchost:$vars.ip dsthost:$vars.target"),
            "class:ms_windows_event and has(srchost) and has(dsthost)"
        )

    def test_negated_variable(self):
        self.assertEqual(
            normalize("class:ms_windows_event !field:$some.variable"),
            "class:ms_windows_event and has(field)"
        )


class TestSpecialSyntax(unittest.TestCase):
    """Test special syntax features."""

    def test_ampersand_array(self):
        self.assertEqual(
            normalize("class:ms_windows_event args:&[`fielssytem`,`--test`]"),
            "class:ms_windows_event and has(args)"
        )

    def test_regex_values(self):
        self.assertEqual(
            normalize("class:ms_windows_event field:/foobar/"),
            "class:ms_windows_event and has(field)"
        )

    def test_regex_complex(self):
        self.assertEqual(
            normalize("class:ms_windows_event pattern:/^test.*end$/"),
            "class:ms_windows_event and has(pattern)"
        )


class TestIgnoredFields(unittest.TestCase):
    """Test ignored fields (rawmsg)."""

    def test_rawmsg_ignored(self):
        self.assertEqual(
            normalize("class:ms_windows_event rawmsg:/test/"),
            "class:ms_windows_event"
        )

    def test_rawmsg_in_middle(self):
        self.assertEqual(
            normalize("class:ms_windows_event eventid:1234 rawmsg:'some message' status:error"),
            "class:ms_windows_event and has(eventid) and has(status)"
        )

    def test_rawmsg_in_group(self):
        # Single-element groups are unwrapped after ignored field is removed
        self.assertEqual(
            normalize("class:ms_windows_event (rawmsg:/pattern/ or eventid:123)"),
            "class:ms_windows_event and has(eventid)"
        )


class TestFunctionCalls(unittest.TestCase):
    """Test function call syntax."""

    def test_explicit_has_function_preserved(self):
        """Explicit has(field) in rule should be preserved in output."""
        self.assertEqual(
            normalize("class=ms_windows_event has(srcipv4)"),
            "class:ms_windows_event and has(srcipv4)"
        )

    def test_explicit_has_deduplicated(self):
        """Duplicate explicit has(field) calls should be deduplicated."""
        self.assertEqual(
            normalize("class=ms_windows_event has(srcipv4) has(srcipv4)"),
            "class:ms_windows_event and has(srcipv4)"
        )

    def test_explicit_has_colon_style_preserved(self):
        """Explicit has:field syntax should be preserved even for ignored fields."""
        self.assertEqual(
            normalize("class=ms_windows_event has:srcipv4"),
            "class:ms_windows_event and has(srcipv4)"
        )

    def test_colon_style_has_missing(self):
        self.assertEqual(
            normalize("class:ms_windows_event has:username missing:domain"),
            "class:ms_windows_event and has(username) and has(domain)"
        )

    def test_colon_style_hash_functions(self):
        self.assertEqual(
            normalize("class:ms_windows_event md5:filehash sha256:checksum"),
            "class:ms_windows_event and has(filehash) and has(checksum)"
        )

    def test_colon_style_transform_functions(self):
        self.assertEqual(
            normalize("class:ms_windows_event lower:hostname upper:status length:message"),
            "class:ms_windows_event and has(hostname) and has(status) and has(message)"
        )

    def test_function_call_comparison(self):
        self.assertEqual(
            normalize("class=ms_windows_event length(domain)>20"),
            "class:ms_windows_event and has(domain)"
        )

    def test_multiple_function_calls(self):
        self.assertEqual(
            normalize("class=ms_windows_event length(username)>=10 and count(events)<100"),
            "class:ms_windows_event and has(username) and has(events)"
        )

    def test_function_calls_in_group(self):
        self.assertEqual(
            normalize("class=ms_windows_event (length(domain)>20 or size(payload)!=0)"),
            "class:ms_windows_event and (has(domain) or has(payload))"
        )

    def test_negated_function_call(self):
        self.assertEqual(
            normalize("class=ms_windows_event !length(field)=0"),
            "class:ms_windows_event and has(field)"
        )


class TestFieldArraySyntax(unittest.TestCase):
    """Test array of field names syntax (e.g., [field1,field2]:value)."""

    def test_field_array_with_multiple_fields(self):
        """Array of field names becomes OR of has() checks."""
        self.assertEqual(
            normalize("class=ms_windows_event [eventlog,category]:application source:/mssql/ eventid=123"),
            "class:ms_windows_event and (has(eventlog) or has(category)) and has(source) and has(eventid)"
        )

    def test_field_array_with_ampersand_and(self):
        """Array of field names with & modifier becomes AND of has() checks."""
        self.assertEqual(
            normalize("class:ms_windows_event [hostname,domain]&:microsoft.com"),
            "class:ms_windows_event and (has(hostname) and has(domain))"
        )


class TestDeduplication(unittest.TestCase):
    """Test deduplication of identical groups and expressions."""

    def test_duplicate_groups_deduplicated(self):
        """Identical parenthesized groups should be deduplicated."""
        self.assertEqual(
            normalize("(class:ms_windows_event category=threat status:[new,updated] severity:high) and (class:ms_windows_event category=threat status:[new,updated] severity:high)"),
            "class:ms_windows_event and has(category) and has(status) and has(severity)"
        )

    def test_overlapping_groups_merged(self):
        """Groups with overlapping fields should be merged with all unique fields."""
        self.assertEqual(
            normalize("(class:ms_windows_event category=threat status:[new,updated] severity:high) and (class:ms_windows_event category=threat status:[new,updated] severity:high domain:foobar.com)"),
            "class:ms_windows_event and has(category) and has(status) and has(severity) and has(domain)"
        )


class TestComplexRules(unittest.TestCase):
    """Test complex combined rules."""

    def test_complex_combined(self):
        result = normalize(
            "metaclass:windows eventid=[1,2,3] (msg:/(service name:|the)\\s+(asdf|back|usb)\\s+service/ OR serviceid=['asdf','wer','oiuouo']) NOT srcipv4:$exclusions.global.srcipv4"
        )
        # srcipv4 is in ignore_fields, so it's removed
        self.assertEqual(
            result,
            "metaclass:windows and has(eventid) and (has(msg) or has(serviceid))"
        )

    def test_complex_with_missing_and_multiple_not(self):
        result = normalize(
            "metaclass:http_proxy dstport=[80,443] missing:referrer useragent=\"Google\" NOT domain:'*.google.com' NOT dstdomain=google.com NOT rawmsg:\"*Google\" NOT srcipv4:$exclusions.global.srcipv4"
        )
        # dstport, rawmsg, srcipv4 are in ignore_fields, so they're removed
        self.assertEqual(
            result,
            "metaclass:http_proxy and has(referrer) and has(useragent) and has(domain) and has(dstdomain)"
        )

    def test_complex_or_branches_with_regex(self):
        """Complex rule with multiple OR branches, regex patterns, and various syntax."""
        rule = (
            'metaclass:http_proxy (useragent="Mozilla/3.0 (compatible; Indy Library)" '
            r'uri:/find_dnfile\.php\?u[a-z0-9]{64}/) OR (httpmethod=post useragent="python" '
            'uri="/a/b/config.php") OR (useragent="IE" uri:dn.snk) OR (useragent="foo" '
            r'uri:/abc.def/) OR (useragent="whoa" uri:/alsdjf.ksdjf\.exe/) NOT '
            'srcipv4:$exclusions.global.srcipv4'
        )
        result = normalize(rule)
        # OR operators preserved, duplicate branches deduplicated by field signature
        # 4 branches have {useragent, uri} so they're deduplicated to 1
        # 1 branch has {httpmethod, useragent, uri}
        # srcipv4 is in ignore_fields, so it's removed
        self.assertEqual(
            result,
            "metaclass:http_proxy and (has(useragent) and has(uri)) or "
            "(has(httpmethod) and has(useragent) and has(uri))"
        )

    def test_metaclass_array_with_ignored_fields(self):
        """Metaclass array with ignored fields (dstipv4, srcipv4) removed."""
        rule = (
            r'metaclass:[asa,http_proxy] (dstipv4=$home.nets OR dstisp:/private*/) '
            r'uri:/^\/\+CSCOIE|U)\+/cedsave\.html\?.+ced=\.\.\.\/\.\.\/locale\/ru\/LC_MESSAGES\/webvpn\.mo$/ '
            r'NOT srcipv4:$exclusions.global.srcipv4'
        )
        result = normalize(rule)
        # dstipv4 and srcipv4 are in ignore_fields
        # Single-element group (dstisp) is unwrapped
        self.assertEqual(
            result,
            "metaclass:[asa,http_proxy] and has(dstisp) and has(uri)"
        )


class TestEdgeCasesGracefulHandling(unittest.TestCase):
    """Test that edge cases and invalid inputs are handled gracefully without exceptions."""

    def test_empty_string(self):
        """Empty input returns empty output."""
        self.assertEqual(normalize(""), "")

    def test_whitespace_only(self):
        """Whitespace-only input returns empty output."""
        self.assertEqual(normalize("   "), "")
        self.assertEqual(normalize("\t\n"), "")

    def test_unbalanced_open_paren(self):
        """Unbalanced open parenthesis is handled gracefully."""
        result = normalize("(class:foo")
        self.assertIn("class:foo", result)

    def test_unbalanced_close_paren(self):
        """Unbalanced close parenthesis is handled gracefully."""
        result = normalize("class:foo)")
        self.assertEqual(result, "class:foo")

    def test_empty_parentheses(self):
        """Empty parentheses are handled gracefully."""
        result = normalize("class:foo ()")
        self.assertEqual(result, "class:foo")

    def test_just_parentheses(self):
        """Only parentheses returns empty."""
        self.assertEqual(normalize("()"), "")
        self.assertEqual(normalize("(())"), "")

    def test_only_operator(self):
        """Operator without operands returns empty."""
        self.assertEqual(normalize("and"), "")
        self.assertEqual(normalize("or"), "")
        self.assertEqual(normalize("not"), "")

    def test_consecutive_operators(self):
        """Consecutive operators are handled gracefully."""
        result = normalize("class:foo and and bar:baz")
        self.assertIn("class:foo", result)

    def test_operator_at_start(self):
        """Operator at start is handled gracefully."""
        result = normalize("and class:foo")
        self.assertEqual(result, "class:foo")

    def test_operator_at_end(self):
        """Operator at end is handled gracefully."""
        result = normalize("class:foo or")
        self.assertEqual(result, "class:foo")

    def test_missing_value_after_colon(self):
        """Missing value after colon returns empty."""
        self.assertEqual(normalize("class:"), "")

    def test_missing_field_before_colon(self):
        """Missing field before colon returns empty."""
        self.assertEqual(normalize(":value"), "")

    def test_random_garbage(self):
        """Random invalid characters return empty."""
        self.assertEqual(normalize("@#$%^&"), "")
        self.assertEqual(normalize("!!!"), "")

    def test_unclosed_double_quote(self):
        """Unclosed double quote is handled gracefully."""
        result = normalize('class:"foo')
        # Should not raise, returns empty or partial
        self.assertIsInstance(result, str)

    def test_unclosed_single_quote(self):
        """Unclosed single quote is handled gracefully."""
        result = normalize("class:'foo")
        self.assertIsInstance(result, str)

    def test_unclosed_bracket(self):
        """Unclosed bracket is handled gracefully."""
        result = normalize("class:foo field:[a,b")
        self.assertIsInstance(result, str)

    def test_deeply_nested_parens(self):
        """Deeply nested parentheses don't cause stack overflow."""
        rule = "class:foo " + "(" * 50 + "field:bar" + ")" * 50
        result = normalize(rule)
        self.assertIn("class:foo", result)

    def test_very_long_input(self):
        """Very long input is handled without issues."""
        fields = " ".join([f"field{i}:value{i}" for i in range(100)])
        rule = f"class:test {fields}"
        result = normalize(rule)
        self.assertIn("class:test", result)

    def test_unicode_characters(self):
        """Unicode characters don't cause crashes."""
        result = normalize("class:测试 field:值")
        self.assertIsInstance(result, str)

    def test_newlines_in_input(self):
        """Newlines in input are handled as whitespace."""
        result = normalize("class:foo\neventid:123")
        self.assertEqual(result, "class:foo and has(eventid)")

    def test_tabs_in_input(self):
        """Tabs in input are handled as whitespace."""
        result = normalize("class:foo\teventid:123")
        self.assertEqual(result, "class:foo and has(eventid)")

    def test_mixed_valid_invalid(self):
        """Mix of valid and invalid tokens extracts valid parts."""
        result = normalize("class:foo @#$ eventid:123")
        self.assertIn("class:foo", result)


class TestNoneHandling(unittest.TestCase):
    """Test internal handling of None values."""

    def test_all_ignored_fields(self):
        """Rule with only ignored fields returns empty."""
        self.assertEqual(normalize("rawmsg:test"), "")

    def test_ignored_in_or_group(self):
        """Ignored field in OR group simplifies correctly."""
        # Single-element groups are unwrapped after ignored field is removed
        result = normalize("class:foo (rawmsg:test or eventid:123)")
        self.assertEqual(result, "class:foo and has(eventid)")

    def test_ignored_in_and_group(self):
        """Ignored field in AND group simplifies correctly."""
        # Single-element groups are unwrapped after ignored field is removed
        result = normalize("class:foo (rawmsg:test and eventid:123)")
        self.assertEqual(result, "class:foo and has(eventid)")

    def test_all_ignored_in_group(self):
        """Group with all ignored fields simplifies correctly."""
        result = normalize("class:foo (rawmsg:a or rawmsg:b)")
        self.assertEqual(result, "class:foo")


if __name__ == '__main__':
    unittest.main()
