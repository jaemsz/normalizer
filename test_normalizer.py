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
        self.assertEqual(
            normalize("class:ms_windows_event srcipv4:$exclusions.global.srcipv4"),
            "class:ms_windows_event and has(srcipv4)"
        )

    def test_multiple_variables(self):
        self.assertEqual(
            normalize("class:ms_windows_event srcip:$vars.ip dstip:$vars.target"),
            "class:ms_windows_event and has(srcip) and has(dstip)"
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
        self.assertEqual(
            normalize("class:ms_windows_event (rawmsg:/pattern/ or eventid:123)"),
            "class:ms_windows_event and (has(eventid))"
        )


class TestFunctionCalls(unittest.TestCase):
    """Test function call syntax."""

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


class TestComplexRules(unittest.TestCase):
    """Test complex combined rules."""

    def test_complex_combined(self):
        result = normalize(
            "metaclass:windows eventid=[1,2,3] (msg:/(service name:|the)\\s+(asdf|back|usb)\\s+service/ OR serviceid=['asdf','wer','oiuouo']) NOT srcipv4:$exclusions.global.srcipv4"
        )
        self.assertEqual(
            result,
            "metaclass:windows and has(eventid) and (has(msg) or has(serviceid)) and has(srcipv4)"
        )

    def test_complex_with_missing_and_multiple_not(self):
        result = normalize(
            "metaclass:http_proxy dstport=[80,443] missing:referrer useragent=\"Google\" NOT domain:'*.google.com' NOT dstdomain=google.com NOT rawmsg:\"*Google\" NOT srcipv4:$exclusions.global.srcipv4"
        )
        self.assertEqual(
            result,
            "metaclass:http_proxy and has(dstport) and has(referrer) and has(useragent) and has(domain) and has(dstdomain) and has(srcipv4)"
        )


if __name__ == '__main__':
    unittest.main()
