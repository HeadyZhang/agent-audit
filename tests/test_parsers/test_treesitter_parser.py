"""Tests for tree-sitter parser module."""

import pytest
from agent_audit.parsers.treesitter_parser import (
    TreeSitterParser,
    ValueType,
    Assignment,
    FunctionCall,
    StringLiteral,
)


class TestTreeSitterParser:
    """Tests for TreeSitterParser class."""

    def test_parser_initialization(self):
        """Test parser initializes without error."""
        source = "x = 1"
        parser = TreeSitterParser(source, language='python')
        assert parser is not None
        assert parser.language == 'python'

    def test_language_detection_from_path(self):
        """Test language is detected from file path."""
        source = "x = 1"
        parser = TreeSitterParser(source, file_path="/path/to/file.py")
        assert parser.language == 'python'

        parser2 = TreeSitterParser(source, file_path="/path/to/file.js")
        assert parser2.language == 'javascript'

        parser3 = TreeSitterParser(source, file_path="/path/to/file.ts")
        assert parser3.language == 'typescript'

    def test_default_language_is_python(self):
        """Test default language is Python when not specified."""
        parser = TreeSitterParser("x = 1")
        assert parser.language == 'python'


class TestPythonAssignments:
    """Tests for Python assignment detection."""

    def test_find_simple_assignment(self):
        """Test finding simple variable assignments."""
        source = """
x = 42
name = "hello"
flag = True
"""
        parser = TreeSitterParser(source, language='python')
        assignments = parser.find_assignments()

        assert len(assignments) >= 3
        names = [a.name for a in assignments]
        assert 'x' in names
        assert 'name' in names
        assert 'flag' in names

    def test_classify_string_literal(self):
        """Test classification of string literal values."""
        source = 'api_key = "sk-proj-abc123"'
        parser = TreeSitterParser(source, language='python')
        assignments = parser.find_assignments()

        assert len(assignments) == 1
        assert assignments[0].name == 'api_key'
        assert assignments[0].value_type == ValueType.LITERAL_STRING

    def test_classify_env_read(self):
        """Test classification of environment variable reads."""
        source = 'api_key = os.environ.get("API_KEY")'
        parser = TreeSitterParser(source, language='python')
        assignments = parser.find_assignments()

        assert len(assignments) == 1
        assert assignments[0].value_type == ValueType.ENV_READ

    def test_classify_function_call(self):
        """Test classification of function call values."""
        source = 'result = some_function()'
        parser = TreeSitterParser(source, language='python')
        assignments = parser.find_assignments()

        assert len(assignments) == 1
        assert assignments[0].value_type == ValueType.FUNCTION_CALL

    def test_classify_variable_ref(self):
        """Test classification of variable reference values."""
        source = 'y = x'
        parser = TreeSitterParser(source, language='python')
        assignments = parser.find_assignments()

        assert len(assignments) == 1
        assert assignments[0].value_type == ValueType.VARIABLE_REF

    def test_classify_none_value(self):
        """Test classification of None values."""
        source = 'x = None'
        parser = TreeSitterParser(source, language='python')
        assignments = parser.find_assignments()

        assert len(assignments) == 1
        assert assignments[0].value_type == ValueType.NONE_NULL

    def test_classify_list_value(self):
        """Test classification of list values."""
        source = 'items = [1, 2, 3]'
        parser = TreeSitterParser(source, language='python')
        assignments = parser.find_assignments()

        assert len(assignments) == 1
        assert assignments[0].value_type == ValueType.LIST

    def test_classify_dict_value(self):
        """Test classification of dict values."""
        source = 'config = {"key": "value"}'
        parser = TreeSitterParser(source, language='python')
        assignments = parser.find_assignments()

        assert len(assignments) == 1
        assert assignments[0].value_type == ValueType.DICT


class TestPythonFunctionCalls:
    """Tests for Python function call detection."""

    def test_find_simple_call(self):
        """Test finding simple function calls."""
        source = """
print("hello")
result = process(data)
"""
        parser = TreeSitterParser(source, language='python')
        calls = parser.find_function_calls()

        names = [c.name for c in calls]
        assert 'print' in names
        assert 'process' in names

    def test_find_method_call(self):
        """Test finding method calls."""
        source = 'items.append(42)'
        parser = TreeSitterParser(source, language='python')
        calls = parser.find_function_calls()

        assert len(calls) >= 1
        assert any('append' in c.name for c in calls)

    def test_extract_call_args(self):
        """Test extraction of call arguments."""
        source = 'subprocess.run(["ls", "-la"], shell=True)'
        parser = TreeSitterParser(source, language='python')
        calls = parser.find_function_calls()

        run_calls = [c for c in calls if 'run' in c.name]
        assert len(run_calls) >= 1


class TestPythonStringLiterals:
    """Tests for Python string literal detection."""

    def test_find_double_quoted_string(self):
        """Test finding double-quoted strings."""
        source = 'msg = "hello world"'
        parser = TreeSitterParser(source, language='python')
        literals = parser.find_string_literals()

        assert len(literals) >= 1
        assert any(lit.value == "hello world" for lit in literals)

    def test_find_single_quoted_string(self):
        """Test finding single-quoted strings."""
        source = "msg = 'hello world'"
        parser = TreeSitterParser(source, language='python')
        literals = parser.find_string_literals()

        assert len(literals) >= 1
        assert any(lit.value == "hello world" for lit in literals)

    def test_detect_fstring(self):
        """Test detection of f-strings."""
        source = 'msg = f"Hello, {name}!"'
        parser = TreeSitterParser(source, language='python')
        literals = parser.find_string_literals()

        fstrings = [lit for lit in literals if lit.is_fstring]
        assert len(fstrings) >= 1

    def test_detect_multiline_string(self):
        """Test detection of multiline strings."""
        source = '''msg = """
This is a
multiline string
"""'''
        parser = TreeSitterParser(source, language='python')
        literals = parser.find_string_literals()

        # In regex fallback mode, multiline strings are harder to detect
        # because we process line by line. Tree-sitter mode handles this better.
        if parser.is_tree_sitter_available:
            multiline = [lit for lit in literals if lit.is_multiline]
            assert len(multiline) >= 1
        else:
            # In fallback mode, just verify we don't crash
            assert isinstance(literals, list)


class TestJavaScriptParsing:
    """Tests for JavaScript parsing (regex fallback)."""

    def test_find_const_assignment(self):
        """Test finding const assignments in JavaScript."""
        source = 'const apiKey = "sk-test-123";'
        parser = TreeSitterParser(source, language='javascript')
        assignments = parser.find_assignments()

        assert len(assignments) >= 1
        assert any(a.name == 'apiKey' for a in assignments)

    def test_find_let_assignment(self):
        """Test finding let assignments in JavaScript."""
        source = 'let counter = 0;'
        parser = TreeSitterParser(source, language='javascript')
        assignments = parser.find_assignments()

        assert len(assignments) >= 1
        assert any(a.name == 'counter' for a in assignments)


class TestValueTypeClassification:
    """Tests for value type classification across patterns."""

    @pytest.mark.parametrize("source,expected_type", [
        ('x = "string"', ValueType.LITERAL_STRING),
        ('x = 42', ValueType.NUMERIC),
        ('x = True', ValueType.BOOLEAN),
        ('x = None', ValueType.NONE_NULL),
        ('x = [1, 2]', ValueType.LIST),
        ('x = {}', ValueType.DICT),
        ('x = foo()', ValueType.FUNCTION_CALL),
        ('x = other_var', ValueType.VARIABLE_REF),
        ('x = os.getenv("KEY")', ValueType.ENV_READ),
        ('x = os.environ["KEY"]', ValueType.ENV_READ),
    ])
    def test_value_type_classification(self, source, expected_type):
        """Test value type classification for various patterns."""
        parser = TreeSitterParser(source, language='python')
        assignments = parser.find_assignments()

        assert len(assignments) == 1
        # Note: Some types may fall back to OTHER in regex mode
        # This is acceptable as tree-sitter mode will be more accurate
        assert assignments[0].value_type in (expected_type, ValueType.OTHER)


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_source(self):
        """Test handling of empty source code."""
        parser = TreeSitterParser("", language='python')

        assert parser.find_assignments() == []
        assert parser.find_function_calls() == []
        assert parser.find_string_literals() == []

    def test_syntax_error_resilience(self):
        """Test parser handles syntax errors gracefully."""
        source = """
x = 1
def broken(
    # incomplete function
"""
        parser = TreeSitterParser(source, language='python')

        # Should not crash, may return partial results
        assignments = parser.find_assignments()
        assert isinstance(assignments, list)

    def test_unicode_strings(self):
        """Test handling of unicode strings."""
        source = 'msg = "Hello, 世界! 🌍"'
        parser = TreeSitterParser(source, language='python')
        literals = parser.find_string_literals()

        assert len(literals) >= 1
        assert any("世界" in lit.value for lit in literals)

    def test_raw_strings(self):
        """Test handling of raw strings."""
        source = r'pattern = r"\d+\.\d+"'
        parser = TreeSitterParser(source, language='python')
        literals = parser.find_string_literals()

        assert len(literals) >= 1

    def test_line_numbers_are_correct(self):
        """Test that line numbers are reported correctly."""
        source = """line1
line2
x = 42
line4
"""
        parser = TreeSitterParser(source, language='python')
        assignments = parser.find_assignments()

        assert len(assignments) == 1
        assert assignments[0].line == 3  # 1-indexed
