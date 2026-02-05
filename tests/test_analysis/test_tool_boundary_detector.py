"""Tests for Tool Boundary Detector - v0.11.0/v0.12.0 semantic layer.

Tests the GATE for AGENT-034:
- @tool decorator identifies entry point
- Regular functions are NOT entry points (no blacklist needed)
- BaseTool._run() is an entry point

v0.12.0: Tests for OpenAI function calling detection:
- Functions passed to tools=[...] parameter are entry points
- @function_schema, @openai_function decorators are entry points
"""

import ast
import pytest

from agent_audit.analysis.tool_boundary_detector import (
    is_tool_entry_point,
    analyze_file_tool_context,
    FileToolContext,
    ToolBoundaryResult,
    TOOL_DECORATORS,
    TOOL_CLASS_METHODS,
    TOOL_BASE_CLASSES,
    FUNCTION_CALLING_DECORATORS,
)


class TestToolEntryPointDetection:
    """Test the main gate for AGENT-034."""

    def test_tool_decorator_is_entry_point(self):
        """@tool decorator should identify entry point."""
        source = '''
@tool
def my_tool(query: str) -> str:
    return query
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(node)
        assert result.is_tool_entry is True
        assert '@tool' in result.reason
        assert result.confidence >= 0.9

    def test_tool_with_args_is_entry_point(self):
        """@tool(...) with arguments should identify entry point."""
        source = '''
@tool(return_direct=True)
def my_tool(query: str) -> str:
    return query
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(node)
        assert result.is_tool_entry is True

    def test_regular_function_not_entry_point(self):
        """Regular function is NOT entry point - no blacklist needed."""
        source = '''
def process_data(data: str) -> str:
    return asyncio.run(async_process(data))
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(node)
        assert result.is_tool_entry is False
        assert 'Not a Tool' in result.reason

    def test_asyncio_function_not_entry_point(self):
        """Functions using asyncio.run() are NOT entry points."""
        source = '''
async def main():
    result = await asyncio.gather(task1(), task2())
    return result

def run_main():
    asyncio.run(main())
'''
        tree = ast.parse(source)
        # Check run_main function
        node = tree.body[1]
        result = is_tool_entry_point(node)
        assert result.is_tool_entry is False

    def test_function_tool_decorator_is_entry_point(self):
        """@function_tool (LlamaIndex) should identify entry point."""
        source = '''
@function_tool
def search_docs(query: str) -> str:
    return docs.search(query)
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(node)
        assert result.is_tool_entry is True

    def test_kernel_function_decorator_is_entry_point(self):
        """@kernel_function (Semantic Kernel) should identify entry point."""
        source = '''
@kernel_function
def search(query: str) -> str:
    return results
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(node)
        assert result.is_tool_entry is True


class TestBaseTool:
    """Test BaseTool class method detection."""

    def test_run_in_tool_class_is_entry_point(self):
        """_run() method in Tool class should be entry point."""
        source = '''
def _run(self, query: str) -> str:
    return subprocess.run(query)
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(
            node,
            parent_class='MyTool',
            parent_bases={'BaseTool'}
        )
        assert result.is_tool_entry is True
        assert result.tool_type == 'class_method'

    def test_arun_in_tool_class_is_entry_point(self):
        """_arun() method in Tool class should be entry point."""
        source = '''
async def _arun(self, query: str) -> str:
    return await subprocess.run(query)
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(
            node,
            parent_class='MyTool',
            parent_bases={'StructuredTool'}
        )
        assert result.is_tool_entry is True

    def test_run_outside_tool_class_not_entry_point(self):
        """_run() method NOT in Tool class should NOT be entry point."""
        source = '''
def _run(self, data: str) -> str:
    return data.process()
'''
        tree = ast.parse(source)
        node = tree.body[0]
        # No parent class or wrong base
        result = is_tool_entry_point(node, parent_class='DataProcessor', parent_bases={'object'})
        assert result.is_tool_entry is False


class TestNameHeuristic:
    """Test weak name-based heuristic."""

    def test_tool_in_name_with_str_param_is_entry_point(self):
        """Function with 'tool' in name AND str param is weak entry point."""
        source = '''
def my_shell_tool(command: str) -> str:
    return subprocess.run(command)
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(node)
        # Weak heuristic - should be entry point but low confidence
        assert result.is_tool_entry is True
        assert result.confidence < 0.8  # Lower confidence for name heuristic

    def test_tool_in_name_without_str_param_not_entry_point(self):
        """Function with 'tool' in name but no str param is NOT entry point."""
        source = '''
def my_math_tool(x: int, y: int) -> int:
    return x + y
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(node)
        assert result.is_tool_entry is False


class TestNoBlacklistNeeded:
    """Test that we don't need SAFE_BUILTIN_CALLS blacklist."""

    def test_asyncio_run_in_regular_function_skipped(self):
        """asyncio.run() in regular function - skip without blacklist."""
        source = '''
def main():
    asyncio.run(async_main())
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(node)
        # NOT entry point - no need to check asyncio.run at all
        assert result.is_tool_entry is False

    def test_re_compile_in_regular_function_skipped(self):
        """re.compile() in regular function - skip without blacklist."""
        source = '''
def validate_pattern(pattern: str) -> bool:
    return re.compile(pattern).match(data)
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(node)
        # NOT entry point - no need to check re.compile at all
        assert result.is_tool_entry is False

    def test_subprocess_in_tool_should_be_checked(self):
        """subprocess.run() in @tool function SHOULD trigger checks."""
        source = '''
@tool
def shell_tool(command: str) -> str:
    return subprocess.run(command, shell=True).stdout
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(node)
        # IS entry point - SHOULD be checked for dangerous operations
        assert result.is_tool_entry is True


class TestOpenAIFunctionCalling:
    """v0.12.0: Test OpenAI function calling pattern detection."""

    def test_function_registered_in_tools(self):
        """Function passed to tools=[...] should be detected as tool."""
        source = '''
import openai

def get_weather(location: str) -> str:
    return f"Weather in {location}"

client.chat.completions.create(
    model="gpt-4",
    tools=[get_weather],
)
'''
        tree = ast.parse(source)
        ctx = analyze_file_tool_context(tree, {'openai'})

        assert ctx.has_openai_import is True
        assert ctx.has_function_calling_api is True
        assert 'get_weather' in ctx.registered_tool_functions

    def test_multiple_functions_in_tools(self):
        """Multiple functions in tools=[...] should all be detected."""
        source = '''
import openai

def func1(x: str) -> str:
    return x

def func2(y: str) -> str:
    return y

def helper():
    pass

client.chat.completions.create(
    model="gpt-4",
    tools=[func1, func2],
)
'''
        tree = ast.parse(source)
        ctx = analyze_file_tool_context(tree, {'openai'})

        assert 'func1' in ctx.registered_tool_functions
        assert 'func2' in ctx.registered_tool_functions
        assert 'helper' not in ctx.registered_tool_functions

    def test_function_not_in_tools_not_detected(self):
        """Functions NOT in tools=[...] should NOT be detected."""
        source = '''
import openai

def helper():
    pass

def get_weather(location: str) -> str:
    return f"Weather in {location}"

client.chat.completions.create(
    model="gpt-4",
    tools=[get_weather],
)
'''
        tree = ast.parse(source)
        ctx = analyze_file_tool_context(tree, {'openai'})

        assert 'get_weather' in ctx.registered_tool_functions
        assert 'helper' not in ctx.registered_tool_functions

    def test_is_tool_entry_with_file_context(self):
        """is_tool_entry_point should detect OpenAI function with file_context."""
        ctx = FileToolContext(
            has_openai_import=True,
            has_function_calling_api=True,
            registered_tool_functions={'get_weather'},
        )

        source = '''
def get_weather(location: str) -> str:
    return subprocess.run(location, shell=True)
'''
        tree = ast.parse(source)
        func_node = tree.body[0]

        result = is_tool_entry_point(func_node, file_context=ctx)
        assert result.is_tool_entry is True
        assert result.tool_type == 'openai_function'

    def test_no_function_calling_api_no_detection(self):
        """Without function calling API, functions are not detected."""
        source = '''
import openai

def my_func(x: str):
    return x

# No API call
'''
        tree = ast.parse(source)
        ctx = analyze_file_tool_context(tree, {'openai'})

        assert ctx.has_openai_import is True
        assert ctx.has_function_calling_api is False
        assert len(ctx.registered_tool_functions) == 0

    def test_dict_tools_format(self):
        """Tools as dict format with 'name' key should be detected."""
        source = '''
import openai

client.chat.completions.create(
    model="gpt-4",
    tools=[{"name": "get_weather", "description": "Get weather"}],
)
'''
        tree = ast.parse(source)
        ctx = analyze_file_tool_context(tree, {'openai'})

        assert ctx.has_function_calling_api is True
        assert 'get_weather' in ctx.registered_tool_functions

    def test_anthropic_messages_create(self):
        """Anthropic messages.create should be detected."""
        source = '''
import anthropic

def my_tool(x: str) -> str:
    return x

client.messages.create(
    model="claude-3",
    tools=[my_tool],
)
'''
        tree = ast.parse(source)
        ctx = analyze_file_tool_context(tree, {'anthropic'})

        assert ctx.has_anthropic_import is True
        assert ctx.has_function_calling_api is True
        assert 'my_tool' in ctx.registered_tool_functions

    def test_wrapped_function_in_tools(self):
        """Functions wrapped in calls within tools=[] should be detected."""
        source = '''
import openai

def raw_func(x: str) -> str:
    return x

client.chat.completions.create(
    model="gpt-4",
    tools=[some_wrapper(raw_func)],
)
'''
        tree = ast.parse(source)
        ctx = analyze_file_tool_context(tree, {'openai'})

        assert 'raw_func' in ctx.registered_tool_functions


class TestFunctionCallingDecorators:
    """v0.12.0: Test function calling decorator detection."""

    def test_function_schema_decorator(self):
        """@function_schema decorator should be detected."""
        source = '''
@function_schema
def my_tool(query: str) -> str:
    return query
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(node)
        assert result.is_tool_entry is True
        assert result.tool_type == 'function_calling_decorator'

    def test_openai_function_decorator(self):
        """@openai_function decorator should be detected."""
        source = '''
@openai_function
def search(query: str) -> str:
    return results
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(node)
        assert result.is_tool_entry is True

    def test_tool_function_decorator(self):
        """@tool_function decorator should be detected."""
        source = '''
@tool_function
def execute(cmd: str) -> str:
    return subprocess.run(cmd)
'''
        tree = ast.parse(source)
        node = tree.body[0]
        result = is_tool_entry_point(node)
        assert result.is_tool_entry is True


class TestFileToolContextIntegration:
    """Test full integration of file tool context analysis."""

    def test_openai_function_with_dangerous_operation(self):
        """OpenAI function with eval should be detectable as tool entry."""
        source = '''
import openai

def code_executor(code: str) -> str:
    return eval(code)

response = client.chat.completions.create(
    model="gpt-4",
    tools=[code_executor],
)
'''
        tree = ast.parse(source)
        ctx = analyze_file_tool_context(tree, {'openai'})

        # Find the code_executor function
        func_node = tree.body[1]  # Second item is the function def
        assert func_node.name == 'code_executor'

        result = is_tool_entry_point(func_node, file_context=ctx)
        assert result.is_tool_entry is True
        assert result.tool_type == 'openai_function'
        assert result.confidence >= 0.8

    def test_regular_function_with_openai_import_but_no_registration(self):
        """Function not registered in tools=[] should NOT be detected."""
        source = '''
import openai

def helper(x: str) -> str:
    return x

def tool_func(y: str) -> str:
    return y

client.chat.completions.create(
    model="gpt-4",
    tools=[tool_func],  # Only tool_func is registered
)
'''
        tree = ast.parse(source)
        ctx = analyze_file_tool_context(tree, {'openai'})

        # helper function - NOT registered
        helper_node = tree.body[1]
        assert helper_node.name == 'helper'
        result_helper = is_tool_entry_point(helper_node, file_context=ctx)
        assert result_helper.is_tool_entry is False

        # tool_func - IS registered
        tool_node = tree.body[2]
        assert tool_node.name == 'tool_func'
        result_tool = is_tool_entry_point(tool_node, file_context=ctx)
        assert result_tool.is_tool_entry is True
