"""Tests for TypeScript tool boundary detection.

Validates detection of AI agent tool entry points in TS/JS code:
- MCP SDK tool definitions
- Vercel AI SDK tools
- OpenAI function calling patterns
- LangChain.js tools
- Express/Fastify route handlers
- Scope estimation and boundary containment checks
"""

import pytest

from agent_audit.analysis.ts_tool_boundary_detector import (
    TSToolBoundary,
    TSToolFramework,
    detect_ts_tool_boundaries,
    get_tool_confidence_boost,
    is_within_tool_boundary,
)


# ---------------------------------------------------------------------------
# MCP SDK detection
# ---------------------------------------------------------------------------


class TestMCPToolDetection:
    """Test MCP SDK server.tool() detection."""

    def test_mcp_server_tool(self):
        """server.tool("name", ...) should be detected as MCP tool."""
        code = '''
const server = new Server({ name: "my-server" });

server.tool("get_weather", { city: z.string() }, async ({ city }) => {
    const weather = await fetchWeather(city);
    return { content: [{ type: "text", text: JSON.stringify(weather) }] };
});
'''
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        mcp = boundaries[0]
        assert mcp.framework == TSToolFramework.MCP
        assert mcp.tool_name == "get_weather"
        assert mcp.confidence >= 0.90

    def test_mcp_single_quoted_name(self):
        """server.tool('name') with single quotes should be detected."""
        code = "server.tool('run_query', schema, handler);"
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) == 1
        assert boundaries[0].tool_name == "run_query"

    def test_mcp_multiple_tools(self):
        """Multiple server.tool() calls should all be detected."""
        code = '''
server.tool("tool_a", {}, async () => { return "a"; });
server.tool("tool_b", {}, async () => { return "b"; });
'''
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) == 2
        names = {b.tool_name for b in boundaries}
        assert names == {"tool_a", "tool_b"}


# ---------------------------------------------------------------------------
# Vercel AI SDK detection
# ---------------------------------------------------------------------------


class TestVercelAIToolDetection:
    """Test Vercel AI SDK tool() detection."""

    def test_vercel_ai_tool(self):
        """tool({ description: ..., parameters: ..., execute: ... }) detected."""
        code = '''
const tools = {
    weather: tool({
        description: "Get weather for a city",
        parameters: z.object({ city: z.string() }),
        execute: async ({ city }) => {
            return fetchWeather(city);
        }
    })
};
'''
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].framework == TSToolFramework.VERCEL_AI

    def test_vercel_tool_confidence(self):
        """Vercel AI tool should have >= 0.85 confidence."""
        code = 'const t = tool({ description: "Do thing" });'
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].confidence >= 0.85


# ---------------------------------------------------------------------------
# OpenAI function calling detection
# ---------------------------------------------------------------------------


class TestOpenAIFunctionDetection:
    """Test OpenAI function calling pattern detection."""

    def test_openai_tools_with_type_function(self):
        """tools: [{ type: 'function', ... }] should be detected."""
        code = '''
const completion = await openai.chat.completions.create({
    model: "gpt-4",
    tools: [{ type: "function", function: { name: "search", parameters: {} } }]
});
'''
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].framework == TSToolFramework.OPENAI

    def test_openai_functions_key(self):
        """functions: [{ name: "..." }] should be detected."""
        code = '''
const resp = await client.create({
    functions: [{ name: "lookup_user", parameters: {} }]
});
'''
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].framework == TSToolFramework.OPENAI


# ---------------------------------------------------------------------------
# LangChain.js detection
# ---------------------------------------------------------------------------


class TestLangChainToolDetection:
    """Test LangChain.js class-based tool detection."""

    def test_structured_tool(self):
        """class X extends StructuredTool should be detected."""
        code = '''
class WeatherTool extends StructuredTool {
    name = "weather";
    description = "Get weather";
    async _call(input) {
        return fetchWeather(input.city);
    }
}
'''
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].framework == TSToolFramework.LANGCHAIN_JS
        assert boundaries[0].tool_name == "WeatherTool"

    def test_dynamic_tool(self):
        """class X extends DynamicTool should be detected."""
        code = '''
class ShellRunner extends DynamicTool {
    async _call(input) {
        return exec(input);
    }
}
'''
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].framework == TSToolFramework.LANGCHAIN_JS
        assert boundaries[0].tool_name == "ShellRunner"

    def test_base_tool_extension(self):
        """class X extends Tool should be detected."""
        code = '''
class MyCustomTool extends Tool {
    async _call(input) { return input; }
}
'''
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].framework == TSToolFramework.LANGCHAIN_JS
        assert boundaries[0].tool_name == "MyCustomTool"


# ---------------------------------------------------------------------------
# Express handler detection
# ---------------------------------------------------------------------------


class TestExpressHandlerDetection:
    """Test Express route handler detection."""

    def test_express_post(self):
        """app.post("/api/...", handler) should be detected."""
        code = '''
app.post("/api/execute", async (req, res) => {
    const result = await processCommand(req.body.command);
    res.json({ result });
});
'''
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].framework == TSToolFramework.EXPRESS

    def test_express_get(self):
        """app.get("/path", handler) should be detected."""
        code = 'app.get("/api/users", listUsers);'
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].framework == TSToolFramework.EXPRESS

    def test_express_router(self):
        """router.post() should also be detected."""
        code = 'router.post("/api/data", async (req, res) => { });'
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].framework == TSToolFramework.EXPRESS

    def test_express_lower_confidence(self):
        """Express handlers should have lower confidence than SDK tools."""
        code = 'app.post("/api/run", handler);'
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].confidence < 0.85


# ---------------------------------------------------------------------------
# Fastify handler detection
# ---------------------------------------------------------------------------


class TestFastifyHandlerDetection:
    """Test Fastify route handler detection."""

    def test_fastify_post(self):
        """fastify.post("/path", handler) should be detected."""
        code = '''
fastify.post("/api/execute", async (request, reply) => {
    const result = eval(request.body.code);
    reply.send({ result });
});
'''
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].framework == TSToolFramework.FASTIFY

    def test_server_alias_for_fastify(self):
        """server.post() should match as Fastify."""
        code = 'server.post("/api/run", handler);'
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].framework == TSToolFramework.FASTIFY


# ---------------------------------------------------------------------------
# Scope estimation and boundary containment
# ---------------------------------------------------------------------------


class TestToolBoundaryScope:
    """Test scope estimation and is_within_tool_boundary."""

    def test_is_within_boundary(self):
        """Lines inside tool handler scope should be detected."""
        code = '''
server.tool("exec", {}, async (args) => {
    const cmd = args.command;
    eval(cmd);
});
'''
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        # Line 4 (eval) should be within the tool boundary
        result = is_within_tool_boundary(4, boundaries)
        assert result is not None
        assert result.framework == TSToolFramework.MCP

    def test_outside_boundary(self):
        """Lines outside tool handler scope should not match."""
        code = '''
console.log("hello");

server.tool("exec", {}, async (args) => {
    eval(args.command);
});

console.log("outside");
'''
        boundaries = detect_ts_tool_boundaries(code)
        # Line 2 (before tool) should be outside
        assert is_within_tool_boundary(2, boundaries) is None

    def test_scope_end_after_closing_brace(self):
        """Scope should end at the matching closing brace."""
        code = '''
server.tool("calc", {}, async (args) => {
    if (true) {
        return 1;
    }
});
const x = 1;
'''
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        b = boundaries[0]
        # scope_end should include the closing }); but not "const x = 1;"
        assert b.scope_end <= 6

    def test_no_boundaries_returns_none(self):
        """is_within_tool_boundary returns None with empty list."""
        assert is_within_tool_boundary(5, []) is None


# ---------------------------------------------------------------------------
# Confidence boost
# ---------------------------------------------------------------------------


class TestConfidenceBoost:
    """Test get_tool_confidence_boost values."""

    @pytest.mark.parametrize(
        "framework,expected_boost",
        [
            (TSToolFramework.MCP, 0.10),
            (TSToolFramework.VERCEL_AI, 0.08),
            (TSToolFramework.OPENAI, 0.08),
            (TSToolFramework.LANGCHAIN_JS, 0.10),
            (TSToolFramework.EXPRESS, 0.05),
            (TSToolFramework.FASTIFY, 0.05),
            (TSToolFramework.UNKNOWN, 0.0),
        ],
    )
    def test_boost_values(self, framework, expected_boost):
        """Each framework should return its expected boost."""
        boundary = TSToolBoundary(
            framework=framework,
            tool_name="test",
            line=1,
            confidence=0.90,
            scope_start=1,
            scope_end=10,
        )
        assert get_tool_confidence_boost(boundary) == expected_boost


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Test edge cases and no-match scenarios."""

    def test_empty_content(self):
        """Empty content should produce no boundaries."""
        assert detect_ts_tool_boundaries("") == []

    def test_no_tools_in_code(self):
        """Plain TS code without tools should produce no boundaries."""
        code = '''
function add(a: number, b: number): number {
    return a + b;
}

const greeting = "hello world";
'''
        assert detect_ts_tool_boundaries(code) == []

    def test_comment_containing_tool_pattern(self):
        """Pattern inside a comment is still detected (regex-based)."""
        code = '// server.tool("commented_out", {}, handler);'
        boundaries = detect_ts_tool_boundaries(code)
        # Regex-based detection will match comments; this is expected
        # and acceptable since findings are confidence-gated downstream
        assert len(boundaries) >= 1

    def test_multiline_vercel_tool(self):
        """Vercel tool spanning multiple lines should be detected."""
        code = '''const t = tool({
    description: "multi",
    parameters: z.object({}),
    execute: async () => "ok"
});'''
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        assert boundaries[0].framework == TSToolFramework.VERCEL_AI

    def test_tool_boundary_is_frozen(self):
        """TSToolBoundary instances should be immutable."""
        code = 'server.tool("immutable_check", {}, handler);'
        boundaries = detect_ts_tool_boundaries(code)
        assert len(boundaries) >= 1
        with pytest.raises(AttributeError):
            boundaries[0].tool_name = "mutated"  # type: ignore[misc]
