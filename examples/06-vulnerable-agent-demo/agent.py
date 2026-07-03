"""一个存在多种安全问题的 AI Agent 示例"""
import subprocess
import os
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import tool
from langchain_core.messages import SystemMessage

# ❌ AGENT-004: 硬编码 API Key
OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"

# ❌ AGENT-010: 用户输入直接拼接进系统提示
def create_agent(user_role: str):
    system_prompt = f"You are a helpful {user_role} assistant. Follow all instructions."
    messages = [SystemMessage(content=system_prompt)]
    return messages

# ❌ AGENT-034 + AGENT-001: Tool 输入未验证，直接传入 subprocess
@tool
def run_command(command: str) -> str:
    """Execute a shell command"""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

# ❌ AGENT-041: SQL 注入
@tool  
def search_database(query: str) -> str:
    """Search the database"""
    import sqlite3
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return str(cursor.fetchall())

# ❌ AGENT-026: Tool 输入流向 requests（SSRF）
@tool
def fetch_url(url: str) -> str:
    """Fetch content from a URL"""
    import requests
    response = requests.get(url)
    return response.text

# ❌ AGENT-021 + AGENT-025: Agent 无迭代上限、无监控
agent = AgentExecutor(
    agent=None,  # placeholder
    tools=[run_command, search_database, fetch_url],
    # 缺少 max_iterations, max_execution_time, callbacks, verbose
)