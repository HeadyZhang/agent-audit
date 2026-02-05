"""
Vuln: CDP browser automation without sandbox.
Expected: AGENT-045.
"""
from playwright.sync_api import sync_playwright


def capture_page(url: str):
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])  # LINE 8
        page = browser.new_page()
        page.goto(url)
        result = page.evaluate("() => document.cookie")  # LINE 11
        browser.close()
        return result
