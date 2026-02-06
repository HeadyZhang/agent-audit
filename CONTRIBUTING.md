# Contributing to Agent Audit

Thank you for your interest in contributing to agent-audit! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Adding Rules](#adding-rules)
- [Style Guide](#style-guide)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this code.

---

## Getting Started

### Good First Issues

Look for issues labeled [`good first issue`](https://github.com/HeadyZhang/agent-audit/labels/good%20first%20issue) — these are beginner-friendly tasks.

### Types of Contributions

| Type | Description |
|------|-------------|
| **Bug Fixes** | Fix incorrect behavior or crashes |
| **New Rules** | Add detection rules for new vulnerability patterns |
| **Documentation** | Improve docs, fix typos, add examples |
| **Tests** | Add test coverage for existing features |
| **Features** | Add new capabilities (discuss first in an issue) |

---

## Development Setup

### Prerequisites

- Python 3.9+
- Poetry 1.8+
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/HeadyZhang/agent-audit.git
cd agent-audit

# Install dependencies
cd packages/audit
poetry install

# Verify installation
poetry run agent-audit --version
```

### Running Tests

```bash
# Run all tests
poetry run pytest ../../tests/ -v

# Run with coverage
poetry run pytest ../../tests/ -v --cov=agent_audit --cov-report=term-missing

# Run specific test file
poetry run pytest ../../tests/test_scanners/test_python_scanner.py -v
```

### Type Checking

```bash
poetry run mypy agent_audit/
```

### Linting

```bash
poetry run ruff check .
poetry run black --check .
```

---

## Making Changes

### Workflow

1. **Fork** the repository
2. **Create a branch** from `master`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
3. **Make changes** following the style guide
4. **Test** your changes
5. **Commit** with conventional commit messages
6. **Push** to your fork
7. **Open a Pull Request**

### Branch Naming

| Prefix | Use Case |
|--------|----------|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `docs/` | Documentation changes |
| `test/` | Test additions |
| `refactor/` | Code restructuring |

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add AGENT-054 rule for unsafe deserialization
fix: correct false positive in AGENT-004 for Pydantic fields
docs: update RULES.md with new CWE mappings
test: add fixtures for MCP config validation
```

---

## Testing

### Test Structure

```
tests/
├── fixtures/              # Test input files
│   ├── vulnerable_agents/ # Python files with known vulnerabilities
│   └── mcp_configs/       # MCP config test cases
├── test_scanners/         # Scanner unit tests
├── test_cli/              # CLI command tests
├── test_analysis/         # Semantic analysis tests
└── benchmark/             # Accuracy benchmarks
```

### Writing Tests

Every new rule or feature needs tests:

```python
# tests/test_scanners/test_your_rule.py
import pytest
from agent_audit.scanners.python_scanner import PythonScanner

class TestYourRule:
    def test_detects_vulnerability(self, tmp_path):
        """Rule should detect the vulnerable pattern."""
        code = """
@tool
def vulnerable_function(input: str):
    eval(input)  # Should trigger AGENT-XXX
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(test_file)

        assert any(r.pattern_type == "your_pattern" for r in results)

    def test_no_false_positive(self, tmp_path):
        """Rule should not flag safe code."""
        code = """
@tool
def safe_function(input: str):
    return input.upper()  # Should NOT trigger
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        scanner = PythonScanner()
        results = scanner.scan(test_file)

        assert not any(r.pattern_type == "your_pattern" for r in results)
```

---

## Submitting Changes

### Pull Request Checklist

- [ ] Tests pass (`poetry run pytest`)
- [ ] Type checks pass (`poetry run mypy agent_audit/`)
- [ ] Linting passes (`poetry run ruff check .`)
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated (for user-facing changes)
- [ ] Commit messages follow conventional commits

### PR Description Template

```markdown
## Summary
Brief description of changes.

## Changes
- Added X
- Fixed Y
- Updated Z

## Testing
How did you test these changes?

## Related Issues
Fixes #123
```

---

## Adding Rules

### Rule Development Workflow

1. **Create YAML definition** in `rules/builtin/`
2. **Implement detection** in the appropriate scanner
3. **Add test fixtures** in `tests/fixtures/`
4. **Write tests** in `tests/test_scanners/`
5. **Update documentation** in `docs/RULES.md`

### Rule ID Assignment

- Use the next available AGENT-XXX number
- Check existing rules to avoid conflicts
- Rule IDs are permanent once assigned

---

## Style Guide

### Python

- **Formatter**: Black (line length 100)
- **Linter**: Ruff
- **Type hints**: Required on all public functions
- **Docstrings**: Google style for public methods

### YAML Rules

- Use 2-space indentation
- Quote strings with special characters
- Include all required fields

### Documentation

- Use GitHub-flavored Markdown
- Include code examples
- Keep line length under 100 characters

---

## Questions?

- Open a [Discussion](https://github.com/HeadyZhang/agent-audit/discussions)
- Check existing [Issues](https://github.com/HeadyZhang/agent-audit/issues)
- Read the [Architecture docs](docs/ARCHITECTURE.md)

---

*Thank you for contributing to agent-audit!*
