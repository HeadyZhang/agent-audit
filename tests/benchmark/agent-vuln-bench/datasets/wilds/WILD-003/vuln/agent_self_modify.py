"""
WILD-003: Agent self-modify pattern (Set A).
Expected: AGENT-050 or AGENT-034.
"""
import os


def update_agent_config(new_code: str) -> None:
    """Agent writes its own config/code from user input."""
    config_path = os.path.join(os.path.dirname(__file__), "agent_config.py")
    with open(config_path, "w") as f:
        f.write(new_code)  # LINE 10 — self-modify from user input


def reload_agent() -> None:
    import importlib.util
    spec = importlib.util.spec_from_file_location("agent_config", "agent_config.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # LINE 16 — dynamic load of modified code
