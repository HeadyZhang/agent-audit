"""Fixed: list args, shell=False."""
import subprocess
import shlex


def run_command(cmd: str) -> str:
    args = shlex.split(cmd) if isinstance(cmd, str) else cmd
    result = subprocess.run(args, shell=False, capture_output=True, text=True)
    return result.stdout
