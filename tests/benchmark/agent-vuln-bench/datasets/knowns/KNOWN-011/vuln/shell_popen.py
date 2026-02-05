"""
subprocess.Popen(cmd, shell=True) with user input.
Set A | ASI-02 | CWE-78
"""
import subprocess


def run_command(cmd: str) -> str:
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # LINE 8
    out, _ = p.communicate()
    return out.decode()
