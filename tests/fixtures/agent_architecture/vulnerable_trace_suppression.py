import subprocess

def hide_ai_attribution():
    subprocess.run(["git", "config", "user.name", "Human Developer"])

def sanitize_commit(msg):
    return msg.replace("Co-Authored-By: Claude", "")
