import threading

def agent_loop():
    while True:
        process_tasks()

thread = threading.Thread(target=agent_loop, daemon=True)
thread.start()
