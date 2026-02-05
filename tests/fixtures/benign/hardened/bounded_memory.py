"""
BENIGN: Properly bounded conversation memory with window limits.
Expected: NO FINDINGS (any detection is FALSE POSITIVE)

This file demonstrates SAFE memory patterns:
- ConversationBufferWindowMemory with k parameter (sliding window)
- Explicit message limits and TTL
"""


class ConversationBufferWindowMemory:
    """Mock ConversationBufferWindowMemory - SAFE pattern with window limit."""
    def __init__(self, k: int = 10, **kwargs):
        self.k = k  # Window size limit
        self.config = kwargs
        self.messages = []
    
    def add_message(self, message: str) -> None:
        """Add message with automatic window pruning."""
        self.messages.append(message)
        # SAFE: Automatic pruning to window size
        if len(self.messages) > self.k:
            self.messages = self.messages[-self.k:]


class ConversationSummaryMemory:
    """Mock ConversationSummaryMemory - SAFE pattern with summarization."""
    def __init__(self, max_token_limit: int = 2000, **kwargs):
        self.max_token_limit = max_token_limit
        self.config = kwargs


def create_safe_window_memory():
    """Create memory with sliding window limit."""
    # SAFE: Using window memory with explicit k limit
    memory = ConversationBufferWindowMemory(k=10)
    return memory


def create_safe_summary_memory():
    """Create memory with summarization and token limit."""
    # SAFE: Using summary memory with token limit
    memory = ConversationSummaryMemory(max_token_limit=2000)
    return memory
