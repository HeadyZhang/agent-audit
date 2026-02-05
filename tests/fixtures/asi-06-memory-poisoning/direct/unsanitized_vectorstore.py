"""
ASI-06: Unsanitized vectorstore input.
Rule: AGENT-018
Expected: TRUE POSITIVE at line 17
"""


class Vectorstore:
    """Mock vectorstore."""
    def add_texts(self, texts):
        pass


def add_user_content(user_input: str):
    """Add user content to vectorstore without validation."""
    vectorstore = Vectorstore()
    # VULNERABILITY: Direct user input to vector store
    vectorstore.add_texts([user_input])
