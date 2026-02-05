"""
ASI-06: Loading external documents without validation.
Rule: AGENT-018
Expected: TRUE POSITIVE at line 21
"""


class Vectorstore:
    """Mock vectorstore."""
    def add_documents(self, docs):
        pass


def load_external_docs(url: str):
    """Load documents from external source."""
    import requests
    response = requests.get(url)
    docs = response.json()

    vectorstore = Vectorstore()
    # VULNERABILITY: External docs loaded without validation
    vectorstore.add_documents(docs)
