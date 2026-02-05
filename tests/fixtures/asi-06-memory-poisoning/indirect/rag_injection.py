"""
ASI-06: RAG injection vulnerability.
Rule: AGENT-018
Expected: TRUE POSITIVE at line 17
owasp_id: ASI-06
"""
from langchain.vectorstores import FAISS
from langchain.embeddings import OpenAIEmbeddings


def ingest_user_document(vectorstore: FAISS, user_doc: str):
    """Ingest user document to RAG - injection risk."""
    # VULNERABILITY: Unsanitized document to vector store
    vectorstore.add_texts([user_doc])
