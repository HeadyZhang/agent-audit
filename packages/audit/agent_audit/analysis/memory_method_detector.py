"""
Agent Memory Method Detection for AGENT-018.

v0.11.0: Core principle - Use a WHITELIST of known Agent memory methods.
No variable name guessing - only specific method identification.

v0.12.0: For ambiguous methods (like 'insert'), add import checking.
- list.insert() should NOT trigger (no llama_index import)
- index.insert() SHOULD trigger (has llama_index import)

This is the GATE for AGENT-018:
- If is_agent_memory_method() returns False, skip ALL further checks
- Python's set.add(), list.append() are NOT in this whitelist
"""

from __future__ import annotations

from typing import Dict, Tuple, Optional, Set


# UNAMBIGUOUS methods - directly trigger, no import check needed
# These are method names unique to Agent memory frameworks
UNAMBIGUOUS_MEMORY_METHODS: Dict[str, str] = {
    # LangChain Memory
    'add_message': 'langchain',
    'add_user_message': 'langchain',
    'add_ai_message': 'langchain',
    'add_messages': 'langchain',
    'save_context': 'langchain',
    'add_memory': 'langchain',

    # Vector Stores (common to multiple frameworks)
    'add_texts': 'vector_store',
    'add_documents': 'vector_store',
    'aadd_texts': 'vector_store',
    'aadd_documents': 'vector_store',

    # LlamaIndex (unambiguous methods)
    'insert_nodes': 'llama_index',

    # CrewAI
    'add_to_memory': 'crewai',

    # Haystack
    'write_documents': 'haystack',

    # Generic patterns that are ALWAYS Agent memory (not Python builtins)
    'store_memory': 'generic',
    'persist_memory': 'generic',
    'save_memory': 'generic',
    'update_memory': 'generic',
    'update_context': 'generic',
}

# AMBIGUOUS methods - require import check
# These methods have the same name as Python builtins or common operations
# Format: method_name -> (framework, required_import_keywords)
AMBIGUOUS_MEMORY_METHODS: Dict[str, Tuple[str, Set[str]]] = {
    # 'insert' - Python list.insert() vs LlamaIndex index.insert()
    'insert': ('llama_index', {'llama_index', 'llama-index', 'llamaindex'}),
    # 'upsert' - vector database operation, but also used in general DB code
    'upsert': ('vector_store', {'pinecone', 'chromadb', 'weaviate', 'qdrant', 'milvus', 'faiss'}),
}

# Methods that are DEFINITELY NOT Agent memory operations
# These are Python builtins that should NEVER trigger AGENT-018
PYTHON_BUILTIN_METHODS: Set[str] = {
    'add',       # set.add()
    'append',    # list.append()
    'extend',    # list.extend()
    'update',    # dict.update(), set.update()
    'put',       # queue.put()
    'push',      # not a Python builtin, but common in stack implementations
    'set',       # dict.set() or similar
}

# Combined for backward compatibility
# v0.11.0 used AGENT_MEMORY_WRITE_METHODS - keep for API compatibility
AGENT_MEMORY_WRITE_METHODS: Dict[str, str] = {
    **UNAMBIGUOUS_MEMORY_METHODS,
    **{k: v[0] for k, v in AMBIGUOUS_MEMORY_METHODS.items()},
}


def is_agent_memory_method(
    method_name: str,
    file_imports: Optional[Set[str]] = None,
) -> Tuple[bool, str]:
    """
    Check if a method is a known Agent memory write operation.

    v0.12.0: For ambiguous methods, check file_imports to distinguish
    Python builtins from framework operations.

    Args:
        method_name: Name of the method being called
        file_imports: Set of import names from the file (for ambiguous methods)

    Returns:
        Tuple of (is_memory_method, framework)
    """
    # Quick skip for Python builtins
    if method_name in PYTHON_BUILTIN_METHODS:
        return (False, "")

    # Check unambiguous methods first (most common case)
    if method_name in UNAMBIGUOUS_MEMORY_METHODS:
        return (True, UNAMBIGUOUS_MEMORY_METHODS[method_name])

    # Check ambiguous methods - require import verification
    if method_name in AMBIGUOUS_MEMORY_METHODS:
        framework, required_imports = AMBIGUOUS_MEMORY_METHODS[method_name]

        # No import info available - be conservative, don't trigger (avoid FP)
        if file_imports is None:
            return (False, "")

        # Check if any required import is present
        # Normalize imports for comparison
        imports_str = ' '.join(file_imports).lower().replace('-', '_')
        for req in required_imports:
            req_normalized = req.replace('-', '_')
            if req_normalized in imports_str:
                return (True, framework)

        # No matching import found - likely Python builtin usage
        return (False, "")

    return (False, "")


def is_definitely_not_memory(method_name: str) -> bool:
    """
    Check if a method is DEFINITELY a Python builtin, not Agent memory.

    This is used to quickly skip common false positives.

    Args:
        method_name: Name of the method

    Returns:
        True if this is definitely a Python builtin
    """
    return method_name in PYTHON_BUILTIN_METHODS


def get_memory_method_info(method_name: str) -> Optional[str]:
    """
    Get framework info for a memory method.

    Args:
        method_name: Name of the method

    Returns:
        Framework name if in whitelist, None otherwise
    """
    if method_name in UNAMBIGUOUS_MEMORY_METHODS:
        return UNAMBIGUOUS_MEMORY_METHODS[method_name]
    if method_name in AMBIGUOUS_MEMORY_METHODS:
        return AMBIGUOUS_MEMORY_METHODS[method_name][0]
    return None
