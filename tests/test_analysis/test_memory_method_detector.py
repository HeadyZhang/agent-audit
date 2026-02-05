"""Tests for Memory Method Detector - v0.11.0/v0.12.0 semantic layer.

Tests the GATE for AGENT-018:
- add_message is Agent memory method (triggers check)
- add (set.add) is NOT Agent memory method (skipped)
- append (list.append) is NOT Agent memory method (skipped)

v0.12.0: Tests for ambiguous methods with import checking:
- list.insert() without llama_index import -> NOT triggered (FP fix)
- index.insert() with llama_index import -> triggered (true positive)
"""

import pytest

from agent_audit.analysis.memory_method_detector import (
    is_agent_memory_method,
    is_definitely_not_memory,
    get_memory_method_info,
    AGENT_MEMORY_WRITE_METHODS,
    PYTHON_BUILTIN_METHODS,
    UNAMBIGUOUS_MEMORY_METHODS,
    AMBIGUOUS_MEMORY_METHODS,
)


class TestAgentMemoryMethodDetection:
    """Test the main gate for AGENT-018."""

    def test_add_message_is_memory_method(self):
        """add_message is Agent memory method."""
        is_mem, framework = is_agent_memory_method('add_message')
        assert is_mem is True
        assert framework == 'langchain'

    def test_add_messages_is_memory_method(self):
        """add_messages is Agent memory method."""
        is_mem, framework = is_agent_memory_method('add_messages')
        assert is_mem is True
        assert framework == 'langchain'

    def test_add_user_message_is_memory_method(self):
        """add_user_message is Agent memory method."""
        is_mem, framework = is_agent_memory_method('add_user_message')
        assert is_mem is True

    def test_save_context_is_memory_method(self):
        """save_context is Agent memory method."""
        is_mem, framework = is_agent_memory_method('save_context')
        assert is_mem is True
        assert framework == 'langchain'

    def test_add_texts_is_memory_method(self):
        """add_texts (vector store) is Agent memory method."""
        is_mem, framework = is_agent_memory_method('add_texts')
        assert is_mem is True
        assert framework == 'vector_store'

    def test_add_documents_is_memory_method(self):
        """add_documents (vector store) is Agent memory method."""
        is_mem, framework = is_agent_memory_method('add_documents')
        assert is_mem is True
        assert framework == 'vector_store'

    def test_upsert_is_memory_method_with_import(self):
        """upsert (vector store) is Agent memory method when import present."""
        # v0.12.0: upsert is ambiguous, needs vector DB import
        is_mem, framework = is_agent_memory_method('upsert', file_imports={'pinecone'})
        assert is_mem is True
        assert framework == 'vector_store'

    def test_write_documents_is_memory_method(self):
        """write_documents (Haystack) is Agent memory method."""
        is_mem, framework = is_agent_memory_method('write_documents')
        assert is_mem is True
        assert framework == 'haystack'


class TestPythonBuiltinsNotMemory:
    """Test that Python builtins are NOT Agent memory methods."""

    def test_set_add_not_memory_method(self):
        """set.add() is NOT Agent memory method."""
        is_mem, _ = is_agent_memory_method('add')
        assert is_mem is False

    def test_list_append_not_memory_method(self):
        """list.append() is NOT Agent memory method."""
        is_mem, _ = is_agent_memory_method('append')
        assert is_mem is False

    def test_dict_update_not_memory_method(self):
        """dict.update() is NOT Agent memory method."""
        is_mem, _ = is_agent_memory_method('update')
        assert is_mem is False

    def test_list_extend_not_memory_method(self):
        """list.extend() is NOT Agent memory method."""
        is_mem, _ = is_agent_memory_method('extend')
        assert is_mem is False

    def test_queue_put_not_memory_method(self):
        """queue.put() is NOT Agent memory method."""
        is_mem, _ = is_agent_memory_method('put')
        assert is_mem is False

    def test_set_not_memory_method(self):
        """dict.set() or similar is NOT Agent memory method."""
        is_mem, _ = is_agent_memory_method('set')
        assert is_mem is False


class TestDefinitelyNotMemory:
    """Test the quick-skip function for known builtins."""

    def test_add_is_definitely_not_memory(self):
        """add is definitely Python builtin."""
        assert is_definitely_not_memory('add') is True

    def test_append_is_definitely_not_memory(self):
        """append is definitely Python builtin."""
        assert is_definitely_not_memory('append') is True

    def test_update_is_definitely_not_memory(self):
        """update is definitely Python builtin."""
        assert is_definitely_not_memory('update') is True

    def test_add_message_is_not_definitely_builtin(self):
        """add_message is NOT a Python builtin."""
        assert is_definitely_not_memory('add_message') is False

    def test_upsert_is_not_definitely_builtin(self):
        """upsert is NOT a Python builtin."""
        assert is_definitely_not_memory('upsert') is False


class TestGetMemoryMethodInfo:
    """Test the info getter function."""

    def test_get_info_for_add_message(self):
        """Should return framework for known method."""
        info = get_memory_method_info('add_message')
        assert info == 'langchain'

    def test_get_info_for_add_texts(self):
        """Should return framework for vector store method."""
        info = get_memory_method_info('add_texts')
        assert info == 'vector_store'

    def test_get_info_for_unknown_method(self):
        """Should return None for unknown method."""
        info = get_memory_method_info('random_method')
        assert info is None

    def test_get_info_for_builtin(self):
        """Should return None for Python builtins."""
        info = get_memory_method_info('add')
        assert info is None


class TestNoVariableNameHeuristic:
    """Test that we DON'T use variable name heuristics.

    v0.10.0 used patterns like 'seen', 'visited' to detect Python collections.
    v0.11.0 uses method whitelist - no variable name guessing.
    """

    def test_seen_add_skipped_via_method_whitelist(self):
        """seen.add() should be skipped because 'add' is not in whitelist.

        NOT because 'seen' matches a variable name pattern.
        """
        is_mem, _ = is_agent_memory_method('add')
        assert is_mem is False
        # The skip happens because 'add' is not in AGENT_MEMORY_WRITE_METHODS
        # NOT because we check the variable name 'seen'

    def test_memory_add_skipped_via_method_whitelist(self):
        """memory.add() should be skipped because 'add' is not in whitelist.

        Even though 'memory' might suggest Agent memory, the method 'add'
        is not specific enough.
        """
        is_mem, _ = is_agent_memory_method('add')
        assert is_mem is False

    def test_visited_update_skipped_via_method_whitelist(self):
        """visited.update() should be skipped because 'update' is not in whitelist."""
        is_mem, _ = is_agent_memory_method('update')
        assert is_mem is False


class TestWhitelistCompleteness:
    """Test that whitelist covers common Agent memory patterns."""

    @pytest.mark.parametrize("method", [
        'add_message',
        'add_messages',
        'add_user_message',
        'add_ai_message',
        'save_context',
        'add_memory',
        'add_texts',
        'add_documents',
        # Note: 'upsert' and 'insert' are now ambiguous - need imports
        'insert_nodes',
        'add_to_memory',
        'write_documents',
        'store_memory',
        'persist_memory',
        'save_memory',
        'update_memory',
    ])
    def test_known_memory_methods_in_whitelist(self, method):
        """All known Agent memory methods should be in whitelist."""
        is_mem, _ = is_agent_memory_method(method)
        assert is_mem is True, f"{method} should be in whitelist"

    @pytest.mark.parametrize("method", [
        'add',
        'append',
        'extend',
        'update',
        'put',
        'push',
        'set',
    ])
    def test_python_builtins_not_in_whitelist(self, method):
        """Python builtins should NOT be in whitelist."""
        is_mem, _ = is_agent_memory_method(method)
        assert is_mem is False, f"{method} should NOT be in whitelist"


class TestAmbiguousMethodsWithImport:
    """v0.12.0: Test ambiguous methods with import checking.

    Methods like 'insert' and 'upsert' need import context to distinguish
    Python builtins from framework operations.
    """

    def test_insert_without_llama_index_import(self):
        """list.insert() should NOT trigger without llama_index import."""
        is_mem, _ = is_agent_memory_method('insert', file_imports={'os', 'sys'})
        assert is_mem is False

    def test_insert_with_llama_index_import(self):
        """index.insert() SHOULD trigger with llama_index import."""
        is_mem, fw = is_agent_memory_method('insert', file_imports={'llama_index'})
        assert is_mem is True
        assert fw == 'llama_index'

    def test_insert_with_llama_index_submodule(self):
        """llama_index submodule import should also trigger."""
        is_mem, fw = is_agent_memory_method(
            'insert',
            file_imports={'llama_index.core', 'llama_index.embeddings'}
        )
        assert is_mem is True
        assert fw == 'llama_index'

    def test_insert_with_llama_index_hyphen(self):
        """llama-index (hyphenated) import should trigger."""
        # Some imports use llama-index instead of llama_index
        is_mem, fw = is_agent_memory_method(
            'insert',
            file_imports={'llama-index'}
        )
        assert is_mem is True
        assert fw == 'llama_index'

    def test_insert_without_imports(self):
        """No imports info - be conservative, don't trigger (avoid FP)."""
        is_mem, _ = is_agent_memory_method('insert', file_imports=None)
        assert is_mem is False

    def test_insert_with_empty_imports(self):
        """Empty imports set - don't trigger."""
        is_mem, _ = is_agent_memory_method('insert', file_imports=set())
        assert is_mem is False

    def test_upsert_with_pinecone(self):
        """pinecone.upsert() SHOULD trigger."""
        is_mem, fw = is_agent_memory_method('upsert', file_imports={'pinecone'})
        assert is_mem is True
        assert fw == 'vector_store'

    def test_upsert_with_chromadb(self):
        """chromadb upsert() SHOULD trigger."""
        is_mem, fw = is_agent_memory_method('upsert', file_imports={'chromadb'})
        assert is_mem is True
        assert fw == 'vector_store'

    def test_upsert_with_weaviate(self):
        """weaviate upsert() SHOULD trigger."""
        is_mem, fw = is_agent_memory_method('upsert', file_imports={'weaviate'})
        assert is_mem is True
        assert fw == 'vector_store'

    def test_upsert_with_qdrant(self):
        """qdrant upsert() SHOULD trigger."""
        is_mem, fw = is_agent_memory_method('upsert', file_imports={'qdrant_client'})
        # Note: 'qdrant' is in the required imports, qdrant_client contains 'qdrant'
        assert is_mem is True
        assert fw == 'vector_store'

    def test_upsert_without_vector_db(self):
        """upsert without vector DB import should NOT trigger."""
        is_mem, _ = is_agent_memory_method('upsert', file_imports={'pandas', 'numpy'})
        assert is_mem is False

    def test_upsert_without_imports(self):
        """No imports info - be conservative, don't trigger."""
        is_mem, _ = is_agent_memory_method('upsert', file_imports=None)
        assert is_mem is False


class TestUnambiguousMethodsDontNeedImports:
    """Test that unambiguous methods work with or without imports."""

    def test_add_message_without_imports(self):
        """add_message should trigger even without imports."""
        is_mem, fw = is_agent_memory_method('add_message', file_imports=None)
        assert is_mem is True
        assert fw == 'langchain'

    def test_add_documents_without_imports(self):
        """add_documents should trigger even without imports."""
        is_mem, fw = is_agent_memory_method('add_documents', file_imports=None)
        assert is_mem is True
        assert fw == 'vector_store'

    def test_insert_nodes_without_imports(self):
        """insert_nodes is unambiguous, should trigger without imports."""
        is_mem, fw = is_agent_memory_method('insert_nodes', file_imports=None)
        assert is_mem is True
        assert fw == 'llama_index'

    def test_add_message_with_unrelated_imports(self):
        """add_message should trigger regardless of imports."""
        is_mem, fw = is_agent_memory_method('add_message', file_imports={'os', 'sys'})
        assert is_mem is True
        assert fw == 'langchain'
