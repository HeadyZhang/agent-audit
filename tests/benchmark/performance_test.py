"""
Performance benchmark tests for agent-audit.

These tests ensure scanner performance meets industrial standards:
- 100 files should scan in under 30 seconds
- Single file should scan in under 500ms
- Memory usage should stay under 200MB for moderate workload
"""

from __future__ import annotations

import sys
import time
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

# Add packages/audit to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "packages" / "audit"))

# Try importing scanner
try:
    from agent_audit.scanners.python_scanner import PythonScanner
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False
    PythonScanner = None  # type: ignore


@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not installed")
class TestScanPerformance:
    """Scan performance benchmarks."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return PythonScanner()

    @pytest.fixture
    def large_fixture(self, tmp_path: Path):
        """Create 100 Python files for testing."""
        for i in range(100):
            code = f'''"""Test file {i}"""
import subprocess
from langchain_core.tools import tool

@tool
def func_{i}(cmd: str):
    """Function {i}."""
    subprocess.run(cmd, shell=True)
    return "done"

def helper_{i}(x):
    return eval(x)
'''
            (tmp_path / f"file_{i}.py").write_text(code)
        return tmp_path

    @pytest.fixture
    def medium_fixture(self, tmp_path: Path):
        """Create 50 Python files for testing."""
        for i in range(50):
            code = f'''"""Test file {i}"""
import os

def process_{i}(cmd: str):
    os.system(cmd)
    return "done"
'''
            (tmp_path / f"file_{i}.py").write_text(code)
        return tmp_path

    def test_scan_100_files_under_30s(self, scanner, large_fixture: Path):
        """100 files should scan in under 30 seconds."""
        start = time.time()
        results = list(scanner.scan(large_fixture))
        elapsed = time.time() - start

        assert elapsed < 30, f"Scan took {elapsed:.1f}s, expected < 30s"
        assert len(results) >= 50, f"Should find findings in test files, got {len(results)}"

        # Log performance metrics
        print(f"\nPerformance: 100 files in {elapsed:.2f}s ({100/elapsed:.1f} files/sec)")

    def test_scan_50_files_under_15s(self, scanner, medium_fixture: Path):
        """50 files should scan in under 15 seconds."""
        start = time.time()
        results = list(scanner.scan(medium_fixture))
        elapsed = time.time() - start

        assert elapsed < 15, f"Scan took {elapsed:.1f}s, expected < 15s"
        assert len(results) >= 25, f"Should find findings in test files, got {len(results)}"

    def test_single_file_under_500ms(self, scanner, tmp_path: Path):
        """Single file should scan in under 500ms."""
        code = '''
import subprocess
subprocess.run("ls", shell=True)
'''
        test_file = tmp_path / "single.py"
        test_file.write_text(code)

        times = []
        for _ in range(5):
            start = time.time()
            list(scanner.scan(test_file))
            times.append(time.time() - start)

        avg_time = sum(times) / len(times)
        assert avg_time < 0.5, f"Avg scan time: {avg_time:.3f}s, expected < 0.5s"

        print(f"\nPerformance: Single file avg {avg_time*1000:.1f}ms")

    def test_empty_directory_fast(self, scanner, tmp_path: Path):
        """Empty directory should return quickly."""
        start = time.time()
        results = list(scanner.scan(tmp_path))
        elapsed = time.time() - start

        assert elapsed < 0.1, f"Empty dir took {elapsed:.3f}s, expected < 0.1s"
        assert len(results) == 0


@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not installed")
class TestMemoryUsage:
    """Memory usage benchmarks."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return PythonScanner()

    def test_memory_usage_under_200mb(self, scanner, tmp_path: Path):
        """Memory usage should stay under 200MB for moderate workload."""
        import tracemalloc

        # Create 50 files with substantial content
        for i in range(50):
            code = f'''"""Test file {i} with more content"""
import subprocess
import os
import sys

def function_a_{i}(x):
    return subprocess.run(x, shell=True)

def function_b_{i}(y):
    return os.system(y)

def function_c_{i}(z):
    return eval(z)

class TestClass_{i}:
    def method_1(self, a):
        subprocess.Popen(a, shell=True)

    def method_2(self, b):
        exec(b)
'''
            (tmp_path / f"file_{i}.py").write_text(code)

        tracemalloc.start()
        results = list(scanner.scan(tmp_path))
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_mb = peak / 1024 / 1024
        assert peak_mb < 200, f"Peak memory: {peak_mb:.1f}MB, expected < 200MB"

        print(f"\nMemory: Peak {peak_mb:.1f}MB for 50 files")

    def test_memory_scales_linearly(self, scanner, tmp_path: Path):
        """Memory should scale roughly linearly with file count."""
        import tracemalloc

        measurements = []

        for file_count in [10, 20, 30]:
            # Create files
            subdir = tmp_path / f"test_{file_count}"
            subdir.mkdir()
            for i in range(file_count):
                (subdir / f"file_{i}.py").write_text(f"import subprocess\nsubprocess.run('ls', shell=True)")

            tracemalloc.start()
            list(scanner.scan(subdir))
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            measurements.append((file_count, peak / 1024 / 1024))

        # Check that memory doesn't grow more than 3x when files grow 3x
        ratio = measurements[-1][1] / measurements[0][1] if measurements[0][1] > 0 else 1
        file_ratio = measurements[-1][0] / measurements[0][0]

        assert ratio < file_ratio * 1.5, f"Memory grew {ratio:.1f}x while files grew {file_ratio}x"


@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not installed")
class TestThroughput:
    """Throughput benchmarks."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return PythonScanner()

    def test_throughput_minimum_10_files_per_second(self, scanner, tmp_path: Path):
        """Should process at least 10 files per second."""
        # Create 30 files
        for i in range(30):
            code = f'''import subprocess
subprocess.run("echo {i}", shell=True)
'''
            (tmp_path / f"file_{i}.py").write_text(code)

        start = time.time()
        results = list(scanner.scan(tmp_path))
        elapsed = time.time() - start

        throughput = 30 / elapsed if elapsed > 0 else float('inf')
        assert throughput >= 10, f"Throughput {throughput:.1f} files/sec, expected >= 10"

        print(f"\nThroughput: {throughput:.1f} files/sec")

    def test_consistent_performance(self, scanner, tmp_path: Path):
        """Performance should be consistent across multiple runs."""
        # Create test files
        for i in range(20):
            (tmp_path / f"file_{i}.py").write_text("import subprocess\nsubprocess.run('ls', shell=True)")

        times = []
        for _ in range(3):
            start = time.time()
            list(scanner.scan(tmp_path))
            times.append(time.time() - start)

        avg = sum(times) / len(times)
        max_deviation = max(abs(t - avg) for t in times)

        # Max deviation should be less than 50% of average
        assert max_deviation < avg * 0.5, f"Performance inconsistent: times={times}, avg={avg}"
