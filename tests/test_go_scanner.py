"""Tests for Go security scanner."""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from agent_audit.scanners.go_scanner import GoScanner, GoScanResult
from agent_audit.models.finding import Finding


@pytest.fixture
def scanner() -> GoScanner:
    """Create a GoScanner instance."""
    return GoScanner()


@pytest.fixture
def tmp_go_file(tmp_path: Path):
    """Factory fixture to create temporary .go files."""
    def _create(name: str, content: str) -> Path:
        go_file = tmp_path / name
        go_file.write_text(content, encoding="utf-8")
        return go_file
    return _create


def _scan_findings(scanner: GoScanner, path: Path) -> List[Finding]:
    """Helper: scan and return flat list of findings."""
    return scanner.scan_and_convert(path)


# ---------------------------------------------------------------------------
# AGENT-034: exec.Command detection
# ---------------------------------------------------------------------------


class TestExecCommandDetection:
    """Tests for exec.Command / exec.CommandContext / syscall.Exec."""

    def test_exec_command_detected(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """exec.Command() should trigger AGENT-034."""
        go_file = tmp_go_file("main.go", """
package main

import "os/exec"

func run(cmd string) (string, error) {
    out, err := exec.Command(cmd).Output()
    return string(out), err
}
""")
        findings = _scan_findings(scanner, go_file)
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-034"
        assert findings[0].cwe_id == "CWE-78"
        assert findings[0].confidence == 0.85

    def test_exec_command_context_detected(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """exec.CommandContext() should trigger AGENT-034."""
        go_file = tmp_go_file("main.go", """
package main

import (
    "context"
    "os/exec"
)

func run(ctx context.Context, cmd string) (string, error) {
    out, err := exec.CommandContext(ctx, cmd).Output()
    return string(out), err
}
""")
        findings = _scan_findings(scanner, go_file)
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-034"
        assert findings[0].confidence == 0.80

    def test_syscall_exec_detected(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """syscall.Exec() should trigger AGENT-034 with critical severity."""
        go_file = tmp_go_file("main.go", """
package main

import "syscall"

func spawn(bin string, args []string) error {
    return syscall.Exec(bin, args, nil)
}
""")
        findings = _scan_findings(scanner, go_file)
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-034"
        assert findings[0].severity.value == "critical"
        assert findings[0].confidence == 0.90


# ---------------------------------------------------------------------------
# AGENT-041: SQL injection detection
# ---------------------------------------------------------------------------


class TestSQLInjectionDetection:
    """Tests for SQL string concatenation and fmt.Sprintf."""

    def test_sql_fmt_sprintf_detected(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """fmt.Sprintf with SQL should trigger AGENT-041."""
        go_file = tmp_go_file("db.go", """
package db

import "fmt"

func getUser(name string) string {
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
    return query
}
""")
        findings = _scan_findings(scanner, go_file)
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-041"
        assert findings[0].cwe_id == "CWE-89"
        assert findings[0].confidence == 0.85

    def test_sql_string_concat_detected(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """db.Query with string concatenation should trigger AGENT-041."""
        go_file = tmp_go_file("db.go", """
package db

func getUser(name string) {
    db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
""")
        findings = _scan_findings(scanner, go_file)
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-041"


# ---------------------------------------------------------------------------
# AGENT-085: Weak random (math/rand)
# ---------------------------------------------------------------------------


class TestWeakRandDetection:
    """Tests for math/rand import detection."""

    def test_math_rand_detected(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """math/rand import should trigger AGENT-085."""
        go_file = tmp_go_file("token.go", """
package auth

import "math/rand"

func generateToken() int {
    return rand.Intn(1000000)
}
""")
        findings = _scan_findings(scanner, go_file)
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-085"
        assert findings[0].cwe_id == "CWE-330"
        assert findings[0].confidence == 0.75

    def test_crypto_rand_coexistence_no_false_positive(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """math/rand + crypto/rand should NOT trigger AGENT-085."""
        go_file = tmp_go_file("rand.go", """
package util

import (
    "crypto/rand"
    "math/rand"
)

func secureRandom() int {
    // Using crypto/rand for security, math/rand for non-security
    return rand.Intn(100)
}
""")
        findings = _scan_findings(scanner, go_file)
        # Should produce 0 findings for weak_rand because crypto/rand is present
        weak_rand_findings = [f for f in findings if f.rule_id == "AGENT-085"]
        assert len(weak_rand_findings) == 0


# ---------------------------------------------------------------------------
# AGENT-026: HTTP without TLS / InsecureSkipVerify
# ---------------------------------------------------------------------------


class TestHTTPTLSDetection:
    """Tests for HTTP without TLS and InsecureSkipVerify."""

    def test_http_get_no_tls_detected(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """http.Get with http:// should trigger AGENT-026."""
        go_file = tmp_go_file("client.go", """
package client

import "net/http"

func fetch() (*http.Response, error) {
    return http.Get("http://api.example.com/data")
}
""")
        findings = _scan_findings(scanner, go_file)
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-026"
        assert findings[0].cwe_id == "CWE-319"

    def test_insecure_skip_verify_detected(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """InsecureSkipVerify: true should trigger AGENT-026."""
        go_file = tmp_go_file("tls.go", """
package client

import (
    "crypto/tls"
    "net/http"
)

func insecureClient() *http.Client {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    return &http.Client{Transport: tr}
}
""")
        findings = _scan_findings(scanner, go_file)
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-026"
        assert findings[0].cwe_id == "CWE-295"
        assert findings[0].confidence == 0.90


# ---------------------------------------------------------------------------
# Test file confidence reduction
# ---------------------------------------------------------------------------


class TestTestFileConfidenceReduction:
    """Test that _test.go files get reduced confidence."""

    def test_test_file_confidence_reduced(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """Findings in _test.go files should have confidence * 0.25."""
        go_file = tmp_go_file("main_test.go", """
package main

import "os/exec"

func TestExec() {
    exec.Command("ls").Run()
}
""")
        findings = _scan_findings(scanner, go_file)
        assert len(findings) == 1
        # Original confidence is 0.85, reduced: 0.85 * 0.25 = 0.2125
        assert abs(findings[0].confidence - 0.85 * 0.25) < 0.001

    def test_test_file_very_low_confidence_suppressed(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """Findings below 0.20 in test files should be dropped entirely."""
        go_file = tmp_go_file("client_test.go", """
package client

import "net/http"

func TestHTTP() {
    http.Get("http://localhost:8080/test")
}
""")
        findings = _scan_findings(scanner, go_file)
        # http_no_tls confidence = 0.70 * 0.25 = 0.175 < 0.20 -> dropped
        http_findings = [f for f in findings if f.cwe_id == "CWE-319"]
        assert len(http_findings) == 0


# ---------------------------------------------------------------------------
# Vendor directory exclusion
# ---------------------------------------------------------------------------


class TestVendorExclusion:
    """Test that vendor/ directories are excluded."""

    def test_vendor_dir_excluded(
        self, scanner: GoScanner, tmp_path: Path
    ) -> None:
        """Files under vendor/ should not be scanned."""
        vendor_dir = tmp_path / "vendor" / "github.com" / "evil"
        vendor_dir.mkdir(parents=True)
        go_file = vendor_dir / "evil.go"
        go_file.write_text("""
package evil

import "os/exec"

func Exploit(cmd string) {
    exec.Command(cmd).Run()
}
""")
        findings = _scan_findings(scanner, tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Clean file: no false positives
# ---------------------------------------------------------------------------


class TestCleanFile:
    """Test that clean Go files produce no findings."""

    def test_clean_go_file_no_findings(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """A safe Go file should produce zero findings."""
        go_file = tmp_go_file("safe.go", """
package main

import (
    "crypto/rand"
    "encoding/json"
    "fmt"
    "net/http"
)

type User struct {
    Name  string `json:"name"`
    Email string `json:"email"`
}

func main() {
    fmt.Println("Hello, world!")
    resp, _ := http.Get("https://api.example.com/users")
    defer resp.Body.Close()
    var user User
    json.NewDecoder(resp.Body).Decode(&user)
    fmt.Printf("User: %s\\n", user.Name)
}
""")
        findings = _scan_findings(scanner, go_file)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Directory scanning
# ---------------------------------------------------------------------------


class TestDirectoryScanning:
    """Test scanning a directory with multiple Go files."""

    def test_scan_directory_multiple_files(
        self, scanner: GoScanner, tmp_path: Path
    ) -> None:
        """Scanner should discover and analyze all .go files recursively."""
        # Create nested structure
        pkg_dir = tmp_path / "pkg" / "util"
        pkg_dir.mkdir(parents=True)

        (tmp_path / "main.go").write_text("""
package main

import "os/exec"

func main() {
    exec.Command("ls").Run()
}
""")
        (pkg_dir / "crypto.go").write_text("""
package util

import "math/rand"

func Token() int {
    return rand.Intn(999999)
}
""")

        findings = _scan_findings(scanner, tmp_path)
        rule_ids = {f.rule_id for f in findings}
        assert "AGENT-034" in rule_ids  # exec.Command
        assert "AGENT-085" in rule_ids  # math/rand

    def test_scan_non_go_file_ignored(
        self, scanner: GoScanner, tmp_path: Path
    ) -> None:
        """Non-.go files should be ignored."""
        py_file = tmp_path / "main.py"
        py_file.write_text("import os; os.system('ls')")

        findings = _scan_findings(scanner, tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Unsafe deserialization (AGENT-049)
# ---------------------------------------------------------------------------


class TestUnsafeDeserialization:
    """Test gob.NewDecoder detection."""

    def test_gob_decoder_detected(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """gob.NewDecoder should trigger AGENT-049."""
        go_file = tmp_go_file("decode.go", """
package main

import (
    "encoding/gob"
    "os"
)

func decode() {
    dec := gob.NewDecoder(os.Stdin)
    var data interface{}
    dec.Decode(&data)
}
""")
        findings = _scan_findings(scanner, go_file)
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-049"
        assert findings[0].cwe_id == "CWE-502"


# ---------------------------------------------------------------------------
# Comment lines are skipped
# ---------------------------------------------------------------------------


class TestCommentSkipping:
    """Test that commented-out patterns are not flagged."""

    def test_commented_exec_command_not_flagged(
        self, scanner: GoScanner, tmp_go_file
    ) -> None:
        """exec.Command in a comment should not produce a finding."""
        go_file = tmp_go_file("main.go", """
package main

// exec.Command("ls") is dangerous, don't use it
func main() {}
""")
        findings = _scan_findings(scanner, go_file)
        assert len(findings) == 0
