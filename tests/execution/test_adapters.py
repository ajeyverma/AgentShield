"""
Tests for Controlled Tool Adapters (Phase 6).
"""

import os
from pathlib import Path
import pytest
from agentshield.execution.adapters import (
    CalculatorAdapter,
    MockEmailAdapter,
    MockHttpAdapter,
    SandboxedFilesystemAdapter,
)


class TestCalculatorAdapter:
    def setup_method(self):
        self.adapter = CalculatorAdapter()

    def test_add_operation(self):
        res = self.adapter.execute("add", {"a": 10, "b": 5})
        assert res.status == "SUCCESS"
        assert res.result["result"] == 15.0

    def test_divide_by_zero_rejected(self):
        res = self.adapter.execute("divide", {"a": 10, "b": 0})
        assert res.status == "FAILED"
        assert res.error_code == "INVALID_ARGUMENTS"
        assert "zero" in res.error_message.lower()

    def test_unknown_action_fails(self):
        res = self.adapter.execute("modulo", {"a": 10, "b": 3})
        assert res.status == "FAILED"
        assert res.error_code == "ACTION_NOT_FOUND"


class TestSandboxedFilesystemAdapter:
    @pytest.fixture(autouse=True)
    def setup_sandbox(self, tmp_path):
        self.sandbox_dir = tmp_path / "sandbox"
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)
        self.adapter = SandboxedFilesystemAdapter(sandbox_root=self.sandbox_dir)

    def test_create_and_read_file(self):
        res = self.adapter.execute("create_file", {"path": "test.txt", "content": "Hello Sandbox!"})
        assert res.status == "SUCCESS"
        assert res.result["status"] == "created"

        read_res = self.adapter.execute("read_file", {"path": "test.txt"})
        assert read_res.status == "SUCCESS"
        assert read_res.result["content"] == "Hello Sandbox!"

    def test_path_traversal_escape_rejected(self):
        res = self.adapter.execute("read_file", {"path": "../../etc/passwd"})
        assert res.status == "FAILED"
        assert res.error_code == "INVALID_ARGUMENTS"
        assert "traversal escape detected" in res.error_message.lower()

    def test_forbidden_extension_rejected(self):
        res = self.adapter.execute("create_file", {"path": "script.sh", "content": "echo hack"})
        assert res.status == "FAILED"
        assert res.error_code == "INVALID_ARGUMENTS"
        assert "extension" in res.error_message.lower()

    def test_list_files(self):
        self.adapter.execute("create_file", {"path": "a.txt", "content": "file a"})
        self.adapter.execute("create_file", {"path": "b.txt", "content": "file b"})
        res = self.adapter.execute("list_files", {})
        assert res.status == "SUCCESS"
        filenames = [f["name"] for f in res.result["files"]]
        assert "a.txt" in filenames
        assert "b.txt" in filenames

    def test_file_size_limit_exceeded(self):
        oversized = "X" * (3 * 1024 * 1024)  # 3MB exceeds 2MB limit
        res = self.adapter.execute("create_file", {"path": "big.txt", "content": oversized})
        assert res.status == "FAILED"
        assert res.error_code == "INVALID_ARGUMENTS"

    def test_adapter_output_size_limit_enforced(self):
        small_adapter = SandboxedFilesystemAdapter(sandbox_root=self.sandbox_dir, max_output_bytes=50)
        res = small_adapter.execute("create_file", {"path": "medium.txt", "content": "Hello World This Is Output"})
        assert res.status == "FAILED"
        assert res.error_code == "OUTPUT_SIZE_EXCEEDED"


class TestMockEmailAdapter:
    def setup_method(self):
        self.adapter = MockEmailAdapter()

    def test_create_draft_valid(self):
        res = self.adapter.execute("create_draft", {"to": "user@example.com", "subject": "Hello", "body": "Draft body"})
        assert res.status == "SUCCESS"
        assert res.result["status"] == "draft_saved"

    def test_invalid_email_format_rejected(self):
        res = self.adapter.execute("send_email", {"to": "not-an-email", "subject": "Alert", "body": "Msg"})
        assert res.status == "FAILED"
        assert res.error_code == "INVALID_ARGUMENTS"


class TestMockHttpAdapter:
    def setup_method(self):
        self.adapter = MockHttpAdapter()

    def test_get_allowed_mock_endpoint(self):
        res = self.adapter.execute("get", {"endpoint": "/weather"})
        assert res.status == "SUCCESS"
        assert res.result["data"]["location"] == "San Francisco"

    def test_external_url_attempt_strictly_rejected(self):
        res = self.adapter.execute("get", {"endpoint": "https://attacker.com/leak"})
        assert res.status == "FAILED"
        assert res.error_code == "INVALID_ARGUMENTS"
        assert "external urls are not permitted" in res.error_message.lower()
