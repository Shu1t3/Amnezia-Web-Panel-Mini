"""Pytest fixtures for Amnezia Web Panel tests."""

import os
import tempfile
import pytest
from unittest.mock import MagicMock


@pytest.fixture
def temp_data_dir():
    """Create a temporary directory for test data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def mock_ssh():
    """Create a mock SSHManager."""
    ssh = MagicMock()
    ssh.host = "192.168.1.100"
    ssh.port = 22
    ssh.username = "root"
    ssh.password = "testpass"
    ssh.run_command.return_value = ("", "", 0)
    ssh.run_sudo_command.return_value = ("", "", 0)
    ssh.run_sudo_script.return_value = ("", "", 0)
    ssh.connect.return_value = True
    ssh.disconnect.return_value = True
    return ssh


@pytest.fixture
def test_app(temp_data_dir):
    """Create a test FastAPI app with temporary SQLite database."""
    db_file = os.path.join(temp_data_dir, "test.db")

    import sys
    if "app" in sys.modules:
        del sys.modules["app"]
    if "managers.db" in sys.modules:
        del sys.modules["managers.db"]
    if "managers.cache" in sys.modules:
        del sys.modules["managers.cache"]

    os.environ["DB_PATH"] = db_file
    import app as app_module
    app_module.DB_PATH = db_file

    from fastapi.testclient import TestClient
    with TestClient(app_module.app) as client:
        yield client, app_module


@pytest.fixture
def sample_server():
    """Sample server data for tests."""
    return {
        "name": "Test Server",
        "host": "192.168.1.100",
        "ssh_port": 22,
        "username": "root",
        "password": "testpass",
        "private_key": "",
        "protocols": {}
    }


@pytest.fixture
def sample_user():
    """Sample user data for tests."""
    return {
        "username": "testuser",
        "password": "testpass123",
        "role": "user"
    }
