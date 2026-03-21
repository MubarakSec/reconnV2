from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

def test_users_full_coverage(tmp_path):
    from recon_cli.users import UserManager, UserRole
    db_path = str(tmp_path / "users.db")
    manager = UserManager(db_path=db_path)
    
    user = manager.create("testuser", "test@test.com", "password123", UserRole.VIEWER)
    assert user is not None
    assert user.username == "testuser"
    
    manager.set_role(user.id, UserRole.ADMIN)
    updated = manager.get(user.id)
    assert updated.role == UserRole.ADMIN
    
    plaintext, key = manager.create_api_token(user.id, "test_key", scopes=["api:access"])
    assert key is not None
    assert plaintext is not None
    
    valid = manager.validate_api_key(plaintext)
    assert valid is not None
    
    manager.revoke_api_token(key.id)
    valid2 = manager.validate_api_key(plaintext)
    assert valid2 is None

def test_api_app_full_coverage():
    from recon_cli.api.app import app
    from fastapi.testclient import TestClient
    client = TestClient(app)
    
    headers = {"X-API-Key": "testkey"}
    with patch("recon_cli.users.UserManager.validate_api_key", return_value={"permissions": ["api:access", "api:admin"]}):
        # Trigger schema
        res = client.get("/openapi.json")
        assert res.status_code == 200

def test_cli_commands_direct():
    from recon_cli.cli import app
    from typer.testing import CliRunner
    runner = CliRunner()
    
    # Test scan
    with patch("recon_cli.cli.run_pipeline") as mock_run:
        result = runner.invoke(app, ["scan", "target.com", "--profile", "full"])
        assert result.exit_code == 0
        
    # Test serve
    with patch("uvicorn.run") as mock_uvicorn:
        result = runner.invoke(app, ["serve", "--port", "8080"])
        assert result.exit_code == 0

    # Test prune
    with patch("recon_cli.config.FINISHED_JOBS") as mock_finished:
        mock_finished.exists.return_value = True
        mock_finished.iterdir.return_value = []
        result = runner.invoke(app, ["prune", "--days", "5"])
        assert result.exit_code == 0

    # Test list-jobs
    with patch("recon_cli.jobs.manager.JobManager.list_jobs", return_value=[]):
        result = runner.invoke(app, ["list-jobs"])
        assert result.exit_code == 0
