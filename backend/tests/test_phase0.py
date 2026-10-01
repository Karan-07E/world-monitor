import pytest
import ipaddress
import urllib.parse
from backend.runner.guard import is_domain_blocked, resolve_and_pin_ip
from backend.twin.client_scope import analyze_client_scope
from backend.twin.analyzer import analyze_roles_and_auth
import os
from pathlib import Path

def test_guard_domain_blocked():
    assert is_domain_blocked("worldmonitor.app") == True
    assert is_domain_blocked("api.worldmonitor.app") == True
    assert is_domain_blocked("safe-domain.com") == False

def test_guard_resolve_localhost():
    # Should resolve localhost to 127.0.0.1 (or ::1) and pin it
    url = "http://localhost:8080/api"
    pinned = resolve_and_pin_ip(url)
    assert "127.0.0.1" in pinned or "[::1]" in pinned
    
def test_guard_blocks_public_ip(monkeypatch):
    # Mock socket.getaddrinfo to return a public IP
    import socket
    def mock_getaddrinfo(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', port))]
    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)
    
    with pytest.raises(ValueError, match="not in the allowed local/compose subnets"):
        resolve_and_pin_ip("http://example.com")

def test_client_scope_detection(tmp_path):
    # Create mock PWA and Tauri
    (tmp_path / "sw.js").touch()
    tauri_conf = tmp_path / "tauri.conf.json"
    tauri_conf.write_text('{"tauri": {"windows": [{"url": "http://external.com"}]}}')
    
    scope = analyze_client_scope(str(tmp_path))
    assert scope["pwa"] == True
    assert scope["tauri"] == True
    assert scope["tauri_details"]["loads_remote_content"] == True

def test_analyzer_detects_roles(tmp_path):
    api_dir = tmp_path / "api"
    api_dir.mkdir()
    (api_dir / "user.ts").write_text("const isAdmin = true;")
    
    auth_data = analyze_roles_and_auth(str(tmp_path))
    assert auth_data["roles_exist"] == True
    assert auth_data["horizontal_tests"] == "APPLICABLE"

def test_analyzer_no_roles(tmp_path):
    api_dir = tmp_path / "api"
    api_dir.mkdir()
    (api_dir / "user.ts").write_text("const name = 'Alice';")
    
    auth_data = analyze_roles_and_auth(str(tmp_path))
    assert auth_data["roles_exist"] == False
    assert auth_data["horizontal_tests"] == "NOT APPLICABLE"
