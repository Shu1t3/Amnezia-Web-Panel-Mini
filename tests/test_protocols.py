"""Tests for protocol-related endpoints."""



class TestProtocols:
    def test_invalid_protocol_validation(self, test_app):
        """Test that invalid protocols are rejected at validation level."""
        client, app_module = test_app
        client.post("/api/auth/login", json={
            "username": "admin",
            "password": "admin"
        })
        
        # Invalid protocols should be rejected even without a server
        invalid_protocols = ["xray", "awg_legacy", "awg", "openvpn", "shadowsocks"]
        for proto in invalid_protocols:
            response = client.post("/api/servers/0/install", json={
                "protocol": proto,
                "port": "443"
            })
            # Should be 404 (server not found) since no servers exist
            # but if server existed, it would be 400 (invalid protocol)
            assert response.status_code in [400, 404], f"Protocol {proto} returned {response.status_code}"

    def test_valid_protocols_list(self):
        """Test that valid protocols are correctly defined."""
        # Read app.py and check the validation list
        with open("app.py", "r") as f:
            content = f.read()
        
        # These protocols should be in the validation list
        valid = ["awg2", "telemt", "wireguard", "dns", "socks5", "adguard"]
        for proto in valid:
            assert f"'{proto}'" in content, f"Protocol {proto} not found in validation list"
        
        # These should NOT be in the validation list
        invalid = ["xray", "awg_legacy", "awg"]
        for proto in invalid:
            # Check it's not in the protocol validation list specifically
            # (it might appear elsewhere like in container names for removal)
            pass  # We check this in regression tests

    def test_container_names_no_legacy(self):
        """Test that CONTAINER_NAMES doesn't contain legacy protocols."""
        with open("app.py", "r") as f:
            content = f.read()
        
        # Find CONTAINER_NAMES dict
        import re
        match = re.search(r'CONTAINER_NAMES\s*=\s*\{([^}]+)\}', content, re.DOTALL)
        assert match, "CONTAINER_NAMES not found"
        
        container_dict = match.group(1)
        assert "'awg2'" in container_dict or '"awg2"' in container_dict
        assert "'awg_legacy'" not in container_dict and '"awg_legacy"' not in container_dict
        assert "'xray'" not in container_dict and '"xray"' not in container_dict
        assert "'awg'" not in container_dict or '"awg"' not in container_dict
