"""Tests for authentication endpoints."""



class TestAuth:
    def test_login_page_loads(self, test_app):
        client, _ = test_app
        response = client.get("/login")
        assert response.status_code == 200

    def test_login_with_correct_credentials(self, test_app):
        client, _ = test_app
        response = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "admin"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["role"] == "admin"

    def test_login_with_wrong_password(self, test_app):
        client, _ = test_app
        response = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "wrongpassword"
        })
        assert response.status_code == 401

    def test_login_with_wrong_username(self, test_app):
        client, _ = test_app
        response = client.post("/api/auth/login", json={
            "username": "nonexistent",
            "password": "admin"
        })
        assert response.status_code == 401

    def test_logout(self, test_app):
        client, _ = test_app
        # First login
        client.post("/api/auth/login", json={
            "username": "admin",
            "password": "admin"
        })
        # Then logout
        response = client.get("/logout", follow_redirects=False)
        assert response.status_code == 302

    def test_protected_route_redirects(self, test_app):
        client, _ = test_app
        response = client.get("/", follow_redirects=False)
        assert response.status_code == 302
        assert "/login" in response.headers["location"]
