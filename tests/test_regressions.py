"""Regression tests to ensure legacy code is removed."""

import os


class TestRegressions:
    def test_no_xray_manager_import(self):
        """Ensure xray_manager.py is deleted."""
        assert not os.path.exists("managers/xray_manager.py")

    def test_no_xray_in_app_imports(self):
        """Ensure app.py doesn't import xray_manager."""
        with open("app.py", "r") as f:
            content = f.read()
        assert "xray_manager" not in content
        assert "XrayManager" not in content

    def test_no_legacy_awg_in_containers(self):
        """Ensure CONTAINER_NAMES doesn't have legacy entries."""
        with open("app.py", "r") as f:
            content = f.read()
        assert "'awg_legacy'" not in content
        assert "'xray'" not in content or "xray_manager" not in content

    def test_no_promo_in_templates(self):
        """Ensure promo blocks are removed from templates."""
        with open("templates/server.html", "r") as f:
            content = f.read()
        assert "promo-block" not in content
        assert "promo-aivpn" not in content
        assert "promo-revproxy" not in content

    def test_no_promo_in_css(self):
        """Ensure promo CSS is removed."""
        with open("static/css/style.css", "r") as f:
            content = f.read()
        assert ".promo-block" not in content
        assert ".promo-orb" not in content

    def test_only_awg2_in_containers(self):
        """Ensure only awg2 is in protocol lists."""
        with open("app.py", "r") as f:
            content = f.read()
        assert "awg2" in content
        assert "protocol: str = 'awg'" not in content

    def test_dockerfile_multistage(self):
        """Ensure Dockerfile has multistage build."""
        with open("Dockerfile", "r") as f:
            content = f.read()
        assert "FROM python:3.14-slim AS builder" in content
        assert "COPY --from=builder" in content

    def test_requirements_no_flask(self):
        """Ensure Flask is removed from requirements."""
        with open("requirements.txt", "r") as f:
            content = f.read()
        assert "Flask" not in content
        assert "Werkzeug" not in content
        assert "blinker" not in content
        assert "colorama" not in content

    def test_requirements_has_pytest(self):
        """Ensure pytest is in requirements."""
        with open("requirements.txt", "r") as f:
            content = f.read()
        assert "pytest" in content

    def test_uses_sqlite(self):
        """Ensure project uses SQLite, not JSON for data storage."""
        with open("app.py", "r") as f:
            content = f.read()
        assert "import db" in content or "from managers import db" in content
        assert "panel.db" in content or "DB_PATH" in content

    def test_no_load_data_calls(self):
        """Ensure all load_data() calls are removed from app.py."""
        with open("app.py", "r") as f:
            content = f.read()
        # Only allow load_data in comments or the telegram bot callback
        active_calls = [line.strip() for line in content.split('\n')
                       if 'load_data()' in line and not line.strip().startswith('#')]
        assert len(active_calls) == 0, f"Found load_data() calls: {active_calls}"

    def test_no_remnawave_in_settings(self):
        """Ensure Remnawave sync is removed from settings."""
        with open("templates/settings.html", "r") as f:
            content = f.read()
        assert "remnawave" not in content.lower()
        assert "import_users" not in content.lower()
