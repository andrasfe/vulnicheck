"""
Lazy loading configuration for dangerous commands.

This module provides a configuration loader that reads dangerous command patterns
from a properties file and provides efficient pattern matching.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)


class DangerousCommandsConfig:
    """Lazily loads and manages dangerous command patterns from a properties file."""

    def __init__(self, config_file: Path | None = None):
        """
        Initialize the configuration loader.

        Args:
            config_file: Path to the properties file. If None, uses default location.
        """
        if config_file is None:
            config_file = Path(__file__).parent / "dangerous_commands.properties"

        self.config_file = config_file
        self._patterns: dict[str, list[tuple[str, str, re.Pattern]]] | None = None
        self._all_patterns: list[tuple[str, str, re.Pattern]] | None = None

    def _load_patterns(self) -> None:
        """Load patterns from the properties file."""
        if self._patterns is not None:
            return  # Already loaded

        self._patterns = {}
        self._all_patterns = []

        try:
            with open(self.config_file) as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue

                    # Parse category.pattern = description
                    if "=" not in line:
                        logger.warning(
                            f"Invalid line {line_num} in {self.config_file}: {line}"
                        )
                        continue

                    key, description = line.split("=", 1)
                    key = key.strip()
                    description = description.strip()

                    if "." not in key:
                        logger.warning(f"Invalid key format at line {line_num}: {key}")
                        continue

                    category, pattern_name = key.split(".", 1)
                    category = category.strip()
                    pattern_name = pattern_name.strip()

                    # Compile the pattern for case-insensitive matching
                    try:
                        # Handle special regex characters in the pattern
                        pattern_str = description

                        # Check if this looks like an intentional regex pattern
                        # Look for patterns like .*, .+, [], etc.
                        regex_indicators = [
                            ".*",
                            ".+",
                            "\\d",
                            "\\w",
                            "\\s",
                            "[",
                            "]",
                            "^",
                            "$",
                            "|",
                            "(?",
                            ")",
                        ]

                        is_regex = any(
                            indicator in pattern_str for indicator in regex_indicators
                        )

                        if is_regex:
                            # Compile as regex
                            compiled_pattern = re.compile(pattern_str, re.IGNORECASE)
                        else:
                            # Escape for literal matching
                            compiled_pattern = re.compile(
                                re.escape(pattern_str), re.IGNORECASE
                            )

                        # Store by category
                        if category not in self._patterns:
                            self._patterns[category] = []

                        pattern_tuple = (pattern_name, description, compiled_pattern)
                        self._patterns[category].append(pattern_tuple)
                        self._all_patterns.append(pattern_tuple)

                    except re.error as e:
                        logger.error(
                            f"Invalid regex pattern at line {line_num}: {description} - {e}"
                        )

            logger.info(
                f"Loaded {len(self._all_patterns)} dangerous command patterns from {self.config_file}"
            )

        except FileNotFoundError:
            logger.error(
                f"Dangerous commands config file not found: {self.config_file}"
            )
            self._patterns = {}
            self._all_patterns = []
        except Exception as e:
            logger.error(f"Error loading dangerous commands config: {e}")
            self._patterns = {}
            self._all_patterns = []

    def check_dangerous_pattern(
        self, text: str, categories: list[str] | None = None
    ) -> tuple[str, str, str] | None:
        """
        Check if the text contains any dangerous patterns.

        Args:
            text: The text to check for dangerous patterns
            categories: Optional list of categories to check. If None, checks all.

        Returns:
            Tuple of (category, pattern_name, matched_text) if dangerous pattern found, None otherwise
        """
        # Ensure patterns are loaded
        if self._patterns is None:
            self._load_patterns()

        # Verify patterns were loaded successfully
        if self._patterns is None or self._all_patterns is None:
            raise RuntimeError("Failed to load dangerous command patterns")

        # Use all patterns if no categories specified
        if categories is None:
            patterns_to_check = self._all_patterns
            category_map = {}
            # Build reverse mapping
            for cat, patterns in self._patterns.items():
                for pattern in patterns:
                    category_map[id(pattern)] = cat
        else:
            patterns_to_check = []
            category_map = {}
            for category in categories:
                if category in self._patterns:
                    for pattern in self._patterns[category]:
                        patterns_to_check.append(pattern)
                        category_map[id(pattern)] = category

        # Check each pattern
        for pattern_tuple in patterns_to_check:
            pattern_name, pattern_desc, compiled_pattern = pattern_tuple
            match = compiled_pattern.search(text)
            if match:
                category = category_map.get(id(pattern_tuple), "unknown")
                return (category, pattern_name, match.group(0))

        return None

    def get_patterns_by_category(self, category: str) -> list[tuple[str, str]]:
        """
        Get all patterns for a specific category.

        Args:
            category: The category name

        Returns:
            List of (pattern_name, pattern_description) tuples
        """
        # Ensure patterns are loaded
        if self._patterns is None:
            self._load_patterns()

        # Verify patterns were loaded successfully
        if self._patterns is None:
            raise RuntimeError("Failed to load dangerous command patterns")

        if category not in self._patterns:
            return []

        return [(name, desc) for name, desc, _ in self._patterns[category]]

    def get_categories(self) -> list[str]:
        """Get all available categories."""
        # Ensure patterns are loaded
        if self._patterns is None:
            self._load_patterns()

        # Verify patterns were loaded successfully
        if self._patterns is None:
            raise RuntimeError("Failed to load dangerous command patterns")

        return list(self._patterns.keys())

    def reload(self) -> None:
        """Force reload of the configuration file."""
        self._patterns = None
        self._all_patterns = None
        self._load_patterns()


# Global instance for lazy loading
_config_instance: DangerousCommandsConfig | None = None


def get_dangerous_commands_config() -> DangerousCommandsConfig:
    """Get the global dangerous commands configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = DangerousCommandsConfig()
    return _config_instance
