"""
Enhanced configuration for dangerous commands with risk levels.

This module provides a configuration loader that reads dangerous command patterns
from a properties file and provides efficient pattern matching with risk assessment.
"""

import logging
import re
from enum import Enum
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger("vulnicheck.dangerous_commands")


class RiskLevel(Enum):
    """Risk levels for dangerous commands."""

    BLOCKED = "BLOCKED"  # Always blocked, no exceptions
    HIGH_RISK = "HIGH_RISK"  # Requires explicit approval with strong justification
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"  # Requires approval but may be legitimate
    LOW_RISK = "LOW_RISK"  # Logged but allowed (for future use)


class DangerousPattern(NamedTuple):
    """Represents a dangerous command pattern with risk assessment."""

    category: str
    name: str
    pattern: re.Pattern
    risk_level: RiskLevel
    description: str


class DangerousCommandsRiskConfig:
    """Enhanced configuration with risk levels for dangerous command patterns."""

    def __init__(self, config_file: Path | None = None):
        """
        Initialize the configuration loader.

        Args:
            config_file: Path to the properties file. If None, uses default location.
        """
        if config_file is None:
            config_file = (
                Path(__file__).parent / "dangerous_commands_risk_based.properties"
            )

        self.config_file = config_file
        self._patterns: dict[str, list[DangerousPattern]] | None = None
        self._all_patterns: list[DangerousPattern] | None = None

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

                    # Parse category.pattern = pattern|risk_level|description
                    if "=" not in line:
                        logger.warning(
                            f"Invalid line {line_num} in {self.config_file}: {line}"
                        )
                        continue

                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()

                    if "." not in key:
                        logger.warning(f"Invalid key format at line {line_num}: {key}")
                        continue

                    category, pattern_name = key.split(".", 1)
                    category = category.strip()
                    pattern_name = pattern_name.strip()

                    # Parse value: pattern|risk_level|description
                    parts = value.split("|")
                    if len(parts) != 3:
                        logger.warning(
                            f"Invalid value format at line {line_num}: {value}"
                        )
                        continue

                    pattern_str, risk_level_str, description = (
                        p.strip() for p in parts
                    )

                    # Parse risk level
                    try:
                        risk_level = RiskLevel(risk_level_str)
                    except ValueError:
                        logger.error(
                            f"Invalid risk level at line {line_num}: {risk_level_str}"
                        )
                        continue

                    # Compile the pattern
                    try:
                        # Check if this looks like an intentional regex pattern
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
                            compiled_pattern = re.compile(pattern_str, re.IGNORECASE)
                        else:
                            compiled_pattern = re.compile(
                                re.escape(pattern_str), re.IGNORECASE
                            )

                        # Create pattern object
                        pattern = DangerousPattern(
                            category=category,
                            name=pattern_name,
                            pattern=compiled_pattern,
                            risk_level=risk_level,
                            description=description,
                        )

                        # Store by category
                        if category not in self._patterns:
                            self._patterns[category] = []

                        self._patterns[category].append(pattern)
                        self._all_patterns.append(pattern)

                    except re.error as e:
                        logger.error(
                            f"Invalid regex pattern at line {line_num}: {pattern_str} - {e}"
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
        self,
        text: str,
        categories: list[str] | None = None,
        max_risk_level: RiskLevel | None = None,
    ) -> tuple[DangerousPattern, str] | None:
        """
        Check if the text contains any dangerous patterns.

        Args:
            text: The text to check for dangerous patterns
            categories: Optional list of categories to check. If None, checks all.
            max_risk_level: Maximum risk level to check (e.g., only check BLOCKED patterns)

        Returns:
            Tuple of (DangerousPattern, matched_text) if found, None otherwise
        """
        # Ensure patterns are loaded
        if self._patterns is None:
            self._load_patterns()

        assert self._patterns is not None
        assert self._all_patterns is not None

        # Use all patterns if no categories specified
        if categories is None:
            patterns_to_check = self._all_patterns
        else:
            patterns_to_check = []
            for category in categories:
                if category in self._patterns:
                    patterns_to_check.extend(self._patterns[category])

        # Check each pattern
        for pattern in patterns_to_check:
            # Skip if risk level is too low
            if max_risk_level and pattern.risk_level != max_risk_level:
                continue

            match = pattern.pattern.search(text)
            if match:
                return (pattern, match.group(0))

        return None

    def get_patterns_by_risk_level(
        self, risk_level: RiskLevel
    ) -> list[DangerousPattern]:
        """Get all patterns with a specific risk level."""
        # Ensure patterns are loaded
        if self._patterns is None:
            self._load_patterns()

        assert self._all_patterns is not None

        return [p for p in self._all_patterns if p.risk_level == risk_level]

    def get_risk_description(self, risk_level: RiskLevel) -> str:
        """Get a human-readable description of a risk level."""
        descriptions = {
            RiskLevel.BLOCKED: "This operation is always blocked for security reasons.",
            RiskLevel.HIGH_RISK: "This operation is high risk and requires explicit approval with strong justification.",
            RiskLevel.REQUIRES_APPROVAL: "This operation requires approval but may be legitimate in some contexts.",
            RiskLevel.LOW_RISK: "This operation is low risk but will be logged.",
        }
        return descriptions.get(risk_level, "Unknown risk level")


# Global instance for lazy loading
_config_instance: DangerousCommandsRiskConfig | None = None


def get_dangerous_commands_risk_config() -> DangerousCommandsRiskConfig:
    """Get the global dangerous commands risk configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = DangerousCommandsRiskConfig()
    return _config_instance
