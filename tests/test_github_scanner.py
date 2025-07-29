"""Tests for GitHub repository scanner."""

import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import pytest

from vulnicheck.scanners.github_scanner import (
    GitHubRepoInfo,
    GitHubRepoScanner,
    ScanConfig,
    ScanDepth,
)


class TestGitHubRepoInfo:
    """Test GitHubRepoInfo dataclass."""

    def test_basic_info(self):
        """Test basic repository info."""
        info = GitHubRepoInfo(owner="test", repo="repo")
        assert info.owner == "test"
        assert info.repo == "repo"
        assert info.branch is None
        assert info.commit is None
        assert info.is_private is False

    def test_clone_url(self):
        """Test clone URL generation."""
        info = GitHubRepoInfo(owner="test", repo="repo")
        assert info.clone_url == "https://github.com/test/repo.git"

    def test_clone_url_with_token(self):
        """Test authenticated clone URL generation."""
        info = GitHubRepoInfo(owner="test", repo="repo")
        url = info.clone_url_with_token("mytoken")
        assert url == "https://mytoken@github.com/test/repo.git"


class TestGitHubRepoScanner:
    """Test GitHubRepoScanner class."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner instance."""
        return GitHubRepoScanner()

    def test_parse_github_url_https(self, scanner):
        """Test parsing HTTPS GitHub URLs."""
        # Basic URL
        info = scanner.parse_github_url("https://github.com/owner/repo")
        assert info.owner == "owner"
        assert info.repo == "repo"
        assert info.branch is None
        assert info.commit is None

        # URL with .git
        info = scanner.parse_github_url("https://github.com/owner/repo.git")
        assert info.owner == "owner"
        assert info.repo == "repo"

        # URL with branch
        info = scanner.parse_github_url("https://github.com/owner/repo/tree/main")
        assert info.owner == "owner"
        assert info.repo == "repo"
        assert info.branch == "main"

        # URL with branch containing slashes
        info = scanner.parse_github_url("https://github.com/owner/repo/tree/feature/new-feature")
        assert info.owner == "owner"
        assert info.repo == "repo"
        assert info.branch == "feature/new-feature"

        # URL with commit
        info = scanner.parse_github_url("https://github.com/owner/repo/commit/abc123")
        assert info.owner == "owner"
        assert info.repo == "repo"
        assert info.commit == "abc123"

    def test_parse_github_url_ssh(self, scanner):
        """Test parsing SSH GitHub URLs."""
        info = scanner.parse_github_url("git@github.com:owner/repo.git")
        assert info.owner == "owner"
        assert info.repo == "repo"

    def test_parse_github_url_invalid(self, scanner):
        """Test parsing invalid URLs."""
        with pytest.raises(ValueError, match="Not a GitHub URL"):
            scanner.parse_github_url("https://gitlab.com/owner/repo")

        with pytest.raises(ValueError, match="Invalid GitHub URL format"):
            scanner.parse_github_url("https://github.com/owner")

        with pytest.raises(ValueError, match="Invalid GitHub SSH URL"):
            scanner.parse_github_url("git@github.com:owner")

    def test_get_cache_key(self, scanner):
        """Test cache key generation."""
        info = GitHubRepoInfo(owner="test", repo="repo", commit="abc123")
        config = ScanConfig(scan_depth=ScanDepth.STANDARD)

        key1 = scanner._get_cache_key(info, config)
        key2 = scanner._get_cache_key(info, config)
        assert key1 == key2  # Same inputs should produce same key

        # Different commit should produce different key
        info2 = GitHubRepoInfo(owner="test", repo="repo", commit="def456")
        key3 = scanner._get_cache_key(info2, config)
        assert key1 != key3

        # Different scan depth should produce different key
        config2 = ScanConfig(scan_depth=ScanDepth.DEEP)
        key4 = scanner._get_cache_key(info, config2)
        assert key1 != key4

    def test_get_cached_results_not_found(self, scanner, tmp_path):
        """Test cache miss."""
        scanner.cache_dir = tmp_path
        result = scanner._get_cached_results("nonexistent", 24)
        assert result is None

    def test_get_cached_results_expired(self, scanner, tmp_path):
        """Test expired cache."""
        scanner.cache_dir = tmp_path
        cache_file = tmp_path / "test.json"

        # Write cache file
        with open(cache_file, 'w') as f:
            json.dump({"test": "data"}, f)

        # Modify timestamp to be old
        old_time = (datetime.now() - timedelta(hours=25)).timestamp()
        import os
        os.utime(cache_file, (old_time, old_time))

        result = scanner._get_cached_results("test", 24)
        assert result is None

    def test_get_cached_results_valid(self, scanner, tmp_path):
        """Test valid cache hit."""
        scanner.cache_dir = tmp_path
        cache_file = tmp_path / "test.json"

        test_data = {"test": "data", "results": [1, 2, 3]}
        with open(cache_file, 'w') as f:
            json.dump(test_data, f)

        result = scanner._get_cached_results("test", 24)
        assert result == test_data

    def test_save_cached_results(self, scanner, tmp_path):
        """Test saving cache."""
        scanner.cache_dir = tmp_path
        test_data = {"test": "data", "results": [1, 2, 3]}

        scanner._save_cached_results("test", test_data)

        cache_file = tmp_path / "test.json"
        assert cache_file.exists()

        with open(cache_file) as f:
            saved_data = json.load(f)
        assert saved_data == test_data

    @pytest.mark.asyncio
    async def test_clone_repository_success(self, scanner, tmp_path):
        """Test successful repository cloning."""
        repo_info = GitHubRepoInfo(owner="test", repo="repo")
        target_dir = tmp_path / "repo"

        # Mock subprocess
        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"", b"")
            mock_exec.return_value = mock_process

            success, message = await scanner.clone_repository(repo_info, target_dir)

            assert success is True
            assert message == "Repository cloned successfully"

            # Check git clone was called
            mock_exec.assert_called()
            call_args = mock_exec.call_args[0]
            assert call_args[0] == "git"
            assert call_args[1] == "clone"
            assert "--depth" in call_args
            assert str(target_dir) in call_args

    @pytest.mark.asyncio
    async def test_clone_repository_with_auth(self, scanner, tmp_path):
        """Test repository cloning with authentication."""
        repo_info = GitHubRepoInfo(owner="test", repo="repo")
        target_dir = tmp_path / "repo"

        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"", b"")
            mock_exec.return_value = mock_process

            success, message = await scanner.clone_repository(
                repo_info, target_dir, auth_token="mytoken"
            )

            assert success is True

            # Check authenticated URL was used
            call_args = mock_exec.call_args[0]
            assert "mytoken@github.com" in call_args[-2]

    @pytest.mark.asyncio
    async def test_clone_repository_failure(self, scanner, tmp_path):
        """Test failed repository cloning."""
        repo_info = GitHubRepoInfo(owner="test", repo="repo")
        target_dir = tmp_path / "repo"

        with patch('asyncio.create_subprocess_exec') as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate.return_value = (b"", b"fatal: repository not found")
            mock_exec.return_value = mock_process

            success, message = await scanner.clone_repository(repo_info, target_dir)

            assert success is False
            assert "Git clone failed" in message
            assert "repository not found" in message

    def test_generate_summary(self, scanner):
        """Test summary generation."""
        results = {
            "findings": {
                "dependencies": {
                    "vulnerabilities": [
                        {"severity": "high"},
                        {"severity": "medium"},
                        {"severity": "medium"},
                    ]
                },
                "secrets": {
                    "high": ["secret1", "secret2"],
                    "medium": ["secret3"]
                },
                "dockerfile": {
                    "total_vulnerabilities": 2
                }
            }
        }

        scanner._generate_summary(results)

        assert "summary" in results
        summary = results["summary"]
        assert summary["total_issues"] == 8  # 3 deps + 3 secrets + 2 docker
        assert summary["high"] == 4  # 1 dep + 3 secrets (all secrets counted as high)
        assert summary["medium"] == 4  # 2 deps + 2 docker
        assert summary["scan_types_completed"] == ["dependencies", "secrets", "dockerfile"]

    def test_generate_remediation(self, scanner):
        """Test remediation recommendations generation."""
        results = {
            "remediation": {
                "immediate": [],
                "medium_term": [],
                "long_term": []
            },
            "findings": {
                "dependencies": {
                    "vulnerabilities": [{"severity": "high"}]
                },
                "secrets": {
                    "high": ["secret1"]
                },
                "dockerfile": {
                    "total_vulnerabilities": 1
                }
            }
        }

        scanner._generate_remediation(results)

        remediation = results["remediation"]
        assert len(remediation["immediate"]) > 0
        assert len(remediation["medium_term"]) > 0
        assert len(remediation["long_term"]) > 0

        # Check specific recommendations
        assert any("Update vulnerable dependencies" in r for r in remediation["immediate"])
        assert any("Rotate all exposed secrets" in r for r in remediation["immediate"])
        assert any("Update base images" in r for r in remediation["immediate"])

    @pytest.mark.asyncio
    async def test_scan_repository_url_parsing_error(self, scanner):
        """Test scan with invalid URL."""
        results = await scanner.scan_repository("not-a-github-url")

        assert results["status"] == "error"
        assert "error" in results
        assert "Not a GitHub URL" in results["error"]

    @pytest.mark.asyncio
    async def test_scan_repository_with_cache_hit(self, scanner, tmp_path):
        """Test scan with cache hit."""
        scanner.cache_dir = tmp_path

        # Pre-populate cache
        cached_data = {
            "status": "success",
            "repository": "https://github.com/test/repo",
            "findings": {"test": "cached"}
        }

        with patch.object(scanner, '_get_cached_results', return_value=cached_data):
            results = await scanner.scan_repository("https://github.com/test/repo")

            assert results["status"] == "success"
            assert results["findings"]["test"] == "cached"
            assert results["from_cache"] is True

    @pytest.mark.asyncio
    async def test_scan_dependencies(self, scanner, tmp_path):
        """Test dependency scanning."""
        # Create a mock requirements.txt
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.25.1\nflask==1.1.2\n")

        # Mock the dependency scanner
        mock_scanner = AsyncMock()
        mock_scanner.scan_file.return_value = {
            "requests": [
                {
                    "id": "CVE-2021-1234",
                    "affected_versions": "==2.25.1",
                    "severity": "high",
                    "summary": "Test vulnerability"
                }
            ],
            "flask": []
        }
        scanner.dependency_scanner = mock_scanner

        findings = await scanner._scan_dependencies(tmp_path)

        assert findings["file_scanned"] == "requirements.txt"
        assert findings["packages_checked"] == 2
        assert len(findings["vulnerabilities"]) == 1
        assert findings["vulnerabilities"][0]["package_name"] == "requests"

    @pytest.mark.asyncio
    async def test_scan_secrets(self, scanner, tmp_path):
        """Test secrets scanning."""
        # Mock the secrets scanner
        mock_scanner = Mock()
        mock_scanner.scan_directory.return_value = {
            "high": ["api_key.py:10: AWS Access Key"],
            "medium": ["config.py:5: Generic Secret"]
        }
        scanner.secrets_scanner = mock_scanner

        config = ScanConfig()
        findings = await scanner._scan_secrets(tmp_path, config)

        assert findings["high"] == ["api_key.py:10: AWS Access Key"]
        assert findings["medium"] == ["config.py:5: Generic Secret"]

    @pytest.mark.asyncio
    async def test_scan_dockerfiles(self, scanner, tmp_path):
        """Test Dockerfile scanning."""
        # Create a mock Dockerfile
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.9\nRUN pip install requests==2.25.1")

        # Mock the docker scanner
        mock_scanner = AsyncMock()
        mock_scanner.scan_dockerfile_async.return_value = {
            "vulnerabilities": [
                {"package": "requests", "version": "2.25.1", "severity": "high"}
            ],
            "packages_found": 1
        }
        scanner.docker_scanner = mock_scanner

        findings = await scanner._scan_dockerfiles(tmp_path)

        assert len(findings["dockerfiles"]) == 1
        assert findings["dockerfiles"][0]["path"] == "Dockerfile"
        assert findings["total_vulnerabilities"] == 1
