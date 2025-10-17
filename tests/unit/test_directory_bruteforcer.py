"""
Unit tests for web-security/directory_bruteforcer.py module.
"""

from unittest.mock import Mock, patch

from web_security.directory_bruteforcer import DirectoryBruteforcer


class TestDirectoryBruteforcer:
    """Tests for DirectoryBruteforcer class."""

    def test_initialization(self, test_config):
        """Test DirectoryBruteforcer initialization."""
        bruteforcer = DirectoryBruteforcer(test_config)

        assert bruteforcer is not None
        assert bruteforcer.config == test_config
        assert bruteforcer.session is not None

    def test_load_wordlist(self, test_config, temp_dir):
        """Test loading wordlist from file."""
        wordlist_file = temp_dir / "wordlist.txt"
        wordlist_file.write_text("admin\nlogin\ntest\n")

        bruteforcer = DirectoryBruteforcer(test_config)
        wordlist = bruteforcer._load_wordlist(str(wordlist_file))

        assert len(wordlist) == 3
        assert "admin" in wordlist
        assert "login" in wordlist

    def test_load_empty_wordlist(self, test_config):
        """Test loading nonexistent wordlist."""
        bruteforcer = DirectoryBruteforcer(test_config)
        wordlist = bruteforcer._load_wordlist("nonexistent.txt")

        assert wordlist == []

    @patch("requests.Session.get")
    def test_test_path_found(self, mock_get, test_config):
        """Test finding an existing path."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"Page content"
        mock_response.headers = {}
        mock_get.return_value = mock_response

        bruteforcer = DirectoryBruteforcer(test_config)
        result = bruteforcer.test_path("https://example.com", "/admin")

        assert result is not None
        assert result["status_code"] == 200
        assert "url" in result

    @patch("requests.Session.get")
    def test_test_path_not_found(self, mock_get, test_config):
        """Test path not found."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        bruteforcer = DirectoryBruteforcer(test_config)
        result = bruteforcer.test_path("https://example.com", "/nonexistent")

        assert result is None
