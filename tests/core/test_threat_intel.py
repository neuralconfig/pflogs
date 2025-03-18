"""
Tests for the Threat Intelligence module.
"""

import os
import pytest
import pandas as pd
import urllib.request
import tempfile
import ipaddress
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime, timedelta
import time
import shutil

from pflogs.core.threat_intel import ThreatIntelligence


@pytest.fixture
def temp_data_dir():
    """Create a temporary directory for data."""
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    # Clean up after test
    shutil.rmtree(temp_dir)


@pytest.fixture
def sample_df():
    """Create a sample DataFrame for testing."""
    return pd.DataFrame({
        "timestamp": ["2023-01-01T12:00:00", "2023-01-01T12:01:00", "2023-01-01T12:02:00"],
        "action": ["block", "block", "allow"],
        "src_ip": ["203.0.113.1", "192.0.2.1", "198.51.100.1"],
        "dst_ip": ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
    })


@pytest.fixture
def sample_blacklist_content():
    """Create sample blacklist content for testing."""
    return """# Sample FireHOL Level1 blacklist
# Generated on 2023-01-01

# IP ranges
192.0.2.0/24      # TEST-NET-1
198.51.100.0/24   # TEST-NET-2
203.0.113.0/24    # TEST-NET-3

# Individual IPs
192.0.2.1
192.0.2.2
198.51.100.1
203.0.113.1
"""


@pytest.fixture
def sample_emerging_threats_content():
    """Create sample Emerging Threats content for testing."""
    return """# Emerging Threats Block List
# Generated on 2023-01-01

# Malicious IPs
# 192.0.2.1
192.0.2.2
198.51.100.1
203.0.113.1
"""


class TestThreatIntelligence:
    """Test the ThreatIntelligence class."""
    
    @patch('os.makedirs')
    def test_init(self, mock_makedirs, temp_data_dir):
        """Test initialization."""
        with patch.object(ThreatIntelligence, '_load_blacklists') as mock_load:
            # Test with data_dir
            threat_intel = ThreatIntelligence(data_dir=temp_data_dir)
            assert threat_intel.data_dir == temp_data_dir
            assert threat_intel.sources == ThreatIntelligence.DEFAULT_SOURCES
            assert threat_intel.auto_refresh is True
            mock_load.assert_called_once()
            mock_makedirs.assert_called_once_with(temp_data_dir, exist_ok=True)
    
    def test_load_ip_set(self, temp_data_dir):
        """Test loading IP sets from files."""
        # Create a temporary file with some IP addresses
        with tempfile.NamedTemporaryFile(mode='w+', dir=temp_data_dir, delete=False) as tmp_file:
            tmp_file.write("""# Test IP list
192.0.2.1
192.0.2.2
198.51.100.0/24
# Comment
203.0.113.1
invalid_ip
""")
            tmp_file.flush()
            tmp_file_path = tmp_file.name
            
        # Load the IP set
        threat_intel = ThreatIntelligence(data_dir=temp_data_dir)
        ip_set = threat_intel._load_ip_set(tmp_file_path)
        
        # Check the results
        assert len(ip_set) == 4
        assert "192.0.2.1" in ip_set
        assert "192.0.2.2" in ip_set
        assert "198.51.100.0/24" in ip_set
        assert "203.0.113.1" in ip_set
        assert "invalid_ip" not in ip_set
        
        # Clean up
        os.unlink(tmp_file_path)
    
    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_load_blacklists(self, mock_file, mock_exists, mock_makedirs, temp_data_dir):
        """Test loading blacklists."""
        # Setup mocks
        mock_exists.return_value = True
        mock_file.return_value.read.return_value = f"{time.time()}|100|https://example.com/list.txt"
        
        # Test loading blacklists
        with patch.object(ThreatIntelligence, '_load_ip_set') as mock_load_ip_set:
            mock_load_ip_set.return_value = {"192.0.2.1", "192.0.2.2"}
            
            threat_intel = ThreatIntelligence(data_dir=temp_data_dir, auto_refresh=False)
            
            # Check that _load_ip_set was called for each source
            assert mock_load_ip_set.call_count == len(ThreatIntelligence.DEFAULT_SOURCES)
            
            # Check that metadata was loaded
            assert len(threat_intel.metadata) == len(ThreatIntelligence.DEFAULT_SOURCES)
            
            # Check that blacklists were loaded
            assert len(threat_intel.blacklists) == len(ThreatIntelligence.DEFAULT_SOURCES)
    
    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_load_blacklists_outdated(self, mock_file, mock_exists, mock_makedirs, temp_data_dir):
        """Test loading outdated blacklists."""
        # Setup mocks
        mock_exists.return_value = True
        
        # Create an outdated timestamp (1 week ago)
        outdated_timestamp = time.time() - 7 * 86400
        mock_file.return_value.read.return_value = f"{outdated_timestamp}|100|https://example.com/list.txt"
        
        # Test loading blacklists with auto-refresh
        with patch.object(ThreatIntelligence, '_load_ip_set') as mock_load_ip_set:
            with patch.object(ThreatIntelligence, 'refresh_blacklists') as mock_refresh:
                mock_load_ip_set.return_value = {"192.0.2.1", "192.0.2.2"}
                
                threat_intel = ThreatIntelligence(data_dir=temp_data_dir, auto_refresh=True)
                
                # Check that refresh_blacklists was called
                mock_refresh.assert_called_once()
    
    def test_download_blacklist(self, temp_data_dir):
        """Test downloading a blacklist."""
        # Create test class instance with mocked sources
        test_sources = {
            "test_source": "https://example.com/list.txt"
        }
        
        with patch.object(ThreatIntelligence, '_load_blacklists'):
            threat_intel = ThreatIntelligence(data_dir=temp_data_dir, sources=test_sources, auto_refresh=False)
        
        # Mock the URL response
        mock_content = b"192.0.2.1\n192.0.2.2\n198.51.100.0/24"
        
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = mock_content
            mock_urlopen.return_value.__enter__.return_value = mock_resp
            
            with patch.object(ThreatIntelligence, '_process_content') as mock_process:
                with patch.object(ThreatIntelligence, '_load_ip_set') as mock_load_ip_set:
                    mock_process.return_value = "192.0.2.1\n192.0.2.2\n198.51.100.0/24"
                    mock_load_ip_set.return_value = {"192.0.2.1", "192.0.2.2", "198.51.100.0/24"}
                    
                    # Test the download
                    result = threat_intel._download_blacklist("test_source", "https://example.com/list.txt")
                    
                    # Verify result
                    assert result is True
                    mock_urlopen.assert_called_once()
                    mock_process.assert_called_once()
                    mock_load_ip_set.assert_called_once()
    
    @patch('os.makedirs')
    def test_process_content(self, mock_makedirs, temp_data_dir):
        """Test processing blacklist content."""
        threat_intel = ThreatIntelligence(data_dir=temp_data_dir)
        
        # Test processing FireHOL content
        firehol_content = """# FireHOL Level1
192.0.2.1
192.0.2.2
198.51.100.0/24
"""
        processed = threat_intel._process_content("firehol_level1", firehol_content)
        assert processed == firehol_content
        
        # Test processing Emerging Threats content
        et_content = """# Emerging Threats
# 192.0.2.1
192.0.2.2
# Comment
198.51.100.1
invalid_ip
"""
        processed = threat_intel._process_content("emerging_threats", et_content)
        # Should only include valid IPs and remove comments
        assert "192.0.2.2" in processed
        assert "198.51.100.1" in processed
        assert "# Comment" not in processed
        assert "invalid_ip" not in processed
    
    @patch('os.makedirs')
    def test_is_malicious(self, mock_makedirs, temp_data_dir):
        """Test checking if an IP is malicious."""
        # Setup test data
        threat_intel = ThreatIntelligence(data_dir=temp_data_dir)
        threat_intel.blacklists = {
            "source1": {"192.0.2.1", "192.0.2.2", "198.51.100.0/24"},
            "source2": {"203.0.113.1", "203.0.113.2"}
        }
        
        # Test exact IP match
        assert threat_intel.is_malicious("192.0.2.1") is True
        assert threat_intel.is_malicious("192.0.2.3") is False
        
        # Test CIDR match
        assert threat_intel.is_malicious("198.51.100.42") is True
        
        # Test with check_all=True
        results = threat_intel.is_malicious("192.0.2.1", check_all=True)
        assert results["source1"] is True
        assert results["source2"] is False
        
        # Test invalid IP
        assert threat_intel.is_malicious("invalid_ip") is False
    
    def test_get_blacklist_info(self, temp_data_dir):
        """Test getting information about blacklists."""
        # Setup test data
        threat_intel = ThreatIntelligence(data_dir=temp_data_dir)
        now = time.time()
        yesterday = now - 86400
        
        threat_intel.metadata = {
            "source1": {
                "timestamp": now,
                "count": 100,
                "url": "https://example.com/list1.txt"
            },
            "source2": {
                "timestamp": yesterday,
                "count": 200,
                "url": "https://example.com/list2.txt"
            }
        }
        
        # Get info
        info = threat_intel.get_blacklist_info()
        
        # Check info
        assert "source1" in info
        assert "source2" in info
        assert info["source1"]["count"] == 100
        assert info["source2"]["count"] == 200
        assert "updated" in info["source1"]
        assert "age" in info["source1"]
    
    def test_enrich_dataframe(self, sample_df, temp_data_dir):
        """Test enriching a DataFrame with threat intelligence data."""
        # Setup test data
        threat_intel = ThreatIntelligence(data_dir=temp_data_dir)
        threat_intel.blacklists = {
            "source1": {"192.0.2.1", "198.51.100.0/24"},
            "source2": {"203.0.113.1"}
        }
        
        # Enrich DataFrame
        with patch.object(ThreatIntelligence, 'is_malicious') as mock_is_malicious:
            # Configure mock to return different results for different IPs
            def mock_is_malicious_impl(ip, check_all=False):
                if check_all:
                    if ip == "203.0.113.1":
                        return {"source1": False, "source2": True}
                    elif ip == "192.0.2.1":
                        return {"source1": True, "source2": False}
                    else:
                        return {"source1": False, "source2": False}
                else:
                    return ip in ["203.0.113.1", "192.0.2.1"]
                    
            mock_is_malicious.side_effect = mock_is_malicious_impl
            
            enriched_df = threat_intel.enrich_dataframe(sample_df)
            
            # Check result
            assert "threat_is_malicious" in enriched_df.columns
            assert "threat_source1" in enriched_df.columns
            assert "threat_source2" in enriched_df.columns
            
            # Numpy boolean comparison needs to be handled differently
            assert bool(enriched_df.loc[0, "threat_is_malicious"]) is True  # 203.0.113.1
            assert bool(enriched_df.loc[0, "threat_source2"]) is True
            assert bool(enriched_df.loc[0, "threat_source1"]) is False
            
            assert bool(enriched_df.loc[1, "threat_is_malicious"]) is True  # 192.0.2.1
            assert bool(enriched_df.loc[1, "threat_source1"]) is True
            assert bool(enriched_df.loc[1, "threat_source2"]) is False
            
            assert bool(enriched_df.loc[2, "threat_is_malicious"]) is False  # 198.51.100.1
            assert bool(enriched_df.loc[2, "threat_source1"]) is False
            assert bool(enriched_df.loc[2, "threat_source2"]) is False