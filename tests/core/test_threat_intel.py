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
import json

from pflogs.core.threat_intel import ThreatIntelligence, ThreatIntelError, ThreatIntelNetworkError
from pflogs.core.config import initialize_config, get_config


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


@pytest.fixture
def initialize_test_config():
    """Initialize test configuration."""
    # Initialize the config with test values
    initialize_config()
    config = get_config()
    config.update("threat_intel", "cache_size", 100)
    config.update("threat_intel", "batch_size", 5)
    config.update("processing", "max_workers", 2)
    return config


class TestThreatIntelligence:
    """Test the ThreatIntelligence class."""
    
    @patch('os.makedirs')
    def test_init(self, mock_makedirs, temp_data_dir, initialize_test_config):
        """Test initialization."""
        with patch.object(ThreatIntelligence, '_load_blacklists') as mock_load:
            # Test with data_dir
            threat_intel = ThreatIntelligence(data_dir=temp_data_dir)
            assert threat_intel.data_dir == temp_data_dir
            assert threat_intel.sources == ThreatIntelligence.DEFAULT_SOURCES
            assert threat_intel.auto_refresh is True
            mock_load.assert_called_once()
            mock_makedirs.assert_called_once_with(temp_data_dir, exist_ok=True)
    
    def test_write_metadata(self, temp_data_dir, initialize_test_config):
        """Test writing metadata."""
        threat_intel = ThreatIntelligence(data_dir=temp_data_dir)
        
        # Write metadata
        threat_intel._write_metadata("test_source", 1609459200.0, 100, "https://example.com/list.txt")
        
        # Verify metadata file was created
        meta_path = os.path.join(temp_data_dir, "test_source.meta")
        assert os.path.exists(meta_path)
        
        # Verify metadata content
        with open(meta_path, 'r') as f:
            metadata = json.load(f)
            assert metadata["timestamp"] == 1609459200.0
            assert metadata["count"] == 100
            assert metadata["url"] == "https://example.com/list.txt"
            assert "hash" in metadata
    
    def test_load_ip_set(self, temp_data_dir, initialize_test_config):
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
    
    def test_build_radix_tree(self, temp_data_dir, initialize_test_config):
        """Test building a radix tree."""
        threat_intel = ThreatIntelligence(data_dir=temp_data_dir)
        ip_set = {"192.0.2.1", "192.0.2.2", "198.51.100.0/24", "203.0.113.1"}
        
        # If radix is available, test the radix tree
        if hasattr(threat_intel, 'rtrees'):
            rtree = threat_intel._build_radix_tree(ip_set)
            if rtree is not None:  # Only test if radix is available
                # Test CIDR range
                assert rtree.search_best("198.51.100.42") is not None
                
                # Test individual IPs (should be converted to /32)
                assert rtree.search_best("192.0.2.1") is not None
                assert rtree.search_best("192.0.2.2") is not None
                assert rtree.search_best("203.0.113.1") is not None
                
                # Test non-matching IPs
                assert rtree.search_best("8.8.8.8") is None
                assert rtree.search_best("10.0.0.1") is None
    
    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_load_blacklists(self, mock_file, mock_exists, mock_makedirs, temp_data_dir, initialize_test_config):
        """Test loading blacklists."""
        # Setup mocks
        mock_exists.return_value = True
        mock_file.return_value.read.return_value = json.dumps({
            "timestamp": time.time(),
            "count": 100,
            "url": "https://example.com/list.txt"
        })
        
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
    def test_load_blacklists_outdated(self, mock_file, mock_exists, mock_makedirs, temp_data_dir, initialize_test_config):
        """Test loading outdated blacklists."""
        # Setup mocks
        mock_exists.return_value = True
        
        # Create an outdated timestamp (1 week ago)
        outdated_timestamp = time.time() - 7 * 86400
        mock_file.return_value.read.return_value = json.dumps({
            "timestamp": outdated_timestamp,
            "count": 100,
            "url": "https://example.com/list.txt"
        })
        
        # Test loading blacklists with auto-refresh
        with patch.object(ThreatIntelligence, '_load_ip_set') as mock_load_ip_set:
            with patch.object(ThreatIntelligence, 'refresh_blacklists') as mock_refresh:
                mock_load_ip_set.return_value = {"192.0.2.1", "192.0.2.2"}
                
                threat_intel = ThreatIntelligence(data_dir=temp_data_dir, auto_refresh=True)
                
                # Check that refresh_blacklists was called
                mock_refresh.assert_called_once()
    
    def test_download_blacklist(self, temp_data_dir, initialize_test_config):
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
                    with patch.object(ThreatIntelligence, '_write_metadata') as mock_write_metadata:
                        mock_process.return_value = "192.0.2.1\n192.0.2.2\n198.51.100.0/24"
                        mock_load_ip_set.return_value = {"192.0.2.1", "192.0.2.2", "198.51.100.0/24"}
                        
                        # Test the download
                        result = threat_intel._download_blacklist("test_source", "https://example.com/list.txt")
                        
                        # Verify result
                        assert result is True
                        mock_urlopen.assert_called_once()
                        mock_process.assert_called_once()
                        mock_load_ip_set.assert_called_once()
                        mock_write_metadata.assert_called_once()
    
    @patch('os.makedirs')
    def test_process_content(self, mock_makedirs, temp_data_dir, initialize_test_config):
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
    def test_check_ip_in_cidr_ranges(self, mock_makedirs, temp_data_dir, initialize_test_config):
        """Test checking IP in CIDR ranges."""
        threat_intel = ThreatIntelligence(data_dir=temp_data_dir)
        
        # Mock blacklists
        threat_intel.blacklists = {
            "source1": {"192.0.2.0/24", "198.51.100.0/24"}
        }
        
        # Set up test IPs
        ip1 = ipaddress.ip_address("192.0.2.42")
        ip2 = ipaddress.ip_address("198.51.100.42")
        ip3 = ipaddress.ip_address("203.0.113.42")
        
        # Test with manual CIDR checking
        assert threat_intel._check_ip_in_cidr_ranges(ip1, "source1") is True
        assert threat_intel._check_ip_in_cidr_ranges(ip2, "source1") is True
        assert threat_intel._check_ip_in_cidr_ranges(ip3, "source1") is False
    
    @patch('os.makedirs')
    def test_is_malicious_impl(self, mock_makedirs, temp_data_dir, initialize_test_config):
        """Test checking if an IP is malicious."""
        # Setup test data
        threat_intel = ThreatIntelligence(data_dir=temp_data_dir)
        threat_intel.blacklists = {
            "source1": {"192.0.2.1", "192.0.2.2", "198.51.100.0/24"},
            "source2": {"203.0.113.1", "203.0.113.2"}
        }
        
        # Test exact IP match
        assert threat_intel._is_malicious_impl("192.0.2.1") is True
        assert threat_intel._is_malicious_impl("192.0.2.3") is False
        
        # Test with invalid IP
        assert threat_intel._is_malicious_impl("invalid_ip") is False
        
        # Test with check_all=True
        results = threat_intel._is_malicious_impl("192.0.2.1", check_all=True)
        assert results["source1"] is True
        assert results["source2"] is False
        
        # Mock CIDR check
        with patch.object(ThreatIntelligence, '_check_ip_in_cidr_ranges') as mock_cidr_check:
            mock_cidr_check.return_value = True
            assert threat_intel._is_malicious_impl("198.51.100.42") is True
    
    def test_get_blacklist_info(self, temp_data_dir, initialize_test_config):
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
    
    def test_process_ips_in_chunks(self, temp_data_dir, initialize_test_config):
        """Test processing IPs in chunks."""
        threat_intel = ThreatIntelligence(data_dir=temp_data_dir)
        
        # Mock the is_malicious method
        with patch.object(threat_intel, 'is_malicious') as mock_is_malicious:
            mock_is_malicious.side_effect = [
                {"source1": True, "source2": False},
                {"source1": False, "source2": True},
                {"source1": False, "source2": False},
                {"source1": True, "source2": True},
                {"source1": False, "source2": False},
            ]
            
            # Test with chunk_size=2
            ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]
            chunks = list(threat_intel.process_ips_in_chunks(ips, chunk_size=2))
            
            # Check chunks
            assert len(chunks) == 3
            assert len(chunks[0][0]) == 2  # First chunk has 2 IPs
            assert len(chunks[1][0]) == 2  # Second chunk has 2 IPs
            assert len(chunks[2][0]) == 1  # Third chunk has 1 IP
            
            # Check results
            assert chunks[0][1][0]["source1"] is True  # First IP is malicious in source1
            assert chunks[0][1][1]["source2"] is True  # Second IP is malicious in source2
    
    def test_enrich_dataframe(self, sample_df, temp_data_dir, initialize_test_config):
        """Test enriching a DataFrame with threat intelligence data."""
        # Setup test data
        threat_intel = ThreatIntelligence(data_dir=temp_data_dir)
        threat_intel.blacklists = {
            "source1": {"192.0.2.1", "198.51.100.0/24"},
            "source2": {"203.0.113.1"}
        }
        
        # Mock the process_ips_in_chunks method
        with patch.object(threat_intel, 'process_ips_in_chunks') as mock_process:
            # Configure mock to return predefined chunks and results
            mock_process.return_value = [
                (
                    ["203.0.113.1", "192.0.2.1", "198.51.100.1"],  # IPs
                    [
                        {"source1": False, "source2": True},  # 203.0.113.1
                        {"source1": True, "source2": False},   # 192.0.2.1
                        {"source1": True, "source2": False}    # 198.51.100.1 (in CIDR range)
                    ]
                )
            ]
            
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
            
            assert bool(enriched_df.loc[2, "threat_is_malicious"]) is True  # 198.51.100.1
            assert bool(enriched_df.loc[2, "threat_source1"]) is True
            assert bool(enriched_df.loc[2, "threat_source2"]) is False