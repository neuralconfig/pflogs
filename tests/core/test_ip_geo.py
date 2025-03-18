"""
Tests for the IP Geolocation module.
"""

import os
import pytest
import pandas as pd
import geoip2.errors
from unittest.mock import patch, MagicMock
from pflogs.core.ip_geo import IPGeolocation, enrich_logs_with_geo, process_df_in_chunks
from pflogs.core.config import initialize_config, get_config


@pytest.fixture
def mock_geoip_response():
    """Create a mock GeoIP response object."""
    # Create mock objects for each response component
    mock_country = MagicMock()
    mock_country.iso_code = "US"
    mock_country.name = "United States"
    
    mock_city = MagicMock()
    mock_city.name = "New York"
    
    mock_location = MagicMock()
    mock_location.latitude = 40.7128
    mock_location.longitude = -74.0060
    mock_location.accuracy_radius = 50
    mock_location.time_zone = "America/New_York"
    
    mock_continent = MagicMock()
    mock_continent.name = "North America"
    
    mock_subdivision = MagicMock()
    mock_subdivision.name = "New York"
    mock_subdivision.iso_code = "NY"
    
    mock_subdivisions = MagicMock()
    mock_subdivisions.most_specific = mock_subdivision
    mock_subdivisions.__bool__ = lambda self: True
    
    mock_postal = MagicMock()
    mock_postal.code = "10001"
    
    # Create the main response object
    mock_response = MagicMock()
    mock_response.country = mock_country
    mock_response.city = mock_city
    mock_response.location = mock_location
    mock_response.continent = mock_continent
    mock_response.subdivisions = mock_subdivisions
    mock_response.postal = mock_postal
    
    return mock_response


@pytest.fixture
def mock_asn_response():
    """Create a mock GeoIP ASN response object."""
    mock_response = MagicMock()
    mock_response.autonomous_system_number = 15169
    mock_response.autonomous_system_organization = "Google LLC"
    mock_response.network = "8.8.8.0/24"
    
    return mock_response


@pytest.fixture
def sample_df():
    """Create a sample DataFrame for testing."""
    return pd.DataFrame({
        "timestamp": ["2023-01-01T12:00:00"],
        "action": ["block"],
        "src_ip": ["203.0.113.1"],
        "dst_ip": ["192.168.1.1"],
    })


@pytest.fixture
def initialize_test_config():
    """Initialize test configuration."""
    # Initialize the config with test values
    initialize_config()
    config = get_config()
    config.update("processing", "chunk_size", 10)
    config.update("processing", "max_workers", 2)
    config.update("geo", "cache_size", 100)
    return config


class TestIPGeolocation:
    """Test the IPGeolocation class."""
    
    @patch("geoip2.database.Reader")
    def test_init_geo_only(self, mock_reader, initialize_test_config):
        """Test initialization with only geo database."""
        with patch("os.path.exists", return_value=True):
            geo = IPGeolocation("/path/to/db.mmdb")
            assert geo.geo_db_path == "/path/to/db.mmdb"
            assert geo.asn_db_path is None
            assert geo.asn_reader is None
            mock_reader.assert_called_once_with("/path/to/db.mmdb")
    
    @patch("geoip2.database.Reader")
    def test_init_geo_and_asn(self, mock_reader, initialize_test_config):
        """Test initialization with both geo and ASN databases."""
        with patch("os.path.exists", return_value=True):
            geo = IPGeolocation("/path/to/geo.mmdb", "/path/to/asn.mmdb")
            assert geo.geo_db_path == "/path/to/geo.mmdb"
            assert geo.asn_db_path == "/path/to/asn.mmdb"
            assert geo.asn_reader is not None
            assert mock_reader.call_count == 2
    
    @patch("geoip2.database.Reader")
    def test_init_file_not_found(self, mock_reader, initialize_test_config):
        """Test initialization with a non-existent database path."""
        with patch("os.path.exists", return_value=False):
            with pytest.raises(FileNotFoundError):
                IPGeolocation("/path/to/nonexistent.mmdb")
    
    @patch("geoip2.database.Reader")
    def test_init_invalid_db(self, mock_reader, initialize_test_config):
        """Test initialization with an invalid database."""
        with patch("os.path.exists", return_value=True):
            mock_reader.side_effect = Exception("Invalid database")
            with pytest.raises(Exception):
                IPGeolocation("/path/to/invalid.mmdb")
    
    @patch("geoip2.database.Reader")
    def test_init_invalid_asn_db(self, mock_reader, initialize_test_config):
        """Test initialization with an invalid ASN database."""
        with patch("os.path.exists", return_value=True):
            # First call is for geo db (success), second call is for ASN db (fail)
            mock_reader.side_effect = [MagicMock(), Exception("Invalid ASN database")]
            with pytest.raises(Exception):
                IPGeolocation("/path/to/geo.mmdb", "/path/to/invalid_asn.mmdb")
    
    def test_is_private_ip(self, initialize_test_config):
        """Test private IP detection."""
        with patch("os.path.exists", return_value=True):
            with patch("geoip2.database.Reader"):
                geo = IPGeolocation("/path/to/db.mmdb")
                
                # Private IPs
                assert geo.is_private_ip("192.168.1.1") is True
                assert geo.is_private_ip("10.0.0.1") is True
                assert geo.is_private_ip("172.16.0.1") is True
                assert geo.is_private_ip("127.0.0.1") is True
                
                # Public IPs
                assert geo.is_private_ip("8.8.8.8") is False
                
                # Documentation/test range IPs (actually reserved but we'll treat as public for tests)
                with patch("ipaddress.ip_address") as mock_ip_address:
                    mock_ip = MagicMock()
                    mock_ip.is_private = False
                    mock_ip.is_reserved = False
                    mock_ip.is_loopback = False
                    mock_ip.is_multicast = False
                    mock_ip_address.return_value = mock_ip
                    
                    assert geo.is_private_ip("203.0.113.1") is False
                
                # Invalid IP
                assert geo.is_private_ip("not_an_ip") is False
    
    @patch("geoip2.database.Reader")
    def test_lookup_asn(self, mock_reader, mock_asn_response, initialize_test_config):
        """Test ASN lookup."""
        with patch("os.path.exists", return_value=True):
            # Setup mock reader
            reader_instance = mock_reader.return_value
            reader_instance.asn.return_value = mock_asn_response
            
            # Test with ASN database
            geo = IPGeolocation("/path/to/geo.mmdb", "/path/to/asn.mmdb")
            
            # Override is_private_ip for test
            with patch.object(IPGeolocation, 'is_private_ip', return_value=False):
                # Test a public IP
                result = geo._lookup_asn_impl("8.8.8.8")
                assert result["asn"] == 15169
                assert result["asn_org"] == "Google LLC"
                assert result["network"] == "8.8.8.0/24"
                
                # Test IP not found
                reader_instance.asn.side_effect = geoip2.errors.AddressNotFoundError("not found")
                result = geo._lookup_asn_impl("203.0.113.1")
                assert result is None
            
            # Test a private IP
            with patch.object(IPGeolocation, 'is_private_ip', return_value=True):
                result = geo._lookup_asn_impl("192.168.1.1")
                assert result is None
            
            # Test with no ASN database
            with patch.object(IPGeolocation, 'is_private_ip', return_value=False):
                geo = IPGeolocation("/path/to/geo.mmdb")  # No ASN database
                assert geo._lookup_asn_impl("8.8.8.8") is None
    
    @patch("geoip2.database.Reader")
    def test_lookup_ip_with_asn(self, mock_reader, mock_geoip_response, mock_asn_response, initialize_test_config):
        """Test IP lookup with ASN data."""
        with patch("os.path.exists", return_value=True):
            # Setup mock readers
            reader_instance = mock_reader.return_value
            reader_instance.city.return_value = mock_geoip_response
            reader_instance.asn.return_value = mock_asn_response
            
            # Create geo instance with both databases
            geo = IPGeolocation("/path/to/geo.mmdb", "/path/to/asn.mmdb")
            
            # Override is_private_ip for test
            with patch.object(IPGeolocation, 'is_private_ip', return_value=False):
                # Mock the lookup_asn method
                with patch.object(IPGeolocation, 'lookup_asn', return_value={
                    "asn": 15169,
                    "asn_org": "Google LLC",
                    "network": "8.8.8.0/24"
                }):
                    # Test a public IP
                    result = geo._lookup_ip_impl("8.8.8.8")
                    
                    # Check city data
                    assert result["ip"] == "8.8.8.8"
                    assert result["country_code"] == "US"
                    assert result["country_name"] == "United States"
                    assert result["city"] == "New York"
                    
                    # Check ASN data
                    assert result["asn"] == 15169
                    assert result["asn_org"] == "Google LLC"
                    assert result["network"] == "8.8.8.0/24"
    
    @patch("geoip2.database.Reader")
    def test_lookup_ip(self, mock_reader, mock_geoip_response, initialize_test_config):
        """Test IP lookup without ASN data."""
        with patch("os.path.exists", return_value=True):
            # Setup mock reader to return our mock response
            reader_instance = mock_reader.return_value
            reader_instance.city.return_value = mock_geoip_response
            
            # Override is_private_ip for test
            with patch.object(IPGeolocation, 'is_private_ip', return_value=False):
                geo = IPGeolocation("/path/to/db.mmdb")
                
                # Test a public IP
                result = geo._lookup_ip_impl("203.0.113.1")
                assert result["ip"] == "203.0.113.1"
                assert result["country_code"] == "US"
                assert result["country_name"] == "United States"
                assert result["city"] == "New York"
                assert result["latitude"] == 40.7128
                assert result["longitude"] == -74.0060
                assert "asn" not in result
            
            # Test a private IP
            with patch.object(IPGeolocation, 'is_private_ip', return_value=True):
                geo = IPGeolocation("/path/to/db.mmdb")
                result = geo._lookup_ip_impl("192.168.1.1")
                assert result is None
            
            # Test IP not found
            with patch.object(IPGeolocation, 'is_private_ip', return_value=False):
                geo = IPGeolocation("/path/to/db.mmdb")
                reader_instance.city.side_effect = MagicMock(side_effect=geoip2.errors.AddressNotFoundError("not found"))
                result = geo._lookup_ip_impl("8.8.8.8")
                assert result is None
    
    @patch("geoip2.database.Reader")
    def test_process_ip_chunk(self, mock_reader, initialize_test_config):
        """Test processing a chunk of IP addresses."""
        with patch("os.path.exists", return_value=True):
            # Create a mock for lookup_ip
            geo = IPGeolocation("/path/to/db.mmdb")
            
            # Replace the lookup_ip method with a mock
            with patch.object(geo, 'lookup_ip', side_effect=[
                {"ip": "1.1.1.1", "country_name": "US"},
                {"ip": "2.2.2.2", "country_name": "CA"},
                None,  # For a private IP
            ]):
                result = geo._process_ip_chunk(["1.1.1.1", "2.2.2.2", "192.168.1.1"])
                
                # Check the results
                assert len(result) == 3
                assert result[0]["country_name"] == "US"
                assert result[1]["country_name"] == "CA"
                assert result[2] is None
    
    @patch("geoip2.database.Reader")
    def test_enrich_dataframe_with_asn(self, mock_reader, mock_geoip_response, mock_asn_response, sample_df, initialize_test_config):
        """Test enriching a DataFrame with geolocation and ASN data."""
        with patch("os.path.exists", return_value=True):
            # Setup mock readers
            reader_instance = mock_reader.return_value
            reader_instance.city.return_value = mock_geoip_response
            reader_instance.asn.return_value = mock_asn_response
            
            # Create a mock for _process_ip_chunk that returns expected data with ASN
            mock_geo_data = [{
                "ip": "203.0.113.1",
                "country_code": "US",
                "country_name": "United States",
                "city": "New York",
                "latitude": 40.7128,
                "longitude": -74.0060,
                "asn": 15169,
                "asn_org": "Google LLC",
                "network": "203.0.113.0/24"
            }]
            
            with patch.object(IPGeolocation, '_process_ip_chunk', return_value=mock_geo_data):
                geo = IPGeolocation("/path/to/geo.mmdb", "/path/to/asn.mmdb")
                
                # Enrich the sample DataFrame
                result_df = geo.enrich_dataframe(sample_df)
                
                # Check if geolocation columns are added
                assert "geo_country_name" in result_df.columns
                assert "geo_city" in result_df.columns
                
                # Check if ASN columns are added
                assert "geo_asn" in result_df.columns
                assert "geo_asn_org" in result_df.columns
                assert "geo_network" in result_df.columns
                
                # Check the values
                assert result_df.loc[0, "geo_country_name"] == "United States"
                assert result_df.loc[0, "geo_city"] == "New York"
                assert result_df.loc[0, "geo_asn"] == 15169
                assert result_df.loc[0, "geo_asn_org"] == "Google LLC"
    
    @patch("geoip2.database.Reader")
    def test_enrich_dataframe(self, mock_reader, mock_geoip_response, sample_df, initialize_test_config):
        """Test enriching a DataFrame with geolocation data only."""
        with patch("os.path.exists", return_value=True):
            # Setup mock reader
            reader_instance = mock_reader.return_value
            reader_instance.city.return_value = mock_geoip_response
            
            # Create a mock for _process_ip_chunk that returns expected data
            mock_geo_data = [{
                "ip": "203.0.113.1",
                "country_code": "US",
                "country_name": "United States",
                "city": "New York",
                "latitude": 40.7128,
                "longitude": -74.0060,
                "accuracy_radius": 50,
                "time_zone": "America/New_York",
                "continent": "North America",
                "subdivision": "New York",
                "subdivision_code": "NY",
                "postal_code": "10001"
            }]
            
            with patch.object(IPGeolocation, '_process_ip_chunk', return_value=mock_geo_data):
                geo = IPGeolocation("/path/to/db.mmdb")
                
                # Enrich the sample DataFrame
                result_df = geo.enrich_dataframe(sample_df)
                
                # Check if geolocation columns are added
                assert "geo_country_code" in result_df.columns
                assert "geo_country_name" in result_df.columns
                assert "geo_city" in result_df.columns
                assert "geo_latitude" in result_df.columns
                assert "geo_longitude" in result_df.columns
                
                # Check the values
                assert result_df.loc[0, "geo_country_name"] == "United States"
                assert result_df.loc[0, "geo_city"] == "New York"
            
            # Test with a non-existent column
            geo = IPGeolocation("/path/to/db.mmdb")
            with pytest.raises(ValueError):
                geo.enrich_dataframe(sample_df, "nonexistent_column")
    
    @patch("geoip2.database.Reader")
    def test_batch_lookup(self, mock_reader, initialize_test_config):
        """Test batch lookup of IP addresses."""
        with patch("os.path.exists", return_value=True):
            geo = IPGeolocation("/path/to/db.mmdb")
            
            # Create a mock for _process_ip_chunk
            mock_chunk_results = [
                {"ip": "203.0.113.1", "country_name": "United States"},
                None,  # For a private IP
                {"ip": "8.8.8.8", "country_name": "United States"}
            ]
            
            with patch.object(geo, '_process_ip_chunk', return_value=mock_chunk_results):
                # Test batch lookup
                results = geo.batch_lookup(["203.0.113.1", "192.168.1.1", "8.8.8.8"])
                
                # Check results
                assert len(results) == 3
                assert results[0]["country_name"] == "United States"  # Public IP
                assert results[1] is None  # Private IP
                assert results[2]["country_name"] == "United States"  # Public IP
    
    @patch("geoip2.database.Reader")
    def test_create_geodata_series(self, mock_reader, initialize_test_config):
        """Test creation of geodata series."""
        with patch("os.path.exists", return_value=True):
            # Create a properly enriched DataFrame to use for testing
            df = pd.DataFrame({
                "src_ip": ["203.0.113.1", "203.0.113.2", "192.168.1.1", "8.8.8.8"],
                "geo_country_name": ["United States", "United States", None, "United States"],
                "geo_city": ["New York", "Los Angeles", None, "Mountain View"]
            })
            
            # Mock the enrich_dataframe method to return our pre-enriched DataFrame
            with patch.object(IPGeolocation, 'enrich_dataframe', return_value=df):
                geo = IPGeolocation("/path/to/db.mmdb")
                
                # Create geodata series
                result_df = geo.create_geodata_series(df)
                
                # Check result
                assert "geo_country_name" in result_df.columns
                assert "geo_city" in result_df.columns
                assert "count" in result_df.columns
                assert len(result_df) > 0
            
            # Test with a non-existent column
            geo = IPGeolocation("/path/to/db.mmdb")
            with pytest.raises(ValueError):
                geo.create_geodata_series(df, "nonexistent_column")


def test_process_df_in_chunks(sample_df, initialize_test_config):
    """Test processing a DataFrame in chunks."""
    # Create a larger sample DataFrame
    large_df = pd.DataFrame({
        "timestamp": [f"2023-01-01T{i:02d}:00:00" for i in range(25)],
        "action": ["block"] * 25,
        "src_ip": [f"10.0.0.{i}" for i in range(25)],
        "dst_ip": ["192.168.1.1"] * 25,
    })
    
    # Process in chunks of 10
    chunks = list(process_df_in_chunks(large_df, 10))
    
    # Check that we got the expected number of chunks
    assert len(chunks) == 3
    assert len(chunks[0]) == 10
    assert len(chunks[1]) == 10
    assert len(chunks[2]) == 5


@patch("pflogs.core.ip_geo.IPGeolocation")
def test_enrich_logs_with_geo_dataframe(mock_ipgeo_class, sample_df, initialize_test_config):
    """Test enrich_logs_with_geo with a DataFrame."""
    # Setup mock
    mock_ipgeo = mock_ipgeo_class.return_value
    mock_ipgeo.enrich_dataframe.return_value = pd.DataFrame({
        "timestamp": ["2023-01-01T12:00:00"],
        "action": ["block"],
        "src_ip": ["203.0.113.1"],
        "dst_ip": ["192.168.1.1"],
        "geo_country_name": ["United States"],
        "geo_city": ["New York"],
    })
    
    # Test with DataFrame
    result = enrich_logs_with_geo(sample_df, "/path/to/db.mmdb")
    
    # Check result
    assert "geo_country_name" in result.columns
    assert "geo_city" in result.columns
    assert result.loc[0, "geo_country_name"] == "United States"
    
    # Test with output path
    with patch("pandas.DataFrame.to_parquet") as mock_to_parquet:
        result = enrich_logs_with_geo(sample_df, "/path/to/db.mmdb", output_path="/path/to/output.parquet")
        assert result is None
        mock_to_parquet.assert_called_once()


@patch("pflogs.core.ip_geo.IPGeolocation")
def test_enrich_logs_with_geo_file(mock_ipgeo_class, initialize_test_config):
    """Test enrich_logs_with_geo with a file path."""
    # Setup mocks
    mock_ipgeo = mock_ipgeo_class.return_value
    mock_ipgeo.enrich_dataframe.return_value = pd.DataFrame({
        "timestamp": ["2023-01-01T12:00:00"],
        "action": ["block"],
        "src_ip": ["203.0.113.1"],
        "dst_ip": ["192.168.1.1"],
        "geo_country_name": ["United States"],
        "geo_city": ["New York"],
    })
    
    # Test with file path
    with patch("os.path.exists", return_value=True):
        with patch("pandas.read_parquet") as mock_read_parquet:
            mock_read_parquet.return_value = pd.DataFrame({
                "timestamp": ["2023-01-01T12:00:00"],
                "action": ["block"],
                "src_ip": ["203.0.113.1"],
                "dst_ip": ["192.168.1.1"],
            })
            
            result = enrich_logs_with_geo("/path/to/logs.parquet", "/path/to/db.mmdb")
            
            # Check result
            assert "geo_country_name" in result.columns
            assert "geo_city" in result.columns
            
            # Test with output path
            with patch("pandas.DataFrame.to_parquet") as mock_to_parquet:
                result = enrich_logs_with_geo(
                    "/path/to/logs.parquet", 
                    "/path/to/db.mmdb", 
                    output_path="/path/to/output.parquet"
                )
                assert result is None
                mock_to_parquet.assert_called_once()
    
    # Test with non-existent file
    with patch("os.path.exists", return_value=False):
        with pytest.raises(FileNotFoundError):
            enrich_logs_with_geo("/path/to/nonexistent.parquet", "/path/to/db.mmdb")