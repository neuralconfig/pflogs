"""
Tests for the update_threat_intel.py script.
"""

import os
import sys
import pytest
import tempfile
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import the function directly from the scripts module
from scripts.update_threat_intel import update_threat_intel

# Reference to the module for patching
import scripts.update_threat_intel


class TestUpdateThreatIntel:
    """Test the threat intelligence update functionality."""
    
    @patch('scripts.update_threat_intel.ThreatIntelligence')
    def test_update_threat_intel_success(self, mock_threat_intel_class):
        """Test successful update of threat intel feeds."""
        # Set up mock
        mock_threat_intel = MagicMock()
        mock_threat_intel.refresh_blacklists.return_value = True
        mock_threat_intel.get_blacklist_info.return_value = {
            "source1": {
                "count": 100,
                "updated": "2023-01-01 12:00:00",
                "url": "https://example.com/list1.txt",
                "age": "1 day, 0:00:00"
            },
            "source2": {
                "count": 200,
                "updated": "2023-01-01 12:00:00",
                "url": "https://example.com/list2.txt",
                "age": "0:30:00"
            }
        }
        mock_threat_intel_class.return_value = mock_threat_intel
        
        # Create a temp directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test update with default sources
            result = update_threat_intel(data_dir=temp_dir)
            
            # Check results
            assert result is True
            mock_threat_intel_class.assert_called_once()
            mock_threat_intel.refresh_blacklists.assert_called_once()
            mock_threat_intel.get_blacklist_info.assert_called_once()
    
    @patch('scripts.update_threat_intel.ThreatIntelligence')
    def test_update_threat_intel_with_add_sources(self, mock_threat_intel_class):
        """Test update with additional sources."""
        # Set up mock
        mock_threat_intel = MagicMock()
        mock_threat_intel.refresh_blacklists.return_value = True
        mock_threat_intel.get_blacklist_info.return_value = {
            "source1": {"count": 100, "updated": "2023-01-01 12:00:00", "age": "0:00:00"},
            "source2": {"count": 200, "updated": "2023-01-01 12:00:00", "age": "0:00:00"},
            "firehol_level2": {"count": 300, "updated": "2023-01-01 12:00:00", "age": "0:00:00"}
        }
        mock_threat_intel_class.return_value = mock_threat_intel
        
        # Create a temp directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test update with additional sources
            result = update_threat_intel(data_dir=temp_dir, add_sources=True)
            
            # Check results
            assert result is True
            
            # Verify the constructor was called with sources
            constructor_call = mock_threat_intel_class.call_args
            # Check that sources parameter is not None
            assert constructor_call[1]['sources'] is not None
            # Should include at least one additional source
            assert len(constructor_call[1]['sources']) > 2
    
    @patch('scripts.update_threat_intel.ThreatIntelligence')
    def test_update_threat_intel_failure(self, mock_threat_intel_class):
        """Test handling of update failure."""
        # Set up mock to simulate failure
        mock_threat_intel = MagicMock()
        mock_threat_intel.refresh_blacklists.return_value = False
        mock_threat_intel_class.return_value = mock_threat_intel
        
        # Create a temp directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test failed update
            result = update_threat_intel(data_dir=temp_dir)
            
            # Check results
            assert result is False
            mock_threat_intel.refresh_blacklists.assert_called_once()
    
    @patch('scripts.update_threat_intel.ThreatIntelligence')
    def test_update_threat_intel_exception(self, mock_threat_intel_class):
        """Test handling of exceptions during update."""
        # Set up mock to raise exception
        mock_threat_intel_class.side_effect = Exception("Test error")
        
        # Create a temp directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test update with exception
            result = update_threat_intel(data_dir=temp_dir)
            
            # Check results
            assert result is False
    
    def test_update_threat_intel_directory_creation(self):
        """Test that the data directory is created if it doesn't exist."""
        # Create a temp directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a nonexistent subdirectory path
            data_dir = os.path.join(temp_dir, "nonexistent", "threat")
            
            # Patch to prevent actual execution of ThreatIntelligence
            with patch('scripts.update_threat_intel.ThreatIntelligence') as mock_threat_intel_class:
                mock_threat_intel = MagicMock()
                mock_threat_intel.refresh_blacklists.return_value = True
                mock_threat_intel.get_blacklist_info.return_value = {}
                mock_threat_intel_class.return_value = mock_threat_intel
                
                # Run the update
                update_threat_intel(data_dir=data_dir)
                
                # Check that directory was created
                assert os.path.exists(data_dir)