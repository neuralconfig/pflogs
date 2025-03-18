"""
Tests for the setup_cron.py script.
"""

import os
import sys
import pytest
import tempfile
from unittest.mock import patch, mock_open, MagicMock, call

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import the function directly from the scripts module
from scripts.setup_cron import setup_cron_job

# Reference to the module for patching
import scripts.setup_cron


class TestSetupCron:
    """Test the cron job setup functionality."""
    
    @patch('subprocess.run')
    @patch('os.chmod')
    @patch('os.unlink')
    def test_setup_cron_job_new(self, mock_unlink, mock_chmod, mock_run):
        """Test setting up a new cron job when none exists."""
        # Create a temp directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock crontab -l to return empty (no existing crontab)
            mock_run.side_effect = [
                MagicMock(),  # For crontab -l
                MagicMock()   # For crontab installation
            ]
            
            # Use multiple open mocks to handle different file operations
            with patch('builtins.open', mock_open(read_data="")) as m:
                # Run the function
                result = setup_cron_job(project_dir=temp_dir)
                
                # Check results
                assert result is True
                mock_chmod.assert_called_once()
                mock_unlink.assert_called_once()
                assert mock_run.call_count == 2
                
                # Check write calls - should include the new cron job
                write_calls = [call[0][0] for call in m().write.call_args_list if len(call[0]) > 0]
                # Only check strings
                string_calls = [arg for arg in write_calls if isinstance(arg, str)]
                assert any("# Daily update of threat intelligence feeds" in arg for arg in string_calls)
                assert any("update_threat_intel.py" in arg for arg in string_calls)
    
    @patch('subprocess.run')
    @patch('os.chmod')
    @patch('os.unlink')
    def test_setup_cron_job_existing(self, mock_unlink, mock_chmod, mock_run):
        """Test when cron job already exists."""
        # Create a temporary directory path but don't actually create it
        temp_dir = "/tmp/mock_test_dir"
        
        # Define the update script path
        update_script = os.path.join(temp_dir, "scripts", "update_threat_intel.py")
        
        # Mock existing crontab with our script already in it
        existing_crontab = f"# Existing jobs\n0 0 * * * some_other_job\n# Already added\n0 3 * * * {update_script}\n"
        
        # Mock cron file path
        with patch('tempfile.mktemp', return_value='/tmp/threat_intel_cron'):
            # Mock run command
            mock_run.return_value = MagicMock()
            
            # Mock open for reading existing crontab
            with patch('builtins.open', mock_open(read_data=existing_crontab)) as m:
                # Run the function
                result = setup_cron_job(project_dir=temp_dir)
                
                # Check results
                assert result is True
                mock_chmod.assert_called_once()
                mock_unlink.assert_called_once()
                
                # Should not add the job again
                write_calls = [call[0][0] for call in m().write.call_args_list if len(call[0]) > 0]
                string_calls = [arg for arg in write_calls if isinstance(arg, str)]
                assert not any("# Daily update of threat intelligence feeds" in arg for arg in string_calls)
    
    @patch('subprocess.run')
    @patch('os.chmod')
    @patch('os.unlink')
    def test_setup_cron_job_custom_time(self, mock_unlink, mock_chmod, mock_run):
        """Test setting up cron job with custom time."""
        # Create a mock directory path
        temp_dir = "/tmp/mock_test_dir"
        
        # Mock cron file path
        with patch('tempfile.mktemp', return_value='/tmp/threat_intel_cron'):
            # Mock empty crontab
            mock_run.side_effect = [
                MagicMock(),  # For crontab -l
                MagicMock()   # For crontab installation
            ]
            
            # Mock open for reading empty crontab
            with patch('builtins.open', mock_open(read_data="")) as m:
                # Run the function with custom time
                custom_time = "30 4 * * *"
                result = setup_cron_job(project_dir=temp_dir, time=custom_time)
                
                # Check results
                assert result is True
                mock_chmod.assert_called_once()
                mock_unlink.assert_called_once()
                
                # Check write calls - should include custom time
                write_calls = [call[0][0] for call in m().write.call_args_list if len(call[0]) > 0]
                string_calls = [arg for arg in write_calls if isinstance(arg, str)]
                assert any(custom_time in arg for arg in string_calls)
    
    @patch('subprocess.run')
    @patch('os.chmod')
    @patch('os.unlink')
    def test_setup_cron_job_with_add_sources(self, mock_unlink, mock_chmod, mock_run):
        """Test setting up cron job with additional sources flag."""
        # Create a mock directory path
        temp_dir = "/tmp/mock_test_dir"
        
        # Mock cron file path
        with patch('tempfile.mktemp', return_value='/tmp/threat_intel_cron'):
            # Mock empty crontab
            mock_run.side_effect = [
                MagicMock(),  # For crontab -l
                MagicMock()   # For crontab installation
            ]
            
            # Mock open for reading empty crontab
            with patch('builtins.open', mock_open(read_data="")) as m:
                # Run the function with add_sources flag
                result = setup_cron_job(project_dir=temp_dir, add_sources=True)
                
                # Check results
                assert result is True
                mock_chmod.assert_called_once()
                mock_unlink.assert_called_once()
                
                # Check write calls - should include --add-sources flag
                write_calls = [call[0][0] for call in m().write.call_args_list if len(call[0]) > 0]
                string_calls = [arg for arg in write_calls if isinstance(arg, str)]
                assert any("--add-sources" in arg for arg in string_calls)
    
    @patch('subprocess.run')
    @patch('os.chmod')
    def test_setup_cron_job_exception(self, mock_chmod, mock_run):
        """Test handling exceptions during cron setup."""
        # Mock chmod to raise an exception
        mock_chmod.side_effect = PermissionError("Permission denied")
        
        # Create a mock directory path for the test
        with patch('tempfile.mktemp', return_value='/tmp/threat_intel_cron'):
            # Run the function
            result = setup_cron_job()
            
            # Check results
            assert result is False