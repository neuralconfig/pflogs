"""
Configuration Management Module.

This module provides a unified configuration system to handle settings consistently
across the pflogs package. It includes defaults and overrides from environment variables
and configuration files.
"""

import os
import json
import logging
from typing import Dict, Any, Optional, Union, List
from pathlib import Path

# Configure logging
logger = logging.getLogger(__name__)

class Config:
    """Configuration manager for pflogs.
    
    This class provides a unified way to access configuration settings across
    the pflogs package. It supports defaults, environment variables,
    and configuration files.
    
    Attributes:
        config_file: Path to the configuration file
        settings: Dictionary of all configuration settings
    """
    
    # Default configuration settings
    DEFAULT_CONFIG = {
        # Geolocation settings
        "geo": {
            "db_path": None,
            "asn_db_path": None,
            "cache_size": 1000,
            "batch_size": 1000,
        },
        # Threat intelligence settings
        "threat_intel": {
            "data_dir": None,
            "refresh_interval": 86400,  # 24 hours
            "auto_refresh": True,
            "cache_size": 100000,       # LRU cache size
            "batch_size": 50,           # Batch size for progress reporting
        },
        # Processing settings
        "processing": {
            "chunk_size": 100000,      # Default chunk size for large files
            "max_workers": 4,          # Default number of workers for parallel processing
            "memory_limit": "1GB",     # Default memory limit
        },
        # Logging settings
        "logging": {
            "level": "INFO",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "file": None,
        }
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize the configuration manager.
        
        Args:
            config_file: Optional path to a JSON configuration file
        """
        self.config_file = config_file
        self.settings = self.DEFAULT_CONFIG.copy()
        
        # Load from environment variables
        self._load_from_env()
        
        # Load from configuration file if provided
        if config_file:
            self._load_from_file(config_file)
        
        # Configure logging
        self._configure_logging()
    
    def _load_from_env(self) -> None:
        """Load configuration from environment variables."""
        # Geo settings
        if os.environ.get("PFLOGS_GEO_DB_PATH"):
            self.settings["geo"]["db_path"] = os.environ.get("PFLOGS_GEO_DB_PATH")
        
        if os.environ.get("PFLOGS_ASN_DB_PATH"):
            self.settings["geo"]["asn_db_path"] = os.environ.get("PFLOGS_ASN_DB_PATH")
        
        if os.environ.get("PFLOGS_GEO_CACHE_SIZE"):
            try:
                cache_size = int(os.environ.get("PFLOGS_GEO_CACHE_SIZE", "1000"))
                self.settings["geo"]["cache_size"] = cache_size
            except ValueError:
                logger.warning("Invalid PFLOGS_GEO_CACHE_SIZE, using default")
        
        # Threat intel settings
        if os.environ.get("PFLOGS_THREAT_DATA_DIR"):
            self.settings["threat_intel"]["data_dir"] = os.environ.get("PFLOGS_THREAT_DATA_DIR")
        
        if os.environ.get("PFLOGS_THREAT_REFRESH_INTERVAL"):
            try:
                interval = int(os.environ.get("PFLOGS_THREAT_REFRESH_INTERVAL", "86400"))
                self.settings["threat_intel"]["refresh_interval"] = interval
            except ValueError:
                logger.warning("Invalid PFLOGS_THREAT_REFRESH_INTERVAL, using default")
        
        if os.environ.get("PFLOGS_THREAT_CACHE_SIZE"):
            try:
                cache_size = int(os.environ.get("PFLOGS_THREAT_CACHE_SIZE", "100000"))
                self.settings["threat_intel"]["cache_size"] = cache_size
            except ValueError:
                logger.warning("Invalid PFLOGS_THREAT_CACHE_SIZE, using default")
        
        # Processing settings
        if os.environ.get("PFLOGS_CHUNK_SIZE"):
            try:
                chunk_size = int(os.environ.get("PFLOGS_CHUNK_SIZE", "100000"))
                self.settings["processing"]["chunk_size"] = chunk_size
            except ValueError:
                logger.warning("Invalid PFLOGS_CHUNK_SIZE, using default")
        
        if os.environ.get("PFLOGS_MAX_WORKERS"):
            try:
                max_workers = int(os.environ.get("PFLOGS_MAX_WORKERS", "4"))
                self.settings["processing"]["max_workers"] = max_workers
            except ValueError:
                logger.warning("Invalid PFLOGS_MAX_WORKERS, using default")
        
        if os.environ.get("PFLOGS_MEMORY_LIMIT"):
            self.settings["processing"]["memory_limit"] = os.environ.get("PFLOGS_MEMORY_LIMIT")
        
        # Logging settings
        if os.environ.get("PFLOGS_LOG_LEVEL"):
            self.settings["logging"]["level"] = os.environ.get("PFLOGS_LOG_LEVEL")
        
        if os.environ.get("PFLOGS_LOG_FILE"):
            self.settings["logging"]["file"] = os.environ.get("PFLOGS_LOG_FILE")
    
    def _load_from_file(self, config_file: str) -> None:
        """Load configuration from a JSON file.
        
        Args:
            config_file: Path to a JSON configuration file
        """
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                
                # Update settings with file configuration
                for section, settings in file_config.items():
                    if section in self.settings:
                        if isinstance(settings, dict) and isinstance(self.settings[section], dict):
                            # Update section settings
                            self.settings[section].update(settings)
                        else:
                            # Replace section settings
                            self.settings[section] = settings
                    else:
                        # Add new section
                        self.settings[section] = settings
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Error loading configuration from {config_file}: {e}")
    
    def _configure_logging(self) -> None:
        """Configure logging based on settings."""
        log_config = self.settings["logging"]
        
        log_level = getattr(logging, log_config["level"], logging.INFO)
        log_format = log_config["format"]
        log_file = log_config["file"]
        
        # Configure root logger
        logging.basicConfig(
            level=log_level,
            format=log_format,
            filename=log_file
        )
    
    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """Get a configuration setting.
        
        Args:
            section: Section name
            key: Setting key within the section (optional)
            default: Default value if section/key is not found
            
        Returns:
            Configuration value or default
        """
        if section not in self.settings:
            return default
        
        if key is None:
            return self.settings[section]
        
        if key not in self.settings[section]:
            return default
        
        return self.settings[section][key]
    
    def update(self, section: str, key: str, value: Any) -> None:
        """Update a configuration setting.
        
        Args:
            section: Section name
            key: Setting key within the section
            value: New value
        """
        if section not in self.settings:
            self.settings[section] = {}
        
        self.settings[section][key] = value
    
    def save(self, file_path: Optional[str] = None) -> None:
        """Save configuration to a JSON file.
        
        Args:
            file_path: Path to save the configuration (defaults to self.config_file)
        """
        file_path = file_path or self.config_file
        if not file_path:
            logger.warning("No configuration file specified, cannot save")
            return
        
        try:
            with open(file_path, 'w') as f:
                json.dump(self.settings, f, indent=2)
            logger.info(f"Configuration saved to {file_path}")
        except IOError as e:
            logger.error(f"Error saving configuration to {file_path}: {e}")


# Create a global config instance
_global_config = Config()

def get_config() -> Config:
    """Get the global configuration instance.
    
    Returns:
        Global Config instance
    """
    return _global_config

def initialize_config(config_file: Optional[str] = None) -> Config:
    """Initialize the global configuration.
    
    Args:
        config_file: Optional path to a JSON configuration file
        
    Returns:
        Updated global Config instance
    """
    global _global_config
    _global_config = Config(config_file)
    return _global_config