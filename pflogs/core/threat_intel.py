"""
Threat Intelligence Module.

This module provides functionality to identify potentially malicious IP addresses 
using various threat intelligence feeds like FireHOL and Emerging Threats.
"""

import os
import re
import ipaddress
import urllib.request
import urllib.error
import time
import logging
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Union, Tuple, Any, Iterator, Generator
from functools import lru_cache
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

# Try to import radix tree for efficient CIDR lookups
try:
    import radix
    RADIX_AVAILABLE = True
except ImportError:
    RADIX_AVAILABLE = False
    logging.warning("py-radix not available, falling back to slower CIDR lookup method")

from .config import get_config

# Configure logging
logger = logging.getLogger(__name__)

class ThreatIntelError(Exception):
    """Base exception for ThreatIntelligence errors."""
    pass

class ThreatIntelNetworkError(ThreatIntelError):
    """Exception raised for network errors during threat feed downloads."""
    pass

class ThreatIntelDataError(ThreatIntelError):
    """Exception raised for errors processing threat feed data."""
    pass

class ThreatIntelligence:
    """Threat Intelligence handler for IP reputation data.
    
    This class provides functionality to detect potentially malicious IP addresses
    using various threat intelligence feeds.
    
    Attributes:
        data_dir: Directory to store threat intelligence data
        sources: Dictionary of threat intelligence sources with their URLs
        blacklists: Dictionary of IP sets from different sources
        rtrees: Dictionary of radix trees for efficient CIDR lookups
        metadata: Information about when each source was last updated
        last_refresh: Timestamp of when blacklists were last refreshed
    """
    
    # Default sources for threat intelligence
    DEFAULT_SOURCES = {
        "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "emerging_threats": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    }
    
    def __init__(self, data_dir: str = None, 
                 sources: Dict[str, str] = None,
                 refresh_interval: int = None,
                 auto_refresh: bool = None,
                 cache_size: int = None):
        """Initialize the Threat Intelligence handler.
        
        Args:
            data_dir: Directory to store threat intelligence data
            sources: Dictionary of threat intelligence sources with their URLs
            refresh_interval: How often to refresh the data in seconds
            auto_refresh: Whether to automatically refresh stale data when needed
            cache_size: Size of the LRU cache for IP lookups
            
        Raises:
            ValueError: If data_dir is not provided and cannot be determined
        """
        # Get configuration
        config = get_config()
        
        # Set the data directory
        if data_dir:
            self.data_dir = data_dir
        else:
            # Try to use the configured directory
            config_data_dir = config.get("threat_intel", "data_dir")
            if config_data_dir:
                self.data_dir = config_data_dir
            else:
                # Try to use a default directory
                script_dir = os.path.dirname(os.path.realpath(__file__))
                default_data_dir = os.path.abspath(os.path.join(script_dir, '..', '..', 'data', 'threat'))
                if os.path.exists(default_data_dir):
                    self.data_dir = default_data_dir
                else:
                    raise ValueError("Data directory must be provided or 'data/threat' must exist")
                    
        # Create the data directory if it doesn't exist
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Set the sources
        self.sources = sources if sources else self.DEFAULT_SOURCES
        
        # Get configuration values or use provided values
        self.refresh_interval = refresh_interval or config.get("threat_intel", "refresh_interval", 86400)
        self.auto_refresh = auto_refresh if auto_refresh is not None else config.get("threat_intel", "auto_refresh", True)
        self.cache_size = cache_size or config.get("threat_intel", "cache_size", 100000)
        
        # Configure LRU cache with bounded size
        # We create a class-level decorator that applies to the instance method
        self.is_malicious = lru_cache(maxsize=self.cache_size)(self._is_malicious_impl)
        
        # Initialize empty blacklists and metadata
        self.blacklists = {}
        self.rtrees = {}
        self.metadata = {}
        self.last_refresh = None
        
        # Load the blacklists
        self._load_blacklists()
        
        logger.info(f"Initialized ThreatIntelligence with {len(self.sources)} sources, {self.cache_size} cache size")
        
    def __del__(self):
        """Clean up resources."""
        # Clear caches
        try:
            self.is_malicious.cache_clear()
        except:
            pass
        
    def _load_blacklists(self) -> None:
        """Load blacklists from files or download if necessary."""
        all_sources_valid = True
        
        for source_name, url in self.sources.items():
            file_path = os.path.join(self.data_dir, f"{source_name}.netset")
            meta_path = os.path.join(self.data_dir, f"{source_name}.meta")
            
            # Check if the file exists and is not too old
            file_exists = os.path.exists(file_path)
            meta_exists = os.path.exists(meta_path)
            
            if file_exists and meta_exists:
                # Load metadata
                try:
                    with open(meta_path, 'r') as f:
                        meta_content = f.read().strip()
                        try:
                            metadata = json.loads(meta_content)
                            timestamp = metadata.get('timestamp', 0)
                            count = metadata.get('count', 0)
                            url_str = metadata.get('url', '')
                            
                            self.metadata[source_name] = {
                                'timestamp': timestamp,
                                'count': count,
                                'url': url_str
                            }
                            
                            # Check if file is too old
                            if time.time() - timestamp > self.refresh_interval:
                                logger.info(f"Blacklist {source_name} is outdated. Will refresh.")
                                all_sources_valid = False
                        except json.JSONDecodeError:
                            # Try legacy format
                            try:
                                timestamp_str, count_str, url_str, *extra = meta_content.split('|')
                                timestamp = float(timestamp_str)
                                count = int(count_str)
                                
                                self.metadata[source_name] = {
                                    'timestamp': timestamp,
                                    'count': count,
                                    'url': url_str
                                }
                                
                                # Check if file is too old
                                if time.time() - timestamp > self.refresh_interval:
                                    logger.info(f"Blacklist {source_name} is outdated. Will refresh.")
                                    all_sources_valid = False
                                    
                                # Write in new JSON format for next time
                                self._write_metadata(source_name, timestamp, count, url_str)
                            except (ValueError, IndexError):
                                logger.warning(f"Invalid metadata format for {source_name}. Will refresh.")
                                all_sources_valid = False
                except Exception as e:
                    logger.warning(f"Error reading metadata for {source_name}: {e}. Will refresh.")
                    all_sources_valid = False
            else:
                logger.info(f"Blacklist {source_name} does not exist. Will download.")
                all_sources_valid = False
                
        # If any source is invalid or too old, refresh all sources
        if not all_sources_valid and self.auto_refresh:
            logger.info("Some blacklists are missing or outdated, refreshing all sources")
            self.refresh_blacklists()
        else:
            # Load existing files
            for source_name in self.sources:
                file_path = os.path.join(self.data_dir, f"{source_name}.netset")
                if os.path.exists(file_path):
                    self.blacklists[source_name] = self._load_ip_set(file_path)
                    
                    # Initialize radix tree if available
                    if RADIX_AVAILABLE:
                        self.rtrees[source_name] = self._build_radix_tree(self.blacklists[source_name])
                    
            self.last_refresh = time.time()
            logger.info(f"Loaded {sum(len(bl) for bl in self.blacklists.values())} IPs from {len(self.blacklists)} blacklists")
    
    def _write_metadata(self, source_name: str, timestamp: float, count: int, url: str) -> None:
        """Write metadata in JSON format.
        
        Args:
            source_name: Name of the source
            timestamp: Timestamp when the source was last updated
            count: Number of entries in the source
            url: URL of the source
        """
        meta_path = os.path.join(self.data_dir, f"{source_name}.meta")
        try:
            metadata = {
                'timestamp': timestamp,
                'count': count,
                'url': url,
                'hash': hashlib.md5(f"{timestamp}:{count}:{url}".encode()).hexdigest()
            }
            
            with open(meta_path, 'w') as f:
                json.dump(metadata, f)
        except Exception as e:
            logger.warning(f"Error writing metadata for {source_name}: {e}")
    
    def _load_ip_set(self, file_path: str) -> Set[str]:
        """Load a set of IP addresses or CIDR ranges from a file.
        
        Args:
            file_path: Path to the file containing IP addresses
            
        Returns:
            Set of IP addresses or CIDR ranges
        """
        ip_set = set()
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Handle any extra data on the line (some lists have comments after IPs)
                    parts = line.split()
                    ip_or_range = parts[0]
                    
                    # Validate IP or CIDR range
                    try:
                        if '/' in ip_or_range:
                            # This is a CIDR range
                            ipaddress.ip_network(ip_or_range, strict=False)
                        else:
                            # This is a single IP
                            ipaddress.ip_address(ip_or_range)
                        
                        ip_set.add(ip_or_range)
                    except ValueError:
                        # Skip invalid IP addresses
                        logger.debug(f"Skipping invalid IP/CIDR: {ip_or_range}")
                        continue
        except Exception as e:
            logger.error(f"Error loading IP set from {file_path}: {e}")
            
        return ip_set
    
    def _build_radix_tree(self, ip_set: Set[str]) -> Optional['radix.Radix']:
        """Build a radix tree for efficient CIDR lookups.
        
        Args:
            ip_set: Set of IP addresses or CIDR ranges
            
        Returns:
            Radix tree object if radix module is available, None otherwise
        """
        if not RADIX_AVAILABLE:
            return None
            
        rtree = radix.Radix()
        
        for ip_or_cidr in ip_set:
            try:
                if '/' in ip_or_cidr:
                    # CIDR range
                    rtree.add(ip_or_cidr)
                else:
                    # Single IP (add as /32 or /128)
                    ip = ipaddress.ip_address(ip_or_cidr)
                    if ip.version == 4:
                        rtree.add(f"{ip_or_cidr}/32")
                    else:
                        rtree.add(f"{ip_or_cidr}/128")
            except Exception as e:
                logger.debug(f"Error adding {ip_or_cidr} to radix tree: {e}")
                
        return rtree
        
    def refresh_blacklists(self) -> bool:
        """Download and refresh all blacklists.
        
        Returns:
            True if all blacklists were successfully refreshed, False otherwise
        """
        logger.info("Refreshing threat intelligence blacklists...")
        success = True
        
        # Get max workers from config, but limit by number of sources
        config = get_config()
        max_workers = min(
            config.get("processing", "max_workers", 4),
            len(self.sources)
        )
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(self._download_blacklist, source_name, url): source_name
                for source_name, url in self.sources.items()
            }
            
            for future in as_completed(future_to_source):
                source_name = future_to_source[future]
                try:
                    result = future.result()
                    if not result:
                        success = False
                except Exception as e:
                    logger.error(f"Error refreshing {source_name}: {e}")
                    success = False
                    
        self.last_refresh = time.time()
        
        # Clear cache after refresh
        self.is_malicious.cache_clear()
        
        return success
        
    def _download_blacklist(self, source_name: str, url: str) -> bool:
        """Download a blacklist from a URL.
        
        Args:
            source_name: Name of the source
            url: URL to download the blacklist from
            
        Returns:
            True if successful, False otherwise
            
        Raises:
            ThreatIntelNetworkError: If there's a network error during download
        """
        file_path = os.path.join(self.data_dir, f"{source_name}.netset")
        temp_path = f"{file_path}.tmp"
        
        try:
            logger.info(f"Downloading {source_name} from {url}...")
            
            # Create a custom request with a user agent
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'pflogs-threat-intelligence/1.0'}
            )
            
            start_time = time.time()
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode('utf-8', errors='ignore')
                download_time = time.time() - start_time
                content_length = len(content)
                logger.info(f"Downloaded {content_length} bytes in {download_time:.2f} seconds")
                
                # Process the content based on the source
                processed_content = self._process_content(source_name, content)
                
                # Write to temporary file
                with open(temp_path, 'w') as f:
                    f.write(processed_content)
                    
                # Count valid IPs
                ip_set = self._load_ip_set(temp_path)
                count = len(ip_set)
                
                # If we got a valid list with IPs
                if count > 0:
                    # Replace the old file
                    if os.path.exists(file_path):
                        try:
                            os.unlink(file_path)
                        except (OSError, IOError) as e:
                            logger.warning(f"Failed to remove old file {file_path}: {e}")
                    
                    try:
                        os.rename(temp_path, file_path)
                    except (OSError, IOError) as e:
                        logger.error(f"Failed to rename {temp_path} to {file_path}: {e}")
                        if os.path.exists(temp_path):
                            os.unlink(temp_path)
                        return False
                    
                    # Update metadata
                    timestamp = time.time()
                    self._write_metadata(source_name, timestamp, count, url)
                    
                    # Update in-memory data
                    self.blacklists[source_name] = ip_set
                    
                    # Update radix tree if available
                    if RADIX_AVAILABLE:
                        self.rtrees[source_name] = self._build_radix_tree(ip_set)
                    
                    # Update metadata
                    self.metadata[source_name] = {
                        'timestamp': timestamp,
                        'count': count,
                        'url': url
                    }
                    
                    logger.info(f"Successfully downloaded {source_name} with {count} entries")
                    return True
                else:
                    logger.warning(f"Downloaded {source_name} but found no valid IPs")
                    if os.path.exists(temp_path):
                        try:
                            os.unlink(temp_path)
                        except (OSError, IOError) as e:
                            logger.warning(f"Failed to remove temporary file {temp_path}: {e}")
                    return False
                    
        except urllib.error.URLError as e:
            logger.error(f"Network error downloading {source_name}: {e}")
            raise ThreatIntelNetworkError(f"Network error downloading {source_name}: {e}")
        except Exception as e:
            logger.error(f"Error downloading {source_name}: {e}")
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except (OSError, IOError) as e:
                    logger.warning(f"Failed to remove temporary file {temp_path}: {e}")
            return False
            
    def _process_content(self, source_name: str, content: str) -> str:
        """Process the content of a blacklist based on its format.
        
        Args:
            source_name: Name of the source
            content: Content of the blacklist
            
        Returns:
            Processed content
        """
        # Process based on the source format
        if source_name == "emerging_threats":
            # Emerging Threats format has IPs without CIDR notation
            # and might have a leading "# " before each IP
            lines = []
            for line in content.splitlines():
                line = line.strip()
                # Remove comments but keep the IP
                if line.startswith("# "):
                    line = line[2:].strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue
                # Validate it's an IP
                try:
                    ipaddress.ip_address(line)
                    lines.append(line)
                except ValueError:
                    continue
            return "\n".join(lines)
        else:
            # Default processing - just return the content
            return content
    
    def _check_ip_in_cidr_ranges(self, ip_obj: 'ipaddress.IPv4Address' or 'ipaddress.IPv6Address', 
                              source: str) -> bool:
        """Check if an IP is in any CIDR range using most efficient method available.
        
        Args:
            ip_obj: IP address object
            source: Source name
            
        Returns:
            True if the IP is in any CIDR range, False otherwise
        """
        # Use radix tree if available for more efficient lookups
        if RADIX_AVAILABLE and source in self.rtrees and self.rtrees[source]:
            try:
                ip_str = str(ip_obj)
                rnode = self.rtrees[source].search_best(ip_str)
                return rnode is not None
            except Exception as e:
                logger.debug(f"Error searching radix tree: {e}")
                # Fall back to manual search
                pass
        
        # Manual CIDR check as fallback
        for entry in self.blacklists[source]:
            if '/' in entry:
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                    if ip_obj in network:
                        return True
                except ValueError:
                    continue
                    
        return False
    
    def _is_malicious_impl(self, ip_address: str, check_all: bool = False) -> Union[bool, Dict[str, bool]]:
        """Implementation of malicious IP check (used by lru_cache wrapper).
        
        Args:
            ip_address: IP address to check
            check_all: If True, return a dictionary with results for each source
            
        Returns:
            If check_all is False: True if the IP is in any blacklist, False otherwise
            If check_all is True: Dictionary mapping source names to boolean results
        """
        # Refresh blacklists if needed, but don't do this for every IP check
        # Only do it once per session
        if self.auto_refresh and (not self.last_refresh or 
                               time.time() - self.last_refresh > self.refresh_interval):
            self.refresh_blacklists()
            
        # Try to convert the IP to an IP address object
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            # Invalid IP address
            logger.debug(f"Invalid IP address: {ip_address}")
            result = {source: False for source in self.blacklists} if check_all else False
            return result
            
        # Check each blacklist
        results = {}
        for source, ip_set in self.blacklists.items():
            # First, check if the exact IP is in the set (fast check)
            if ip_address in ip_set:
                results[source] = True
                if not check_all:
                    return True
                continue
            
            # Next, check if the IP is in any CIDR range
            if self._check_ip_in_cidr_ranges(ip_obj, source):
                results[source] = True
                if not check_all:
                    return True
            else:
                results[source] = False
                
        # Return results
        if check_all:
            return results
        
        # If we got here, the IP wasn't found in any blacklist
        return any(results.values())
        
    def get_blacklist_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about the blacklists.
        
        Returns:
            Dictionary with information about each blacklist
        """
        info = {}
        for source, metadata in self.metadata.items():
            timestamp = metadata.get('timestamp', 0)
            update_time = datetime.fromtimestamp(timestamp)
            age = timedelta(seconds=int(time.time() - timestamp))
            
            info[source] = {
                'count': metadata.get('count', 0),
                'updated': update_time.strftime('%Y-%m-%d %H:%M:%S'),
                'url': metadata.get('url', self.sources.get(source, 'Unknown')),
                'age': str(age),
            }
        return info
    
    def process_ips_in_chunks(self, ips: List[str], chunk_size: int = None) -> Generator[Tuple[List[str], List[Dict[str, bool]]], None, None]:
        """Process IPs in chunks to reduce memory usage and provide progress updates.
        
        Args:
            ips: List of IP addresses to check
            chunk_size: Size of each chunk, defaults to config value
            
        Yields:
            Tuple of (chunk of IPs, results for each IP)
        """
        if chunk_size is None:
            config = get_config()
            chunk_size = config.get("threat_intel", "batch_size", 50)
            
        total = len(ips)
        for i in range(0, total, chunk_size):
            chunk = ips[i:i+chunk_size]
            results = [self.is_malicious(ip, check_all=True) for ip in chunk]
            yield (chunk, results)
        
    def enrich_dataframe(self, df: pd.DataFrame, ip_column: str = "src_ip") -> pd.DataFrame:
        """Enrich a DataFrame with threat intelligence data.
        
        Args:
            df: Pandas DataFrame containing IP addresses
            ip_column: Name of the column containing IP addresses to check
            
        Returns:
            DataFrame with added threat intelligence columns
            
        Raises:
            ValueError: If the specified IP column doesn't exist in the DataFrame
        """
        if ip_column not in df.columns:
            logger.error(f"IP column '{ip_column}' not found in DataFrame")
            raise ValueError(f"IP column '{ip_column}' not found in DataFrame")
            
        # Create a new dataframe to avoid modifying the original
        enriched_df = df.copy()
        
        # Get unique IP addresses to check (much more efficient)
        unique_ips = df[ip_column].dropna().unique()
        total_ips = len(unique_ips)
        logger.info(f"Checking {total_ips} unique IPs against threat intelligence sources")
        print(f"Checking {total_ips} IPs against threat intelligence...")
        
        # Pre-compute the threat intelligence results for each unique IP
        # Use batching to provide progress updates
        config = get_config()
        batch_size = config.get("threat_intel", "batch_size", 50)
        start_time = time.time()
        malicious_count = 0
        
        # Create mapping dictionaries for all sources
        threat_is_malicious_map = {}
        source_maps = {source: {} for source in self.blacklists}
        
        # Process in batches
        for i, (batch, results) in enumerate(self.process_ips_in_chunks(unique_ips, batch_size)):
            batch_end = min((i+1) * batch_size, total_ips)
            current_time = time.time()
            elapsed = current_time - start_time
            
            # Estimate time remaining
            if i > 0:
                ips_per_second = i * batch_size / elapsed if elapsed > 0 else 0
                remaining_ips = total_ips - i * batch_size
                eta_seconds = remaining_ips / ips_per_second if ips_per_second > 0 else 0
                eta_str = f", ETA: {int(eta_seconds//60)}m {int(eta_seconds%60)}s"
            else:
                eta_str = ""
                
            print(f"Processing IPs {i*batch_size+1}-{batch_end} of {total_ips} ({(i*batch_size+1)/total_ips*100:.1f}%{eta_str})")
            
            # Update mapping dictionaries
            for ip, result in zip(batch, results):
                is_malicious = any(result.values())
                threat_is_malicious_map[ip] = is_malicious
                
                if is_malicious:
                    malicious_count += 1
                
                # Update each source map
                for source in self.blacklists:
                    source_maps[source][ip] = result.get(source, False)
        
        # Report total time and stats
        total_time = time.time() - start_time
        ips_per_second = total_ips / total_time if total_time > 0 else 0
        print(f"Threat intelligence processing complete: {total_ips} IPs in {total_time:.1f}s ({ips_per_second:.1f} IPs/sec)")
        print(f"Found {malicious_count} malicious IPs ({malicious_count/total_ips*100:.1f}%)")
        
        # Initialize the threat columns
        enriched_df['threat_is_malicious'] = False
        sources = list(self.blacklists.keys())
        for source in sources:
            enriched_df[f"threat_{source}"] = False
        
        print("Applying threat intelligence data to dataframe...")
        
        # Apply the results using map operation (faster than row-by-row)
        enriched_df['threat_is_malicious'] = enriched_df[ip_column].map(lambda ip: threat_is_malicious_map.get(ip, False))
        
        # Apply source-specific results
        for source in sources:
            enriched_df[f"threat_{source}"] = enriched_df[ip_column].map(lambda ip: source_maps[source].get(ip, False))
        
        return enriched_df