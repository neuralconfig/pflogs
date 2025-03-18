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
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Union, Tuple, Any
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """Threat Intelligence handler for IP reputation data.
    
    This class provides functionality to detect potentially malicious IP addresses
    using various threat intelligence feeds.
    
    Attributes:
        data_dir: Directory to store threat intelligence data
        sources: Dictionary of threat intelligence sources with their URLs
        blacklists: Dictionary of IP sets from different sources
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
                 refresh_interval: int = 86400,  # Default: 24 hours
                 auto_refresh: bool = True):
        """Initialize the Threat Intelligence handler.
        
        Args:
            data_dir: Directory to store threat intelligence data
            sources: Dictionary of threat intelligence sources with their URLs
            refresh_interval: How often to refresh the data in seconds
            auto_refresh: Whether to automatically refresh stale data when needed
            
        Raises:
            ValueError: If data_dir is not provided and cannot be determined
        """
        # Set the data directory
        if data_dir:
            self.data_dir = data_dir
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
        
        # Initialize empty blacklists and metadata
        self.blacklists = {}
        self.metadata = {}
        self.last_refresh = None
        self.refresh_interval = refresh_interval
        self.auto_refresh = auto_refresh
        
        # Load the blacklists
        self._load_blacklists()
        
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
                with open(meta_path, 'r') as f:
                    meta_content = f.read().strip()
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
                    except (ValueError, IndexError):
                        logger.warning(f"Invalid metadata format for {source_name}. Will refresh.")
                        all_sources_valid = False
            else:
                logger.info(f"Blacklist {source_name} does not exist. Will download.")
                all_sources_valid = False
                
        # If any source is invalid or too old, refresh all sources
        if not all_sources_valid and self.auto_refresh:
            self.refresh_blacklists()
        else:
            # Load existing files
            for source_name in self.sources:
                file_path = os.path.join(self.data_dir, f"{source_name}.netset")
                if os.path.exists(file_path):
                    self.blacklists[source_name] = self._load_ip_set(file_path)
                    
            self.last_refresh = time.time()
    
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
                        continue
        except Exception as e:
            logger.error(f"Error loading IP set from {file_path}: {e}")
            
        return ip_set
        
    def refresh_blacklists(self) -> bool:
        """Download and refresh all blacklists.
        
        Returns:
            True if all blacklists were successfully refreshed, False otherwise
        """
        logger.info("Refreshing threat intelligence blacklists...")
        success = True
        
        with ThreadPoolExecutor(max_workers=min(4, len(self.sources))) as executor:
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
        return success
        
    def _download_blacklist(self, source_name: str, url: str) -> bool:
        """Download a blacklist from a URL.
        
        Args:
            source_name: Name of the source
            url: URL to download the blacklist from
            
        Returns:
            True if successful, False otherwise
        """
        file_path = os.path.join(self.data_dir, f"{source_name}.netset")
        temp_path = f"{file_path}.tmp"
        meta_path = os.path.join(self.data_dir, f"{source_name}.meta")
        
        try:
            logger.info(f"Downloading {source_name} from {url}...")
            
            # Create a custom request with a user agent
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'pflogs-threat-intelligence/1.0'}
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode('utf-8', errors='ignore')
                
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
                    with open(meta_path, 'w') as f:
                        f.write(f"{timestamp}|{count}|{url}")
                        
                    # Update in-memory data
                    self.blacklists[source_name] = ip_set
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
            
    # Cache for IP lookups to avoid rechecking the same IPs
    _ip_cache = {}
    
    # Cache for parsed network objects (expensive to create)
    _network_cache = {}
    
    def is_malicious(self, ip_address: str, check_all: bool = False) -> Union[bool, Dict[str, bool]]:
        """Check if an IP address is in any blacklist.
        
        Args:
            ip_address: IP address to check
            check_all: If True, return a dictionary with results for each source
            
        Returns:
            If check_all is False: True if the IP is in any blacklist, False otherwise
            If check_all is True: Dictionary mapping source names to boolean results
        """
        # Check cache first (major performance optimization for repeatedly seen IPs)
        cache_key = f"{ip_address}:{check_all}"
        if cache_key in self._ip_cache:
            return self._ip_cache[cache_key]
            
        # Refresh blacklists if needed, but don't do this for every IP check
        # Only do it once per session
        if self.auto_refresh and (not self.last_refresh or 
                               time.time() - self.last_refresh > self.refresh_interval):
            self.refresh_blacklists()
            # Clear caches when blacklists are refreshed
            self._ip_cache = {}
            self._network_cache = {}
            
        # Try to convert the IP to an IP address object
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            # Invalid IP address
            result = {source: False for source in self.blacklists} if check_all else False
            self._ip_cache[cache_key] = result
            return result
            
        # Check each blacklist
        results = {}
        for source, ip_set in self.blacklists.items():
            # First, check if the exact IP is in the set (fast check)
            if ip_address in ip_set:
                results[source] = True
                if not check_all:
                    self._ip_cache[cache_key] = True
                    return True
                continue
            
            # Next, check if the IP is in any CIDR range
            # Use cached network objects for better performance
            if source not in self._network_cache:
                # Initialize cache for this source
                self._network_cache[source] = []
                
                # Parse all CIDR ranges once and cache them
                for entry in ip_set:
                    if '/' in entry:
                        try:
                            network = ipaddress.ip_network(entry, strict=False)
                            self._network_cache[source].append(network)
                        except ValueError:
                            continue
            
            # Now check against cached networks (much faster)
            found = False
            for network in self._network_cache[source]:
                if ip_obj in network:
                    found = True
                    break
                        
            results[source] = found
            if found and not check_all:
                self._ip_cache[cache_key] = True
                return True
                
        # Cache and return the result
        if check_all:
            self._ip_cache[cache_key] = results
            return results
        
        result = any(results.values())
        self._ip_cache[cache_key] = result
        return result
        
    def get_blacklist_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about the blacklists.
        
        Returns:
            Dictionary with information about each blacklist
        """
        info = {}
        for source, metadata in self.metadata.items():
            info[source] = {
                'count': metadata.get('count', 0),
                'updated': datetime.fromtimestamp(metadata.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                'url': metadata.get('url', self.sources.get(source, 'Unknown')),
                'age': str(timedelta(seconds=int(time.time() - metadata.get('timestamp', 0)))),
            }
        return info
        
    def enrich_dataframe(self, df: pd.DataFrame, ip_column: str = "src_ip") -> pd.DataFrame:
        """Enrich a DataFrame with threat intelligence data.
        
        Args:
            df: Pandas DataFrame containing IP addresses
            ip_column: Name of the column containing IP addresses to check
            
        Returns:
            DataFrame with added threat intelligence columns
        """
        if ip_column not in df.columns:
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
        ip_results = {}
        batch_size = 50  # Process IPs in smaller batches to show progress
        start_time = time.time()
        malicious_count = 0
        
        for i in range(0, total_ips, batch_size):
            batch = unique_ips[i:i+batch_size]
            batch_end = min(i + batch_size, total_ips)
            current_time = time.time()
            elapsed = current_time - start_time
            
            # Estimate time remaining
            if i > 0:
                ips_per_second = i / elapsed if elapsed > 0 else 0
                remaining_ips = total_ips - i
                eta_seconds = remaining_ips / ips_per_second if ips_per_second > 0 else 0
                eta_str = f", ETA: {int(eta_seconds//60)}m {int(eta_seconds%60)}s"
            else:
                eta_str = ""
                
            print(f"Processing IPs {i+1}-{batch_end} of {total_ips} ({(i+1)/total_ips*100:.1f}%{eta_str})")
            
            # Process this batch
            for ip in batch:
                try:
                    result = self.is_malicious(ip, check_all=True)
                    ip_results[ip] = result
                    if any(result.values()):
                        malicious_count += 1
                except Exception as e:
                    logger.warning(f"Error checking IP {ip}: {e}")
                    ip_results[ip] = {source: False for source in self.blacklists}
        
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
        # Apply the results to the dataframe more efficiently using dictionary mapping
        # First create a mapping for the main flag
        threat_is_malicious_map = {ip: any(results.values()) for ip, results in ip_results.items()}
        # Apply it using map operation (faster than row-by-row)
        enriched_df['threat_is_malicious'] = enriched_df[ip_column].map(lambda ip: threat_is_malicious_map.get(ip, False))
        
        # Do the same for each source
        for source in sources:
            # Create mapping for this source
            source_map = {ip: results.get(source, False) for ip, results in ip_results.items()}
            # Apply it
            enriched_df[f"threat_{source}"] = enriched_df[ip_column].map(lambda ip: source_map.get(ip, False))
        
        return enriched_df