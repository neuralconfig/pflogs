"""
IP Geolocation Module.

This module provides functionality to map IP addresses to geographic locations
using the MaxMind GeoIP2 database, including ASN data.
"""

import os
import time
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List, Union, Tuple, Iterator, Generator
import ipaddress
import geoip2.database
import geoip2.errors
import pandas as pd
from pandas import Index
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from .config import get_config

# Configure logging
logger = logging.getLogger(__name__)

class GeoIPError(Exception):
    """Base exception for IPGeolocation errors."""
    pass

class GeoIPDatabaseError(GeoIPError):
    """Exception raised for errors with GeoIP database."""
    pass

class GeoIPLookupError(GeoIPError):
    """Exception raised for errors during IP lookup."""
    pass

class IPGeolocation:
    """IP Geolocation handler.

    This class provides functionality to map IP addresses to geographic locations
    using the MaxMind GeoIP2 database.

    Attributes:
        geo_db_path: Path to the MaxMind GeoIP2 City database (.mmdb file)
        geo_reader: GeoIP2 City database reader instance
        asn_db_path: Path to the MaxMind GeoIP2 ASN database (.mmdb file)
        asn_reader: GeoIP2 ASN database reader instance
    """

    def __init__(self, geo_db_path: str, asn_db_path: Optional[str] = None, cache_size: int = None):
        """Initialize the IP Geolocation handler.

        Args:
            geo_db_path: Path to the MaxMind GeoIP2 City database (.mmdb file)
            asn_db_path: Optional path to the MaxMind GeoIP2 ASN database (.mmdb file)
            cache_size: Size of the LRU cache for IP lookups, defaults to config value

        Raises:
            FileNotFoundError: If the database file doesn't exist
            GeoIPDatabaseError: If the database file is invalid
        """
        # Get configuration
        config = get_config()
        if cache_size is None:
            cache_size = config.get("geo", "cache_size", 1000)

        # Configure LRU cache for lookup methods
        # The LRU cache is a class-level decorator, so we need to apply it to instance methods
        self.lookup_ip = lru_cache(maxsize=cache_size)(self._lookup_ip_impl)
        self.lookup_asn = lru_cache(maxsize=cache_size)(self._lookup_asn_impl)
        
        # Initialize GeoIP City database
        if not os.path.exists(geo_db_path):
            logger.error(f"GeoIP City database file not found: {geo_db_path}")
            raise FileNotFoundError(f"GeoIP City database file not found: {geo_db_path}")

        try:
            self.geo_db_path = geo_db_path
            self.geo_reader = geoip2.database.Reader(geo_db_path)
            logger.debug(f"Successfully opened GeoIP City database: {geo_db_path}")
        except Exception as e:
            logger.error(f"Failed to open GeoIP City database: {e}")
            raise GeoIPDatabaseError(f"Failed to open GeoIP City database: {e}")
            
        # Initialize GeoIP ASN database if provided
        self.asn_db_path = asn_db_path
        self.asn_reader = None
        
        if asn_db_path:
            if not os.path.exists(asn_db_path):
                logger.error(f"GeoIP ASN database file not found: {asn_db_path}")
                raise FileNotFoundError(f"GeoIP ASN database file not found: {asn_db_path}")
                
            try:
                self.asn_reader = geoip2.database.Reader(asn_db_path)
                logger.debug(f"Successfully opened GeoIP ASN database: {asn_db_path}")
            except Exception as e:
                logger.error(f"Failed to open GeoIP ASN database: {e}")
                raise GeoIPDatabaseError(f"Failed to open GeoIP ASN database: {e}")

    def __del__(self):
        """Clean up resources."""
        if hasattr(self, "geo_reader"):
            self.geo_reader.close()
            
        if hasattr(self, "asn_reader") and self.asn_reader:
            self.asn_reader.close()
            
        # Clear caches 
        try:
            self.lookup_ip.cache_clear()
            self.lookup_asn.cache_clear()
        except:
            pass

    def is_private_ip(self, ip_address: str) -> bool:
        """Check if the IP address is private/reserved.

        Args:
            ip_address: IP address string

        Returns:
            True if the IP is private/reserved, False otherwise
            
        Raises:
            ValueError: If the IP address is invalid
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_multicast
        except ValueError as e:
            logger.debug(f"Invalid IP address: {ip_address}")
            # If we can't parse the IP address, we'll assume it's not private
            return False

    def _lookup_asn_impl(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Implementation of ASN lookup for an IP address (used by lru_cache wrapper).

        Args:
            ip_address: IP address string

        Returns:
            Dictionary containing ASN information for the IP address,
            or None if the IP is private or not found in the database
            
        Raises:
            GeoIPLookupError: If an error occurs during lookup
        """
        if self.is_private_ip(ip_address) or not self.asn_reader:
            return None

        try:
            response = self.asn_reader.asn(ip_address)
            return {
                "asn": response.autonomous_system_number,
                "asn_org": response.autonomous_system_organization,
                "network": str(response.network) if response.network else None,
            }
        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"IP not found in ASN database: {ip_address}")
            return None
        except Exception as e:
            logger.warning(f"Error looking up ASN for IP {ip_address}: {e}")
            # Any other error, we'll just return None
            return None

    def _lookup_ip_impl(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Implementation of IP lookup for geographic information (used by lru_cache wrapper).

        Args:
            ip_address: IP address string

        Returns:
            Dictionary containing geographic information for the IP address,
            or None if the IP is private or not found in the database
            
        Raises:
            GeoIPLookupError: If an error occurs during lookup
        """
        if self.is_private_ip(ip_address):
            return None

        result = {"ip": ip_address}
        
        # Try to get city/geo information
        try:
            response = self.geo_reader.city(ip_address)
            result.update({
                "country_code": response.country.iso_code,
                "country_name": response.country.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "accuracy_radius": response.location.accuracy_radius,
                "time_zone": response.location.time_zone,
                "continent": response.continent.name,
                "subdivision": (
                    response.subdivisions.most_specific.name
                    if response.subdivisions
                    else None
                ),
                "subdivision_code": (
                    response.subdivisions.most_specific.iso_code
                    if response.subdivisions
                    else None
                ),
                "postal_code": response.postal.code if response.postal else None,
            })
        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"IP not found in geo database: {ip_address}")
            pass
        except Exception as e:
            logger.warning(f"Error looking up geo for IP {ip_address}: {e}")
            # Any other error, we'll proceed with what we have
            pass
            
        # Try to get ASN information if we have an ASN database
        if self.asn_reader:
            asn_info = self.lookup_asn(ip_address)
            if asn_info:
                result.update(asn_info)
                
        # Return None if we couldn't get any useful information
        if len(result) <= 1:  # Only has the IP
            return None
            
        return result

    def _process_ip_chunk(self, ips: List[str]) -> List[Optional[Dict[str, Any]]]:
        """Process a chunk of IP addresses in parallel.

        Args:
            ips: List of IP addresses to process

        Returns:
            List of dictionaries with the geolocation data
        """
        config = get_config()
        max_workers = config.get("processing", "max_workers", 4)

        # Create a list to store results in the same order as input IPs
        results = [None] * len(ips)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Map IPs to futures
            future_to_index = {executor.submit(self.lookup_ip, ip): i for i, ip in enumerate(ips)}
            
            # Collect results as they complete and store in correct position
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                results[index] = future.result()
                
        return results

    def enrich_dataframe(
        self, df: pd.DataFrame, ip_column: str = "src_ip"
    ) -> pd.DataFrame:
        """Enrich a DataFrame with geolocation data for IPs in a specified column.

        Args:
            df: Pandas DataFrame containing IP addresses
            ip_column: Name of the column containing IP addresses to look up

        Returns:
            DataFrame with added geolocation columns
            
        Raises:
            ValueError: If the specified IP column doesn't exist in the DataFrame
        """
        if ip_column not in df.columns:
            logger.error(f"IP column '{ip_column}' not found in DataFrame")
            raise ValueError(f"IP column '{ip_column}' not found in DataFrame")

        # Get configuration for chunk size
        config = get_config()
        chunk_size = config.get("processing", "chunk_size", 1000)
        
        # Create a new dataframe to avoid modifying the original
        enriched_df = df.copy()
        
        # Get unique IPs to reduce redundant lookups
        unique_ips = df[ip_column].dropna().unique()
        total_ips = len(unique_ips)
        
        logger.info(f"Enriching {total_ips} unique IPs with geolocation data")
        
        # Process IPs in chunks for better memory management and progress reporting
        geo_data = []
        for i in range(0, total_ips, chunk_size):
            chunk = unique_ips[i:i+chunk_size]
            logger.info(f"Processing IPs {i+1}-{min(i+chunk_size, total_ips)} of {total_ips}")
            
            # Process this chunk in parallel
            chunk_results = self._process_ip_chunk(chunk)
            
            # Add to results, handling None values
            for ip, result in zip(chunk, chunk_results):
                if result is None:
                    # Include the IP but no geo data
                    geo_data.append({'ip': ip})
                else:
                    geo_data.append(result)
        
        # Create a DataFrame with the geolocation data
        geo_df = pd.DataFrame(geo_data)
        
        # Return early if no geolocation data was found
        if geo_df.empty:
            return enriched_df
            
        # Add geo_ prefix to all columns except 'ip'
        if "ip" in geo_df.columns:
            new_cols = []
            for col in geo_df.columns:
                new_cols.append(f"geo_{col}" if col != "ip" else col)
            geo_df.columns = Index(new_cols)
            
            # Merge the geolocation data
            enriched_df = pd.merge(
                enriched_df, geo_df, left_on=ip_column, right_on="ip", how="left"
            )
            
            # Drop the redundant 'ip' column from geolocation data
            if "ip" in enriched_df.columns and "ip" != ip_column:
                enriched_df = enriched_df.drop(columns=["ip"])

        return enriched_df

    def batch_lookup(self, ip_addresses: List[str]) -> List[Optional[Dict[str, Any]]]:
        """Look up geographic information for multiple IP addresses.

        Args:
            ip_addresses: List of IP address strings

        Returns:
            List of dictionaries containing geographic information for each IP address,
            with None for IPs that are private or not found in the database
        """
        # Process in batches using the chunk processor
        config = get_config()
        chunk_size = config.get("processing", "chunk_size", 1000)
        
        results = []
        for i in range(0, len(ip_addresses), chunk_size):
            chunk = ip_addresses[i:i+chunk_size]
            chunk_results = self._process_ip_chunk(chunk)
            results.extend(chunk_results)
            
        return results

    def create_geodata_series(
        self, df: pd.DataFrame, ip_column: str = "src_ip"
    ) -> pd.DataFrame:
        """Create a DataFrame with counts of connections by geographic location.

        Args:
            df: DataFrame containing IP addresses
            ip_column: Name of the column containing IP addresses to look up

        Returns:
            DataFrame with counts of connections grouped by country and city
            
        Raises:
            ValueError: If the specified IP column doesn't exist in the DataFrame
        """
        if ip_column not in df.columns:
            logger.error(f"IP column '{ip_column}' not found in DataFrame")
            raise ValueError(f"IP column '{ip_column}' not found in DataFrame")

        # Enrich with geolocation data
        geo_df = self.enrich_dataframe(df, ip_column)

        # Group by location and count occurrences
        if "geo_country_name" in geo_df.columns:
            # Group by country and city and count occurrences
            location_counts = (
                geo_df.groupby(["geo_country_name", "geo_city"], dropna=False)
                .size()
                .reset_index(name="count")
            )

            # Sort by count in descending order
            location_counts = location_counts.sort_values("count", ascending=False)

            return location_counts
        else:
            # If no geolocation data was found, return an empty DataFrame
            return pd.DataFrame(columns=["geo_country_name", "geo_city", "count"])


def process_df_in_chunks(df: pd.DataFrame, chunk_size: int) -> Generator[pd.DataFrame, None, None]:
    """Process a DataFrame in chunks to manage memory usage.

    Args:
        df: DataFrame to process
        chunk_size: Number of rows in each chunk

    Yields:
        Chunks of the DataFrame
    """
    total_rows = len(df)
    for i in range(0, total_rows, chunk_size):
        yield df.iloc[i:min(i + chunk_size, total_rows)]


def enrich_logs_with_geo(
    logs: Union[pd.DataFrame, str],
    geo_db_path: str,
    ip_column: str = "src_ip",
    output_path: Optional[str] = None,
    asn_db_path: Optional[str] = None
) -> Optional[pd.DataFrame]:
    """Enrich log data with geolocation and ASN information.

    High-level function to enrich PF logs with geolocation data and ASN data.

    Args:
        logs: DataFrame containing logs or path to a Parquet file
        geo_db_path: Path to the MaxMind GeoIP2 City database (.mmdb file)
        ip_column: Name of the column containing IP addresses to look up
        output_path: Optional path to save the enriched logs as a Parquet file
        asn_db_path: Optional path to the MaxMind GeoIP2 ASN database (.mmdb file)

    Returns:
        A pandas DataFrame if output_path is None, otherwise None

    Raises:
        FileNotFoundError: If the database file or log file doesn't exist
        ValueError: If the specified IP column doesn't exist in the log data
    """
    # Get configuration
    config = get_config()
    chunk_size = config.get("processing", "chunk_size", 100000)

    # Initialize geo/ASN lookup
    geo = IPGeolocation(geo_db_path, asn_db_path)
    logger.info(f"Initialized IPGeolocation with {geo_db_path} and ASN DB: {asn_db_path}")

    # Load data if a file path was provided
    if isinstance(logs, str):
        if not os.path.exists(logs):
            logger.error(f"Log file not found: {logs}")
            raise FileNotFoundError(f"Log file not found: {logs}")
        logs_df = pd.read_parquet(logs)
        logger.info(f"Loaded {len(logs_df)} rows from {logs}")
    else:
        logs_df = logs
        logger.info(f"Using provided DataFrame with {len(logs_df)} rows")

    # Process in chunks to manage memory
    logger.info(f"Processing in chunks of {chunk_size} rows")
    enriched_chunks = []
    
    for i, chunk in enumerate(process_df_in_chunks(logs_df, chunk_size)):
        logger.info(f"Processing chunk {i+1} ({len(chunk)} rows)")
        enriched_chunk = geo.enrich_dataframe(chunk, ip_column)
        enriched_chunks.append(enriched_chunk)
        
    # Combine all chunks
    enriched_df = pd.concat(enriched_chunks, ignore_index=True)
    logger.info(f"Enrichment complete, {len(enriched_df)} rows processed")

    # Save to Parquet if an output path was provided
    if output_path:
        enriched_df.to_parquet(output_path, index=False)
        logger.info(f"Saved enriched data to {output_path}")
        return None

    return enriched_df


def enrich_with_geolocation(
    logs_df: pd.DataFrame, 
    geo_db_path: str, 
    ip_column: str = 'src_ip', 
    asn_db_path: Optional[str] = None
) -> pd.DataFrame:
    """
    Enrich log data with geolocation and ASN data only.
    
    Args:
        logs_df: DataFrame containing PF logs
        geo_db_path: Path to the MaxMind GeoIP2 City database
        ip_column: Name of the column containing IP addresses
        asn_db_path: Optional path to the MaxMind GeoIP2 ASN database
        
    Returns:
        DataFrame with geolocation and ASN enrichment
    """
    # Check if databases exist
    if not os.path.exists(geo_db_path):
        raise FileNotFoundError(f"GeoIP City database '{geo_db_path}' does not exist.")
        
    if asn_db_path and not os.path.exists(asn_db_path):
        raise FileNotFoundError(f"GeoIP ASN database '{asn_db_path}' does not exist.")
        
    # Use the core implementation function
    return enrich_logs_with_geo(
        logs_df,
        geo_db_path,
        ip_column=ip_column,
        asn_db_path=asn_db_path
    )