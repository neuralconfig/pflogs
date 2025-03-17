"""
IP Geolocation Module.

This module provides functionality to map IP addresses to geographic locations
using the MaxMind GeoIP2 database.
"""

import os
from typing import Dict, Any, Optional, List, Union
import ipaddress
import geoip2.database
import geoip2.errors
import pandas as pd
from pandas import Index


class IPGeolocation:
    """IP Geolocation handler.

    This class provides functionality to map IP addresses to geographic locations
    using the MaxMind GeoIP2 database.

    Attributes:
        db_path: Path to the MaxMind GeoIP2 database (.mmdb file)
        reader: GeoIP2 database reader instance
    """

    def __init__(self, db_path: str):
        """Initialize the IP Geolocation handler.

        Args:
            db_path: Path to the MaxMind GeoIP2 database (.mmdb file)

        Raises:
            FileNotFoundError: If the database file doesn't exist
            ValueError: If the database file is invalid
        """
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"GeoIP database file not found: {db_path}")

        try:
            self.db_path = db_path
            self.reader = geoip2.database.Reader(db_path)
        except Exception as e:
            raise ValueError(f"Failed to open GeoIP database: {e}")

    def __del__(self):
        """Clean up resources."""
        if hasattr(self, "reader"):
            self.reader.close()

    def is_private_ip(self, ip_address: str) -> bool:
        """Check if the IP address is private/reserved.

        Args:
            ip_address: IP address string

        Returns:
            True if the IP is private/reserved, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_multicast
        except ValueError:
            # If we can't parse the IP address, we'll assume it's not private
            return False

    def lookup_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Look up geographic information for an IP address.

        Args:
            ip_address: IP address string

        Returns:
            Dictionary containing geographic information for the IP address,
            or None if the IP is private or not found in the database
        """
        if self.is_private_ip(ip_address):
            return None

        try:
            response = self.reader.city(ip_address)
            return {
                "ip": ip_address,
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
            }
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception:
            # Any other error, we'll just return None for now
            return None

    def enrich_dataframe(
        self, df: pd.DataFrame, ip_column: str = "src_ip"
    ) -> pd.DataFrame:
        """Enrich a DataFrame with geolocation data for IPs in a specified column.

        Args:
            df: Pandas DataFrame containing IP addresses
            ip_column: Name of the column containing IP addresses to look up

        Returns:
            DataFrame with added geolocation columns
        """
        if ip_column not in df.columns:
            raise ValueError(f"IP column '{ip_column}' not found in DataFrame")

        # Create a new dataframe to avoid modifying the original
        enriched_df = df.copy()

        # Apply geolocation lookup to each IP address
        geo_data = []
        for ip in df[ip_column]:
            geo_info = self.lookup_ip(ip)
            geo_data.append(geo_info)

        # Create a DataFrame with the geolocation data
        geo_df = pd.DataFrame(geo_data)

        # If we have geolocation data, merge it with the original DataFrame
        if not geo_df.empty:
            # Add geo_ prefix to all columns except 'ip'
            if "ip" in geo_df.columns:  # Check if 'ip' column exists
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
        return [self.lookup_ip(ip) for ip in ip_addresses]

    def create_geodata_series(
        self, df: pd.DataFrame, ip_column: str = "src_ip"
    ) -> pd.DataFrame:
        """Create a DataFrame with counts of connections by geographic location.

        Args:
            df: DataFrame containing IP addresses
            ip_column: Name of the column containing IP addresses to look up

        Returns:
            DataFrame with counts of connections grouped by country and city
        """
        if ip_column not in df.columns:
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


def enrich_logs_with_geo(
    logs: Union[pd.DataFrame, str],
    db_path: str,
    ip_column: str = "src_ip",
    output_path: Optional[str] = None,
) -> Optional[pd.DataFrame]:
    """Enrich log data with geolocation information.

    High-level function to enrich PF logs with geolocation data.

    Args:
        logs: DataFrame containing logs or path to a Parquet file
        db_path: Path to the MaxMind GeoIP2 database (.mmdb file)
        ip_column: Name of the column containing IP addresses to look up
        output_path: Optional path to save the enriched logs as a Parquet file

    Returns:
        A pandas DataFrame if output_path is None, otherwise None

    Raises:
        FileNotFoundError: If the database file or log file doesn't exist
        ValueError: If the specified IP column doesn't exist in the log data
    """
    geo = IPGeolocation(db_path)

    # Load data if a file path was provided
    if isinstance(logs, str):
        if not os.path.exists(logs):
            raise FileNotFoundError(f"Log file not found: {logs}")
        logs_df = pd.read_parquet(logs)
    else:
        logs_df = logs

    # Enrich with geolocation data
    enriched_df = geo.enrich_dataframe(logs_df, ip_column)

    # Save to Parquet if an output path was provided
    if output_path:
        enriched_df.to_parquet(output_path, index=False)
        return None

    return enriched_df
