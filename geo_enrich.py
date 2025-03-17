#!/usr/bin/env python3
"""
IP Geolocation Enrichment CLI Tool

This script provides a command-line interface to enrich PF log data with
geolocation information using the MaxMind GeoIP2 database.
"""

import os
import sys
import argparse
from datetime import datetime
import pandas as pd
from pflogs.core.ip_geo import enrich_logs_with_geo


def main():
    """Run the IP geolocation enrichment CLI."""
    parser = argparse.ArgumentParser(
        description="Enrich PF log data with geolocation information"
    )
    
    parser.add_argument(
        "input_path",
        help="Path to the Parquet file containing parsed PF logs"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Path to save the enriched logs as a Parquet file"
    )
    
    parser.add_argument(
        "-d", "--db",
        required=True,
        help="Path to the MaxMind GeoIP2 database (.mmdb file)"
    )
    
    parser.add_argument(
        "-c", "--column",
        default="src_ip",
        help="Name of the column containing IP addresses to look up (default: src_ip)"
    )
    
    parser.add_argument(
        "--sample", 
        type=int, 
        default=5,
        help="Number of sample entries to display (default: 5)"
    )
    
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show summary of geolocation data"
    )
    
    args = parser.parse_args()
    
    # Check if the input path exists
    if not os.path.exists(args.input_path):
        print(f"Error: Input path '{args.input_path}' does not exist.", file=sys.stderr)
        return 1
    
    # Check if the GeoIP database exists
    if not os.path.exists(args.db):
        print(f"Error: GeoIP database '{args.db}' does not exist.", file=sys.stderr)
        return 1
    
    print(f"Enriching logs from {args.input_path} with geolocation data...")
    start_time = datetime.now()
    
    try:
        if args.output:
            # Enrich and save to Parquet
            enrich_logs_with_geo(
                args.input_path, 
                args.db, 
                args.column, 
                args.output
            )
            print(f"Enriched logs saved to {args.output}")
            
            # If summary is requested, load the enriched data
            if args.summary:
                enriched_df = pd.read_parquet(args.output)
            else:
                enriched_df = None
        else:
            # Enrich and display sample
            enriched_df = enrich_logs_with_geo(
                args.input_path, 
                args.db, 
                args.column
            )
            
            if enriched_df is None or enriched_df.empty:
                print("No logs were enriched.")
                return 0
            
            # Display sample entries
            print(f"\nSample entries ({min(args.sample, len(enriched_df))}):")
            print(enriched_df.head(args.sample))
        
        # Display summary if requested and we have the data
        if args.summary and enriched_df is not None:
            geo_columns = [col for col in enriched_df.columns if col.startswith("geo_")]
            
            if geo_columns:
                print("\nGeolocation data summary:")
                
                # Top countries
                if "geo_country_name" in enriched_df.columns:
                    country_counts = enriched_df["geo_country_name"].value_counts().head(10)
                    if not country_counts.empty:
                        print("\nTop 10 source countries:")
                        for country, count in country_counts.items():
                            if country is not None:
                                print(f"  {country}: {count} ({count/len(enriched_df)*100:.1f}%)")
                
                # Top cities
                if "geo_city" in enriched_df.columns:
                    city_counts = enriched_df["geo_city"].value_counts().head(10)
                    if not city_counts.empty:
                        print("\nTop 10 source cities:")
                        for city, count in city_counts.items():
                            if city is not None:
                                print(f"  {city}: {count} ({count/len(enriched_df)*100:.1f}%)")
                
                # Count of private/unresolved IPs
                if "geo_country_name" in enriched_df.columns:
                    null_count = enriched_df["geo_country_name"].isna().sum()
                    if null_count > 0:
                        print(f"\nPrivate/unresolved IPs: {null_count} ({null_count/len(enriched_df)*100:.1f}%)")
            else:
                print("\nNo geolocation data found in the enriched logs.")
                
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    end_time = datetime.now()
    print(f"\nProcessing time: {end_time - start_time}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())