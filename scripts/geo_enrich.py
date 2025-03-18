#!/usr/bin/env python3
"""
IP Geolocation Enrichment CLI Tool

This script provides a command-line interface to enrich PF log data with
geolocation information and ASN data using the MaxMind GeoIP2 databases.
"""

import os
import sys
import argparse
import logging
from datetime import datetime
import pandas as pd
from pflogs.core.ip_geo import enrich_with_geolocation
from pflogs.core.config import get_config, initialize_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Run the IP geolocation enrichment CLI."""
    # Initialize configuration
    initialize_config()
    config = get_config()
    
    parser = argparse.ArgumentParser(
        description="Enrich PF log data with geolocation and ASN data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic enrichment with geolocation data
  %(prog)s input.parquet -g data/geo/GeoLite2-City.mmdb -o enriched.parquet
  
  # Enrich with geolocation and ASN data
  %(prog)s input.parquet -g data/geo/GeoLite2-City.mmdb -a data/geo/GeoLite2-ASN.mmdb -o enriched.parquet
  
  # Show sample of enriched data
  %(prog)s input.parquet -g data/geo/GeoLite2-City.mmdb --sample 10
"""
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
        "-g", "--geo-db",
        required=True,
        help="Path to the MaxMind GeoIP2 City database (.mmdb file)"
    )
    
    parser.add_argument(
        "-a", "--asn-db",
        help="Path to the MaxMind GeoIP2 ASN database (.mmdb file)"
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
    
    args = parser.parse_args()
    
    # Check if the input path exists
    if not os.path.exists(args.input_path):
        print(f"Error: Input file '{args.input_path}' does not exist.", file=sys.stderr)
        return 1
    
    # Check if the GeoIP database exists
    if not os.path.exists(args.geo_db):
        print(f"Error: GeoIP City database '{args.geo_db}' does not exist.", file=sys.stderr)
        return 1
    
    # Check if the ASN database exists if specified
    if args.asn_db and not os.path.exists(args.asn_db):
        print(f"Error: GeoIP ASN database '{args.asn_db}' does not exist.", file=sys.stderr)
        return 1
    
    print(f"Enriching logs from {args.input_path} with geolocation data...")
    start_time = datetime.now()
    
    try:
        # Load the log data
        logs_df = pd.read_parquet(args.input_path)
        print(f"Loaded {len(logs_df)} log entries from {args.input_path}")
        
        if logs_df.empty:
            print("No logs were found in the input file.")
            return 0
        
        # Enrich with geolocation and ASN data
        enriched_df = enrich_with_geolocation(
            logs_df,
            args.geo_db,
            ip_column=args.column,
            asn_db_path=args.asn_db
        )
        
        # Save to Parquet if output path provided
        if args.output:
            enriched_df.to_parquet(args.output, index=False)
            print(f"Enriched logs saved to {args.output}")
        
        # Display sample entries
        if not args.output or args.sample > 0:
            print(f"\nSample entries ({min(args.sample, len(enriched_df))}):")
            # Show only geo columns and the IP column
            geo_cols = [col for col in enriched_df.columns if col.startswith("geo_")]
            sample_cols = [args.column] + geo_cols
            print(enriched_df[sample_cols].head(args.sample))
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    
    end_time = datetime.now()
    print(f"\nProcessing time: {end_time - start_time}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())