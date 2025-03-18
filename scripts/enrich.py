#!/usr/bin/env python3
"""
Combined Enrichment CLI Tool

This script provides a command-line interface to enrich PF log data with
both geolocation information and threat intelligence using a single command.
"""

import os
import sys
import argparse
import logging
from datetime import datetime
import pandas as pd
from pflogs.core.ip_geo import enrich_with_geolocation
from pflogs.core.threat_intel import enrich_with_threat_intel
from pflogs.core.config import get_config, initialize_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Run the combined enrichment CLI."""
    # Initialize configuration
    initialize_config()
    config = get_config()
    
    parser = argparse.ArgumentParser(
        description="Enrich PF log data with geolocation and threat intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic enrichment with both geolocation and threat intel
  %(prog)s input.parquet -g data/geo/GeoLite2-City.mmdb -t data/threat -o enriched.parquet
  
  # Enrich with geolocation, ASN, and threat intel
  %(prog)s input.parquet -g data/geo/GeoLite2-City.mmdb -a data/geo/GeoLite2-ASN.mmdb -t data/threat -o enriched.parquet
  
  # Refresh threat intel data before enrichment
  %(prog)s input.parquet -g data/geo/GeoLite2-City.mmdb -t data/threat --refresh -o enriched.parquet
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
        "-t", "--threat-dir",
        help="Path to the directory for storing threat intelligence data"
    )
    
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Force refresh of threat intelligence data"
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
    
    print(f"Enriching logs from {args.input_path}...")
    start_time = datetime.now()
    
    try:
        # Load the log data
        logs_df = pd.read_parquet(args.input_path)
        print(f"Loaded {len(logs_df)} log entries from {args.input_path}")
        
        if logs_df.empty:
            print("No logs were found in the input file.")
            return 0
        
        # Step 1: Enrich with geolocation and ASN data
        print(f"Applying geolocation enrichment...")
        geo_start = datetime.now()
        enriched_df = enrich_with_geolocation(
            logs_df,
            args.geo_db,
            ip_column=args.column,
            asn_db_path=args.asn_db
        )
        geo_end = datetime.now()
        print(f"Geolocation enrichment completed in {geo_end - geo_start}")
        
        # Step 2: Enrich with threat intelligence data if requested
        if args.threat_dir:
            print(f"Applying threat intelligence enrichment...")
            threat_start = datetime.now()
            enriched_df = enrich_with_threat_intel(
                enriched_df,
                args.threat_dir,
                ip_column=args.column,
                refresh=args.refresh
            )
            threat_end = datetime.now()
            print(f"Threat intelligence enrichment completed in {threat_end - threat_start}")
        
        # Save to Parquet if output path provided
        if args.output:
            enriched_df.to_parquet(args.output, index=False)
            print(f"Enriched logs saved to {args.output}")
        
        # Display sample entries
        if not args.output or args.sample > 0:
            # Show a sample with geo and threat columns
            geo_cols = [col for col in enriched_df.columns if col.startswith("geo_")][:3]  # Limit to first 3 geo columns
            threat_cols = [col for col in enriched_df.columns if col.startswith("threat_")][:3]  # Limit to first 3 threat columns
            
            sample_cols = [args.column] + geo_cols + threat_cols
            print(f"\nSample entries ({min(args.sample, len(enriched_df))}):")
            print(enriched_df[sample_cols].head(args.sample))
            
            # Summary of enrichment
            print("\nEnrichment Summary:")
            
            # Geo summary
            if "geo_country_name" in enriched_df.columns:
                geo_resolved = enriched_df["geo_country_name"].notna().sum()
                geo_percent = geo_resolved / len(enriched_df) * 100
                print(f"- Geo resolved: {geo_resolved} ({geo_percent:.1f}%)")
                
                # Show top countries
                top_countries = enriched_df["geo_country_name"].value_counts().head(3)
                print("  Top countries:")
                for country, count in top_countries.items():
                    if country is not None:
                        print(f"    {country}: {count} ({count/len(enriched_df)*100:.1f}%)")
            
            # ASN summary
            if "geo_asn" in enriched_df.columns:
                asn_resolved = enriched_df["geo_asn"].notna().sum()
                asn_percent = asn_resolved / len(enriched_df) * 100
                print(f"- ASN resolved: {asn_resolved} ({asn_percent:.1f}%)")
            
            # Threat summary
            if "threat_is_malicious" in enriched_df.columns:
                malicious_count = enriched_df["threat_is_malicious"].sum()
                threat_percent = malicious_count / len(enriched_df) * 100
                print(f"- Malicious IPs: {malicious_count} ({threat_percent:.1f}%)")
                
                # Show breakdown by source
                for col in threat_cols:
                    if col != "threat_is_malicious":
                        source_name = col.replace("threat_", "")
                        source_count = enriched_df[col].sum()
                        if source_count > 0:
                            print(f"  - {source_name}: {source_count} ({source_count/len(enriched_df)*100:.1f}%)")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    
    end_time = datetime.now()
    print(f"\nTotal processing time: {end_time - start_time}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())