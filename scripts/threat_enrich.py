#!/usr/bin/env python3
"""
Threat Intelligence Enrichment CLI Tool

This script provides a command-line interface to enrich PF log data with
threat intelligence information using various threat feeds.
"""

import os
import sys
import argparse
import logging
from datetime import datetime
import pandas as pd
from pflogs.core.threat_intel import enrich_with_threat_intel, ThreatIntelligence
from pflogs.core.config import get_config, initialize_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Run the threat intelligence enrichment CLI."""
    # Initialize configuration
    initialize_config()
    config = get_config()
    
    parser = argparse.ArgumentParser(
        description="Enrich PF log data with threat intelligence information",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic enrichment with threat intelligence
  %(prog)s input.parquet -t data/threat -o enriched.parquet
  
  # Refresh threat intelligence data before enrichment
  %(prog)s input.parquet -t data/threat --refresh -o enriched.parquet
  
  # Show threat intelligence information
  %(prog)s input.parquet -t data/threat --info
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
        "-t", "--threat-dir",
        required=True,
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
    
    parser.add_argument(
        "--info",
        action="store_true",
        help="Show threat intelligence information only"
    )
    
    args = parser.parse_args()
    
    # If only showing threat intelligence info, do that first
    if args.info:
        try:
            # Ensure threat directory exists
            os.makedirs(args.threat_dir, exist_ok=True)
            
            # Create threat intelligence handler
            threat_intel = ThreatIntelligence(data_dir=args.threat_dir, auto_refresh=True)
            
            # Force refresh if requested
            if args.refresh:
                print("Refreshing threat intelligence data...")
                threat_intel.refresh_blacklists()
            
            # Get and display threat info
            threat_info = threat_intel.get_blacklist_info()
            print(f"Threat intelligence sources: {len(threat_info)}")
            
            for source, info in threat_info.items():
                print(f"  - {source}: {info['count']} entries, updated {info['updated']} (age: {info['age']})")
                
            return 0
        except Exception as e:
            print(f"Error getting threat intelligence information: {e}", file=sys.stderr)
            return 1
    
    # Check if the input path exists
    if not os.path.exists(args.input_path):
        print(f"Error: Input file '{args.input_path}' does not exist.", file=sys.stderr)
        return 1
    
    print(f"Enriching logs from {args.input_path} with threat intelligence data...")
    start_time = datetime.now()
    
    try:
        # Load the log data
        logs_df = pd.read_parquet(args.input_path)
        print(f"Loaded {len(logs_df)} log entries from {args.input_path}")
        
        if logs_df.empty:
            print("No logs were found in the input file.")
            return 0
        
        # Enrich with threat intelligence data
        enriched_df = enrich_with_threat_intel(
            logs_df,
            args.threat_dir,
            ip_column=args.column,
            refresh=args.refresh
        )
        
        # Check for malicious IPs
        if 'threat_is_malicious' in enriched_df.columns:
            malicious_count = enriched_df['threat_is_malicious'].sum()
            print(f"Found {malicious_count} malicious IPs ({malicious_count/len(logs_df)*100:.2f}%)")
            
            # Breakdown by source
            threat_columns = [col for col in enriched_df.columns if col.startswith('threat_') and col != 'threat_is_malicious']
            for col in threat_columns:
                source_name = col.replace('threat_', '')
                source_count = enriched_df[col].sum()
                if source_count > 0:
                    print(f"  - {source_name}: {source_count} ({source_count/len(logs_df)*100:.2f}%)")
        else:
            print("No malicious IPs found (threat_is_malicious column not present)")
        
        # Save to Parquet if output path provided
        if args.output:
            enriched_df.to_parquet(args.output, index=False)
            print(f"Enriched logs saved to {args.output}")
        
        # Display sample entries
        if not args.output or args.sample > 0:
            # Only show the IP column and threat columns for malicious IPs
            if 'threat_is_malicious' in enriched_df.columns:
                malicious_df = enriched_df[enriched_df['threat_is_malicious'] == True]
                if not malicious_df.empty:
                    threat_cols = [col for col in enriched_df.columns if col.startswith("threat_")]
                    sample_cols = [args.column] + threat_cols
                    print(f"\nSample malicious entries ({min(args.sample, len(malicious_df))}):")
                    print(malicious_df[sample_cols].head(args.sample))
                else:
                    print("\nNo malicious IPs found in the dataset.")
            else:
                print("\nNo threat intelligence data found in the dataset.")
        
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