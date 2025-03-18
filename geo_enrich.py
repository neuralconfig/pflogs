#!/usr/bin/env python3
"""
IP Geolocation and Threat Intel Enrichment CLI Tool

This script provides a command-line interface to enrich PF log data with
geolocation information, ASN data, and threat intelligence using the 
MaxMind GeoIP2 databases and various threat intelligence feeds.
"""

import os
import sys
import argparse
from datetime import datetime
import pandas as pd
from pflogs.core.ip_geo import IPGeolocation
from pflogs.core.threat_intel import ThreatIntelligence


def enrich_logs(logs_path_or_df, geo_db_path, ip_column='src_ip', output_path=None, 
                asn_db_path=None, threat_intel_dir=None, refresh_threat_intel=False):
    """
    Enrich log data with geolocation, ASN, and threat intelligence information.

    High-level function to enrich PF logs with geolocation data, ASN data, and
    threat intelligence data.

    Args:
        logs_path_or_df: Path to the Parquet file containing parsed PF logs OR a pandas DataFrame
        geo_db_path: Path to the MaxMind GeoIP2 City database (.mmdb file)
        ip_column: Name of the column containing IP addresses to look up
        output_path: Optional path to save the enriched logs as a Parquet file
        asn_db_path: Optional path to the MaxMind GeoIP2 ASN database (.mmdb file)
        threat_intel_dir: Optional path to the directory containing threat intelligence data
        refresh_threat_intel: Whether to force refresh of threat intelligence data

    Returns:
        A pandas DataFrame if output_path is None, otherwise None

    Raises:
        FileNotFoundError: If the database file or log file doesn't exist
        ValueError: If the specified IP column doesn't exist in the log data
    """
    # Check if the GeoIP database exists
    if not os.path.exists(geo_db_path):
        raise FileNotFoundError(f"GeoIP City database '{geo_db_path}' does not exist.")

    # Check if the ASN database exists if specified
    if asn_db_path and not os.path.exists(asn_db_path):
        raise FileNotFoundError(f"GeoIP ASN database '{asn_db_path}' does not exist.")

    # Load or use provided log data
    if isinstance(logs_path_or_df, pd.DataFrame):
        logs_df = logs_path_or_df
    else:
        # It's a file path
        if not os.path.exists(logs_path_or_df):
            raise FileNotFoundError(f"Log file not found: {logs_path_or_df}")
        logs_df = pd.read_parquet(logs_path_or_df)

    # Initialize geo/ASN lookup
    geo = IPGeolocation(geo_db_path, asn_db_path)

    # Enrich with geolocation and ASN data
    enriched_df = geo.enrich_dataframe(logs_df, ip_column)

    # Enrich with threat intelligence data if requested
    if threat_intel_dir:
        try:
            # Ensure threat directory exists
            os.makedirs(threat_intel_dir, exist_ok=True)
            
            # Create threat intelligence handler
            threat_intel = ThreatIntelligence(
                data_dir=threat_intel_dir,
                auto_refresh=True
            )
            
            # Force refresh if requested
            if refresh_threat_intel:
                threat_intel.refresh_blacklists()
                
            # Enrich with threat intelligence data
            enriched_df = threat_intel.enrich_dataframe(enriched_df, ip_column)
            
            # Add threat intelligence metadata
            threat_info = threat_intel.get_blacklist_info()
            # Store metadata as dataframe attributes
            enriched_df.attrs['threat_intel_info'] = threat_info
            
        except Exception as e:
            import logging
            logging.warning(f"Error enriching with threat intelligence: {e}")

    # Save to Parquet if an output path was provided
    if output_path:
        enriched_df.to_parquet(output_path, index=False)
        return None

    return enriched_df


def main():
    """Run the IP geolocation and threat intel enrichment CLI."""
    parser = argparse.ArgumentParser(
        description="Enrich PF log data with geolocation, ASN data, and threat intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic enrichment with geolocation data
  %(prog)s input.parquet -g data/geo/GeoLite2-City.mmdb -o enriched.parquet
  
  # Enrich with geolocation and ASN data
  %(prog)s input.parquet -g data/geo/GeoLite2-City.mmdb -a data/geo/GeoLite2-ASN.mmdb -o enriched.parquet
  
  # Enrich with geolocation, ASN, and threat intelligence
  %(prog)s input.parquet -g data/geo/GeoLite2-City.mmdb -a data/geo/GeoLite2-ASN.mmdb -t data/threat -o enriched.parquet
  
  # Refresh threat intelligence data before enrichment
  %(prog)s input.parquet -g data/geo/GeoLite2-City.mmdb -t data/threat --refresh-threat -o enriched.parquet
  
  # Show summary of enriched data
  %(prog)s input.parquet -g data/geo/GeoLite2-City.mmdb -a data/geo/GeoLite2-ASN.mmdb -t data/threat --summary
  
  # Batch processing by hour
  %(prog)s input.parquet -g data/geo/GeoLite2-City.mmdb -a data/geo/GeoLite2-ASN.mmdb -t data/threat -o enriched.parquet --batch-by hour
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
        "--refresh-threat",
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
        "--summary",
        action="store_true",
        help="Show summary of enriched data"
    )
    
    parser.add_argument(
        "--batch-by",
        choices=["hour", "day", "none"],
        default="none",
        help="Process data in batches by time period"
    )
    
    args = parser.parse_args()
    
    # Check if the input path exists
    if not os.path.exists(args.input_path):
        print(f"Error: Input path '{args.input_path}' does not exist.", file=sys.stderr)
        return 1
    
    # Check if the GeoIP database exists
    if not os.path.exists(args.geo_db):
        print(f"Error: GeoIP City database '{args.geo_db}' does not exist.", file=sys.stderr)
        return 1
    
    # Check if the ASN database exists if specified
    if args.asn_db and not os.path.exists(args.asn_db):
        print(f"Error: GeoIP ASN database '{args.asn_db}' does not exist.", file=sys.stderr)
        return 1
    
    # Prepare enrichment parameters
    enrichment_type = "geolocation"
    if args.asn_db:
        enrichment_type += ", ASN"
    if args.threat_dir:
        enrichment_type += ", and threat intelligence"
    
    print(f"Enriching logs from {args.input_path} with {enrichment_type} data...")
    start_time = datetime.now()
    
    try:
        # Load the log data
        logs_df = pd.read_parquet(args.input_path)
        
        if logs_df.empty:
            print("No logs were found in the input file.")
            return 0
        
        # Check if batch processing is requested
        if args.batch_by != "none" and 'timestamp' in logs_df.columns:
            print(f"Processing logs in batches by {args.batch_by}...")
            
            # Convert timestamp to datetime if needed
            if not pd.api.types.is_datetime64_any_dtype(logs_df['timestamp']):
                logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])
            
            # Create batches based on time period
            if args.batch_by == "hour":
                logs_df['batch_key'] = logs_df['timestamp'].dt.floor('H')
            elif args.batch_by == "day":
                logs_df['batch_key'] = logs_df['timestamp'].dt.floor('D')
            
            # Get unique batch keys
            batch_keys = logs_df['batch_key'].unique()
            print(f"Found {len(batch_keys)} time batches to process")
            
            # Process each batch separately
            all_enriched_dfs = []
            for batch_idx, batch_key in enumerate(batch_keys):
                batch_time = batch_key.strftime("%Y-%m-%d %H:%M")
                print(f"Processing batch {batch_idx+1}/{len(batch_keys)}: {batch_time}")
                batch_df = logs_df[logs_df['batch_key'] == batch_key]
                batch_size = len(batch_df)
                
                print(f"  - Starting enrichment for {batch_size} records...")
                start_batch_time = datetime.now()
                
                # Enrich this batch
                enriched_batch = enrich_logs(
                    batch_df, 
                    args.geo_db, 
                    args.column,
                    output_path=None,  # Don't save individual batches
                    asn_db_path=args.asn_db,
                    threat_intel_dir=args.threat_dir,
                    refresh_threat_intel=args.refresh_threat if batch_idx == 0 else False  # Only refresh on first batch
                )
                
                end_batch_time = datetime.now()
                batch_duration = end_batch_time - start_batch_time
                
                # Get stats for this batch
                geo_resolved = enriched_batch['geo_country_name'].notna().sum()
                geo_percent = geo_resolved / batch_size * 100 if batch_size > 0 else 0
                
                asn_resolved = 0
                if 'asn' in enriched_batch.columns:
                    asn_resolved = enriched_batch['asn'].notna().sum()
                asn_percent = asn_resolved / batch_size * 100 if batch_size > 0 else 0
                
                threat_count = 0
                if 'threat_is_malicious' in enriched_batch.columns:
                    threat_count = enriched_batch['threat_is_malicious'].sum()
                threat_percent = threat_count / batch_size * 100 if batch_size > 0 else 0
                
                all_enriched_dfs.append(enriched_batch)
                print(f"  - Batch {batch_idx+1} complete: {batch_size} logs processed in {batch_duration}")
                print(f"  - Geo resolved: {geo_resolved} ({geo_percent:.1f}%), ASN resolved: {asn_resolved} ({asn_percent:.1f}%)")
                if 'threat_is_malicious' in enriched_batch.columns:
                    print(f"  - Threats identified: {threat_count} ({threat_percent:.1f}%)")
            
            # Combine all enriched batches
            total_batch_rows = sum(len(df) for df in all_enriched_dfs)
            
            # First approach: preserve original row count by using row numbers
            # Add a row_id before batching to help identify artificial vs. legitimate duplicates
            
            # Concatenate batches
            enriched_df = pd.concat(all_enriched_dfs, ignore_index=True)
            
            # Count how many duplicated rows we have
            duplicated_count = len(enriched_df) - len(logs_df)
            
            if duplicated_count > 0:
                print(f"Detected {duplicated_count} potentially artificial duplicates")
                
                if duplicated_count > len(logs_df):
                    print("Artificial duplicate detection: Preserving original row count and data integrity")
                    
                    # Create a reference dataframe with original row order
                    reference_df = logs_df.copy()
                    if 'original_index' not in reference_df.columns:
                        reference_df['original_index'] = range(len(reference_df))
                    
                    # Get the key columns that identify a unique log entry
                    # We want to preserve all variations in timestamps, elapsed times, etc.
                    key_columns = list(reference_df.columns)
                    if 'batch_key' in key_columns:
                        key_columns.remove('batch_key')
                    if 'original_index' in key_columns:
                        key_columns.remove('original_index')
                    
                    # Use the original data as a reference to extract exactly one copy of each
                    # enriched record that corresponds to an original record
                    result_rows = []
                    
                    # Process each original row to find its corresponding enriched version
                    for _, orig_row in reference_df.iterrows():
                        # Build a query to find matching rows in enriched data
                        query = True
                        for col in key_columns:
                            if col in orig_row and col in enriched_df.columns:
                                query &= (enriched_df[col] == orig_row[col])
                        
                        # Get all matching rows and take the first one
                        matches = enriched_df[query]
                        if not matches.empty:
                            result_rows.append(matches.iloc[0])
                        else:
                            # If no match (unlikely), use the original row
                            result_rows.append(orig_row)
                    
                    # Create a new dataframe with exactly the same rows as the original
                    enriched_df = pd.DataFrame(result_rows)
                    
                    if 'original_index' in enriched_df.columns:
                        enriched_df = enriched_df.drop(columns=['original_index'])
                    
                    print(f"Preserved original {len(enriched_df)} rows while keeping enrichment data")
                else:
                    # If duplication is minimal, just use drop_duplicates to handle it
                    enriched_df = enriched_df.drop_duplicates()
                    print(f"Applied simple deduplication, resulting in {len(enriched_df)} rows")
            
            print(f"Combined {total_batch_rows} total rows from batches into {len(enriched_df)} final records")
            
            # Save to Parquet if output path provided
            if args.output:
                enriched_df.to_parquet(args.output, index=False)
                print(f"All batches enriched and saved to {args.output}")
                
                # If summary is requested, use the combined data
                if args.summary:
                    # Keep enriched_df as is
                    pass
                else:
                    enriched_df = None
            
        else:
            # Standard processing (no batching)
            if args.output:
                # Enrich and save to Parquet
                enrich_logs(
                    args.input_path, 
                    args.geo_db, 
                    args.column, 
                    args.output,
                    asn_db_path=args.asn_db,
                    threat_intel_dir=args.threat_dir,
                    refresh_threat_intel=args.refresh_threat
                )
                print(f"Enriched logs saved to {args.output}")
                
                # If summary is requested, load the enriched data
                if args.summary:
                    enriched_df = pd.read_parquet(args.output)
                else:
                    enriched_df = None
            else:
                # Enrich and display sample
                enriched_df = enrich_logs(
                    args.input_path, 
                    args.geo_db, 
                    args.column,
                    asn_db_path=args.asn_db,
                    threat_intel_dir=args.threat_dir,
                    refresh_threat_intel=args.refresh_threat
                )
                
                if enriched_df is None or enriched_df.empty:
                    print("No logs were enriched.")
                    return 0
                
                # Display sample entries
                print(f"\nSample entries ({min(args.sample, len(enriched_df))}):")
                print(enriched_df.head(args.sample))
        
        # Display summary if requested and we have the data
        if args.summary and enriched_df is not None:
            # Display geolocation summary
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
                
            # Display ASN summary
            asn_columns = [col for col in enriched_df.columns if col in ["asn", "asn_org", "network"]]
            if asn_columns:
                print("\nASN data summary:")
                
                # Top ASNs
                if "asn" in enriched_df.columns:
                    asn_counts = enriched_df["asn"].value_counts().head(10)
                    if not asn_counts.empty:
                        print("\nTop 10 source ASNs:")
                        for asn, count in asn_counts.items():
                            if asn is not None:
                                # Get the organization name for this ASN if available
                                asn_org = None
                                if "asn_org" in enriched_df.columns:
                                    asn_orgs = enriched_df[enriched_df["asn"] == asn]["asn_org"].unique()
                                    if len(asn_orgs) > 0 and asn_orgs[0] is not None:
                                        asn_org = asn_orgs[0]
                                        
                                asn_str = f"AS{asn}"
                                if asn_org:
                                    asn_str += f" ({asn_org})"
                                    
                                print(f"  {asn_str}: {count} ({count/len(enriched_df)*100:.1f}%)")
                
                # Count of unresolved ASNs
                if "asn" in enriched_df.columns:
                    null_count = enriched_df["asn"].isna().sum()
                    if null_count > 0:
                        print(f"\nUnresolved ASNs: {null_count} ({null_count/len(enriched_df)*100:.1f}%)")
            
            # Display threat intelligence summary
            threat_columns = [col for col in enriched_df.columns if col.startswith("threat_")]
            if threat_columns:
                print("\nThreat intelligence summary:")
                
                # Count of malicious IPs
                if "threat_is_malicious" in enriched_df.columns:
                    malicious_count = enriched_df["threat_is_malicious"].sum()
                    total_count = len(enriched_df)
                    if malicious_count > 0:
                        print(f"\nMalicious IPs: {malicious_count} ({malicious_count/total_count*100:.1f}%)")
                        
                        # Breakdown by source
                        for col in threat_columns:
                            if col != "threat_is_malicious":
                                source_name = col.replace("threat_", "")
                                source_count = enriched_df[col].sum()
                                if source_count > 0:
                                    print(f"  - {source_name}: {source_count} ({source_count/total_count*100:.1f}%)")
                
                # Show threat intelligence database info if available
                if hasattr(enriched_df, 'attrs') and 'threat_intel_info' in enriched_df.attrs:
                    threat_info = enriched_df.attrs['threat_intel_info']
                    print("\nThreat intelligence databases:")
                    for source, info in threat_info.items():
                        print(f"  - {source}: {info['count']} entries, updated {info['updated']} (age: {info['age']})")
                        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    end_time = datetime.now()
    print(f"\nProcessing time: {end_time - start_time}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())