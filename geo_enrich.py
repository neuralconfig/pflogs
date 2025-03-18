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
import logging
from datetime import datetime
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from pflogs.core.ip_geo import IPGeolocation, enrich_logs_with_geo, process_df_in_chunks
from pflogs.core.threat_intel import ThreatIntelligence
from pflogs.core.config import get_config, initialize_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def enrich_with_geolocation(logs_df, geo_db_path, ip_column='src_ip', asn_db_path=None):
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
    print(f"Enriching {len(logs_df)} log entries with geolocation data...")
    start_time = datetime.now()
    
    # Use the improved implementation from ip_geo module
    enriched_df = enrich_logs_with_geo(
        logs_df,
        geo_db_path,
        ip_column=ip_column,
        asn_db_path=asn_db_path
    )
    
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"Geolocation enrichment completed in {duration}")
    
    return enriched_df

def enrich_with_threat_intel(logs_df, threat_intel_dir, ip_column='src_ip', refresh=False):
    """
    Enrich log data with threat intelligence data only.
    
    Args:
        logs_df: DataFrame containing PF logs
        threat_intel_dir: Path to the directory containing threat intelligence data
        ip_column: Name of the column containing IP addresses
        refresh: Whether to force refresh of threat intelligence data
        
    Returns:
        DataFrame with threat intelligence enrichment
    """
    if not threat_intel_dir:
        return logs_df
        
    print(f"Enriching {len(logs_df)} log entries with threat intelligence data...")
    start_time = datetime.now()
    
    try:
        # Ensure threat directory exists
        os.makedirs(threat_intel_dir, exist_ok=True)
        
        # Create threat intelligence handler
        threat_intel = ThreatIntelligence(
            data_dir=threat_intel_dir,
            auto_refresh=True
        )
        
        # Force refresh if requested
        if refresh:
            print("Refreshing threat intelligence data...")
            threat_intel.refresh_blacklists()
            
        # Enrich with threat intelligence data
        enriched_df = threat_intel.enrich_dataframe(logs_df, ip_column)
        
        # Add threat intelligence metadata
        threat_info = threat_intel.get_blacklist_info()
        # Store metadata as dataframe attributes
        enriched_df.attrs['threat_intel_info'] = threat_info
        
        end_time = datetime.now()
        duration = end_time - start_time
        print(f"Threat intelligence enrichment completed in {duration}")
        
        return enriched_df
        
    except Exception as e:
        logger.error(f"Error enriching with threat intelligence: {e}")
        # Return the original dataframe if there's an error
        return logs_df

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

    # First, enrich with geolocation and ASN data
    enriched_df = enrich_with_geolocation(
        logs_df,
        geo_db_path,
        ip_column=ip_column,
        asn_db_path=asn_db_path
    )

    # Next, enrich with threat intelligence if requested
    if threat_intel_dir:
        enriched_df = enrich_with_threat_intel(
            enriched_df,
            threat_intel_dir,
            ip_column=ip_column,
            refresh=refresh_threat_intel
        )

    # Save to Parquet if an output path was provided
    if output_path:
        enriched_df.to_parquet(output_path, index=False)
        return None

    return enriched_df


def process_batch(batch_df, geo_db_path, ip_column, asn_db_path, threat_intel_dir, refresh_threat_intel):
    """
    Process a batch of log data with enrichment.
    
    Args:
        batch_df: DataFrame batch to process
        geo_db_path: Path to the GeoIP City database
        ip_column: Name of the IP column
        asn_db_path: Path to the ASN database
        threat_intel_dir: Path to the threat intelligence directory
        refresh_threat_intel: Whether to refresh threat intel
        
    Returns:
        Enriched DataFrame batch
    """
    batch_size = len(batch_df)
    print(f"  - Starting enrichment for {batch_size} records...")
    start_batch_time = datetime.now()
    
    # Enrich this batch
    enriched_batch = enrich_logs(
        batch_df, 
        geo_db_path, 
        ip_column,
        output_path=None,  # Don't save individual batches
        asn_db_path=asn_db_path,
        threat_intel_dir=threat_intel_dir,
        refresh_threat_intel=refresh_threat_intel
    )
    
    end_batch_time = datetime.now()
    batch_duration = end_batch_time - start_batch_time
    
    # Get stats for this batch
    geo_resolved = enriched_batch['geo_country_name'].notna().sum()
    geo_percent = geo_resolved / batch_size * 100 if batch_size > 0 else 0
    
    asn_resolved = 0
    if 'geo_asn' in enriched_batch.columns:
        asn_resolved = enriched_batch['geo_asn'].notna().sum()
    asn_percent = asn_resolved / batch_size * 100 if batch_size > 0 else 0
    
    threat_count = 0
    if 'threat_is_malicious' in enriched_batch.columns:
        threat_count = enriched_batch['threat_is_malicious'].sum()
    threat_percent = threat_count / batch_size * 100 if batch_size > 0 else 0
    
    print(f"  - Batch complete: {batch_size} logs processed in {batch_duration}")
    print(f"  - Geo resolved: {geo_resolved} ({geo_percent:.1f}%), ASN resolved: {asn_resolved} ({asn_percent:.1f}%)")
    if 'threat_is_malicious' in enriched_batch.columns:
        print(f"  - Threats identified: {threat_count} ({threat_percent:.1f}%)")
        
    return enriched_batch


def main():
    """Run the IP geolocation and threat intel enrichment CLI."""
    # Initialize configuration
    initialize_config()
    config = get_config()
    
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
  
  # Use parallel processing (4 workers)
  %(prog)s input.parquet -g data/geo/GeoLite2-City.mmdb -a data/geo/GeoLite2-ASN.mmdb -t data/threat -o enriched.parquet --workers 4
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
    
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=None,
        help=f"Size of data chunks to process (default: {config.get('processing', 'chunk_size', 100000)})"
    )
    
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help=f"Number of worker processes for parallel processing (default: {config.get('processing', 'max_workers', 4)})"
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
    
    # Update configuration with CLI arguments
    if args.chunk_size:
        config.update("processing", "chunk_size", args.chunk_size)
        
    if args.workers:
        config.update("processing", "max_workers", args.workers)
    
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
            # Allow parallel processing if requested
            max_workers = config.get("processing", "max_workers")
            if max_workers > 1:
                print(f"Processing batches in parallel with {max_workers} workers")
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = []
                    for batch_idx, batch_key in enumerate(batch_keys):
                        batch_time = batch_key.strftime("%Y-%m-%d %H:%M")
                        print(f"Submitting batch {batch_idx+1}/{len(batch_keys)}: {batch_time}")
                        batch_df = logs_df[logs_df['batch_key'] == batch_key]
                        
                        # Only refresh threat intel on first batch
                        refresh = args.refresh_threat if batch_idx == 0 else False
                        
                        # Submit the batch for processing
                        future = executor.submit(
                            process_batch,
                            batch_df,
                            args.geo_db,
                            args.column,
                            args.asn_db,
                            args.threat_dir,
                            refresh
                        )
                        futures.append((batch_idx, future))
                    
                    # Collect results as they complete
                    all_enriched_dfs = []
                    for batch_idx, future in sorted(futures, key=lambda x: x[0]):
                        all_enriched_dfs.append(future.result())
            else:
                # Process batches sequentially
                all_enriched_dfs = []
                for batch_idx, batch_key in enumerate(batch_keys):
                    batch_time = batch_key.strftime("%Y-%m-%d %H:%M")
                    print(f"Processing batch {batch_idx+1}/{len(batch_keys)}: {batch_time}")
                    batch_df = logs_df[logs_df['batch_key'] == batch_key]
                    
                    # Process this batch
                    enriched_batch = process_batch(
                        batch_df,
                        args.geo_db,
                        args.column,
                        args.asn_db,
                        args.threat_dir,
                        args.refresh_threat if batch_idx == 0 else False  # Only refresh on first batch
                    )
                    
                    all_enriched_dfs.append(enriched_batch)
            
            # Combine all enriched batches while preserving original row count
            input_row_count = len(logs_df)
            print(f"Preserving original {input_row_count} rows while combining batches")
            
            # Create a reference dataframe with original row order
            reference_df = logs_df.copy()
            if 'original_index' not in reference_df.columns:
                reference_df['original_index'] = range(len(reference_df))
            
            # Concatenate batches
            combined_df = pd.concat(all_enriched_dfs, ignore_index=True)
            
            # Copy batch keys to ensure we can match back to original
            if 'batch_key' not in combined_df.columns and 'batch_key' in reference_df.columns:
                # We need to merge the batch_key back
                for batch_idx, batch_key in enumerate(batch_keys):
                    mask = reference_df['batch_key'] == batch_key
                    reference_rows = reference_df[mask].index
                    for row_idx in reference_rows:
                        combined_df.loc[combined_df.index == row_idx, 'batch_key'] = batch_key
            
            # Ensure we maintain the original row count by reindexing
            enriched_df = pd.DataFrame(index=range(input_row_count))
            
            # Copy all columns from the combined dataframe
            for col in combined_df.columns:
                if col != 'original_index' and col != 'batch_key':
                    enriched_df[col] = combined_df[col].values
            
            print(f"Successfully combined batches into {len(enriched_df)} rows")
            
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
            asn_columns = [col for col in enriched_df.columns if col in ["geo_asn", "geo_asn_org", "geo_network"]]
            if asn_columns:
                print("\nASN data summary:")
                
                # Top ASNs
                if "geo_asn" in enriched_df.columns:
                    asn_counts = enriched_df["geo_asn"].value_counts().head(10)
                    if not asn_counts.empty:
                        print("\nTop 10 source ASNs:")
                        for asn, count in asn_counts.items():
                            if asn is not None:
                                # Get the organization name for this ASN if available
                                asn_org = None
                                if "geo_asn_org" in enriched_df.columns:
                                    asn_orgs = enriched_df[enriched_df["geo_asn"] == asn]["geo_asn_org"].unique()
                                    if len(asn_orgs) > 0 and asn_orgs[0] is not None:
                                        asn_org = asn_orgs[0]
                                        
                                asn_str = f"AS{asn}"
                                if asn_org:
                                    asn_str += f" ({asn_org})"
                                    
                                print(f"  {asn_str}: {count} ({count/len(enriched_df)*100:.1f}%)")
                
                # Count of unresolved ASNs
                if "geo_asn" in enriched_df.columns:
                    null_count = enriched_df["geo_asn"].isna().sum()
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
        import traceback
        traceback.print_exc()
        return 1
    
    end_time = datetime.now()
    print(f"\nProcessing time: {end_time - start_time}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())