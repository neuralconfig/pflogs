#!/usr/bin/env python
"""
PF Log Parser CLI Tool

This script provides a command-line interface to the PF log parser.
It can process log files or directories and output structured data.
"""

import os
import sys
import argparse
from datetime import datetime
from pflogs.core.pf_parser import parse_logs


def main():
    """Run the PF log parser CLI."""
    parser = argparse.ArgumentParser(
        description="Parse PF firewall logs into structured data format"
    )
    
    parser.add_argument(
        "input_path",
        help="Path to the log file or directory containing log files"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Path to save the parsed logs as a Parquet file"
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
        print(f"Error: Input path '{args.input_path}' does not exist.", file=sys.stderr)
        return 1
    
    print(f"Parsing logs from {args.input_path}...")
    start_time = datetime.now()
    
    if args.output:
        # Parse and save to Parquet
        parse_logs(args.input_path, args.output)
        print(f"Parsed logs saved to {args.output}")
    else:
        # Parse and display sample
        df = parse_logs(args.input_path)
        
        if df.empty:
            print("No logs were parsed.")
            return 0
        
        # Display statistics
        print(f"\nTotal entries: {len(df)}")
        print(f"\nProtocol distribution:")
        if 'protocol' in df.columns:
            protocol_counts = df['protocol'].value_counts()
            for protocol, count in protocol_counts.items():
                print(f"  {protocol}: {count} ({count/len(df)*100:.1f}%)")
        
        # Display sample entries
        print(f"\nSample entries ({min(args.sample, len(df))}):")
        print(df.head(args.sample))
    
    end_time = datetime.now()
    print(f"\nProcessing time: {end_time - start_time}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())