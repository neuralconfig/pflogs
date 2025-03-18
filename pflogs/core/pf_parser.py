"""
PF Firewall Log Parser Module.

This module provides functionality to parse PF firewall logs into structured data
that can be used for analysis and ML processing.
"""

import re
from datetime import datetime
import os
import gzip
from typing import Dict, List, Optional, Union, Any, TextIO, BinaryIO
import pandas as pd


class PFLogParser:
    """Parser for PF firewall logs.

    This class parses PF firewall logs into structured data format for further analysis.
    It supports multiple output formats including Pandas DataFrames and Parquet files.

    Attributes:
        log_pattern: Regular expression pattern to match PF log entries
    """

    # Pattern for the PF logs based on the observed format
    LOG_PATTERN = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2})\s+"
        r"(?P<hostname>[\w\.-]+)\s+pf\[\d+\]\s+"
        r"(?P<elapsed>[\d:.]+)\s+rule\s+"
        r"(?P<rule_info>[\w\d\.\/\(\)]+):\s+"
        r"(?P<action>\w+)\s+(?P<direction>\w+)\s+on\s+(?P<interface>\w+):\s+"
        r"(?P<src_ip>[\d\.]+)\.(?P<src_port>\d+)\s+>\s+"
        r"(?P<dst_ip>[\d\.]+)\.(?P<dst_port>\d+):\s+"
        r"(?P<protocol_info>.*)"
    )

    def __init__(self):
        """Initialize the PF log parser."""
        pass

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single line of PF log.

        Args:
            line: A string containing a single line from the PF log.

        Returns:
            A dictionary of parsed fields or None if the line isn't a valid PF log entry.
        """
        match = self.LOG_PATTERN.match(line)
        if not match:
            return None

        log_data = match.groupdict()

        # Convert timestamp to datetime
        try:
            log_data["timestamp"] = datetime.fromisoformat(log_data["timestamp"])
        except ValueError:
            # Keep the original timestamp if parsing fails
            pass

        # Process protocol info to extract more details
        protocol_info = log_data.get("protocol_info", "")

        # Check for TCP flags
        flags_match = re.search(r"Flags \[([^\]]+)\]", protocol_info)
        if flags_match:
            log_data["tcp_flags"] = flags_match.group(1)

        # Extract protocol
        if "UDP" in protocol_info:
            log_data["protocol"] = "UDP"
        elif "ICMP" in protocol_info:
            log_data["protocol"] = "ICMP"
        elif "Flags" in protocol_info:  # TCP typically has flags
            log_data["protocol"] = "TCP"
        else:
            log_data["protocol"] = "OTHER"

        # Extract packet length if available
        length_match = re.search(r"length (\d+)", protocol_info)
        if length_match:
            log_data["length"] = int(length_match.group(1))

        # Extract sequence number if available (for TCP)
        seq_match = re.search(r"seq (\d+)", protocol_info)
        if seq_match:
            log_data["seq"] = int(seq_match.group(1))

        # Extract window size if available (for TCP)
        win_match = re.search(r"win (\d+)", protocol_info)
        if win_match:
            log_data["win"] = int(win_match.group(1))

        return log_data

    def parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse a PF log file.

        Args:
            file_path: Path to the PF log file.

        Returns:
            A list of dictionaries containing the parsed log entries.

        Raises:
            FileNotFoundError: If the specified file doesn't exist.
        """
        parsed_logs = []
        
        # Check if file is gzipped
        is_gzipped = file_path.endswith('.gz')
        
        if is_gzipped:
            with gzip.open(file_path, 'rt', encoding='utf-8', errors='replace') as f:
                for line in f:
                    log_entry = self.parse_line(line.strip())
                    if log_entry:
                        parsed_logs.append(log_entry)
        else:
            with open(file_path, "r", encoding='utf-8', errors='replace') as f:
                for line in f:
                    log_entry = self.parse_line(line.strip())
                    if log_entry:
                        parsed_logs.append(log_entry)

        return parsed_logs

    def parse_directory(
        self, dir_path: str, pattern: str = "*.log*"
    ) -> List[Dict[str, Any]]:
        """Parse all matching files in a directory.

        Args:
            dir_path: Path to the directory containing PF log files.
            pattern: Glob pattern to match specific log files (default: '*.log*').
                     The default pattern will match both .log and .log.gz files.

        Returns:
            A list of dictionaries containing the parsed log entries.

        Raises:
            FileNotFoundError: If the specified directory doesn't exist.
        """
        import glob

        all_logs = []
        file_paths = glob.glob(os.path.join(dir_path, pattern))

        for file_path in file_paths:
            if os.path.isfile(file_path):
                logs = self.parse_file(file_path)
                all_logs.extend(logs)

        return all_logs

    def to_dataframe(self, logs: List[Dict[str, Any]]) -> pd.DataFrame:
        """Convert parsed logs to a pandas DataFrame.

        Args:
            logs: A list of dictionaries containing parsed log entries.

        Returns:
            A pandas DataFrame with the parsed log data.
        """
        return pd.DataFrame(logs)

    def to_parquet(self, logs: List[Dict[str, Any]], file_path: str) -> None:
        """Save parsed logs to a Parquet file.

        Args:
            logs: A list of dictionaries containing parsed log entries.
            file_path: Path where the Parquet file will be saved.

        Returns:
            None
        """
        df = self.to_dataframe(logs)
        df.to_parquet(file_path, index=False)

    def parse_to_parquet(self, input_path: str, output_path: str) -> None:
        """Parse logs from file or directory and save to Parquet.

        Args:
            input_path: Path to log file or directory containing log files.
            output_path: Path where the Parquet file will be saved.

        Returns:
            None

        Raises:
            FileNotFoundError: If the input path doesn't exist.
        """
        if os.path.isdir(input_path):
            logs = self.parse_directory(input_path)
        else:
            logs = self.parse_file(input_path)

        self.to_parquet(logs, output_path)


def parse_logs(
    input_path: str, output_path: Optional[str] = None
) -> Optional[pd.DataFrame]:
    """Parse PF logs from file or directory.

    High-level function to parse PF logs from file or directory and
    return as DataFrame or save to Parquet file.

    Args:
        input_path: Path to log file or directory containing log files.
        output_path: Optional path to save parsed logs as Parquet file.

    Returns:
        A pandas DataFrame if output_path is None, otherwise None.

    Raises:
        FileNotFoundError: If the input path doesn't exist.
    """
    parser = PFLogParser()

    if os.path.isdir(input_path):
        logs = parser.parse_directory(input_path)
    else:
        logs = parser.parse_file(input_path)

    if output_path:
        parser.to_parquet(logs, output_path)
        return None
    else:
        return parser.to_dataframe(logs)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Parse PF firewall logs")
    parser.add_argument("input", help="Input log file or directory")
    parser.add_argument("-o", "--output", help="Output Parquet file path")

    args = parser.parse_args()

    if args.output:
        parse_logs(args.input, args.output)
        print(f"Parsed logs saved to {args.output}")
    else:
        df = parse_logs(args.input)
        if df is not None:
            print(df.head())
            print(f"Total entries: {len(df)}")
