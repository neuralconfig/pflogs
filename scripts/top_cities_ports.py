#!/usr/bin/env python3
"""
Top Geographic Analysis CLI Tool

This script provides a command-line interface to analyze PF log data
and display the top cities and countries with their top destination ports.
"""

import os
import sys
import argparse
import pandas as pd


def analyze_top_locations_ports(
    input_path: str, 
    num_locations: int = 10, 
    num_ports: int = 5
):
    """
    Analyze PF log data to find top cities and countries with top destination ports.
    
    Args:
        input_path: Path to the Parquet file containing enriched PF logs
        num_locations: Number of top cities/countries to display (default: 10)
        num_ports: Number of top destination ports per location to display (default: 5)
        
    Returns:
        None
    """
    # Check if the input file exists
    if not os.path.exists(input_path):
        print(f"Error: Input file '{input_path}' does not exist.", file=sys.stderr)
        return 1
    
    # Load the enriched log data
    try:
        df = pd.read_parquet(input_path)
    except Exception as e:
        print(f"Error loading Parquet file: {e}", file=sys.stderr)
        return 1
    
    # Check if we have the required columns
    required_cols = ['geo_city', 'geo_country_name', 'dst_port']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        print(f"Error: Required columns {missing_cols} not found in the data.", file=sys.stderr)
        return 1
    
    # Analyze cities
    analyze_top_cities(df, num_locations, num_ports)
    
    # Analyze countries
    analyze_top_countries(df, num_locations, num_ports)
    
    return 0


def analyze_top_cities(df: pd.DataFrame, num_cities: int = 10, num_ports: int = 5):
    """
    Analyze and display top cities with their top destination ports.
    
    Args:
        df: DataFrame containing enriched PF logs
        num_cities: Number of top cities to display
        num_ports: Number of top destination ports per city to display
    """
    # Filter out rows with null city
    city_df = df[df['geo_city'].notna()]
    
    # Get the top cities by frequency
    top_cities = city_df['geo_city'].value_counts().head(num_cities)
    
    print(f"\nTop {min(num_cities, len(top_cities))} Cities with Top {num_ports} Destination Ports:")
    print("-" * 80)
    
    # Analyze each top city
    for city, count in top_cities.items():
        # Get data for this city
        city_data = city_df[city_df['geo_city'] == city]
        
        # Get top destination ports for this city
        top_ports = city_data['dst_port'].value_counts().head(num_ports)
        
        # Display city information
        print(f"\n{city} ({count} connections)")
        
        # Display top ports
        if not top_ports.empty:
            print("  Top destination ports:")
            for port, port_count in top_ports.items():
                port_percent = port_count / count * 100
                service = get_service_name(port)
                print(f"    Port {port} ({service}): {port_count} connections ({port_percent:.1f}%)")
        else:
            print("  No port data available")


def analyze_top_countries(df: pd.DataFrame, num_countries: int = 10, num_ports: int = 5):
    """
    Analyze and display top countries with their top destination ports.
    
    Args:
        df: DataFrame containing enriched PF logs
        num_countries: Number of top countries to display
        num_ports: Number of top destination ports per country to display
    """
    # Filter out rows with null country
    country_df = df[df['geo_country_name'].notna()]
    
    # Get the top countries by frequency
    top_countries = country_df['geo_country_name'].value_counts().head(num_countries)
    
    print(f"\nTop {min(num_countries, len(top_countries))} Countries with Top {num_ports} Destination Ports:")
    print("-" * 80)
    
    # Analyze each top country
    for country, count in top_countries.items():
        # Get data for this country
        country_data = country_df[country_df['geo_country_name'] == country]
        
        # Get top destination ports for this country
        top_ports = country_data['dst_port'].value_counts().head(num_ports)
        
        # Display country information
        print(f"\n{country} ({count} connections)")
        
        # Display top ports
        if not top_ports.empty:
            print("  Top destination ports:")
            for port, port_count in top_ports.items():
                port_percent = port_count / count * 100
                service = get_service_name(port)
                print(f"    Port {port} ({service}): {port_count} connections ({port_percent:.1f}%)")
        else:
            print("  No port data available")


def analyze_protocol_distribution(df: pd.DataFrame):
    """
    Analyze and display the distribution of protocols.
    
    Args:
        df: DataFrame containing enriched PF logs
    """
    if 'protocol' not in df.columns:
        return
    
    print("\nProtocol Distribution:")
    print("-" * 80)
    
    protocol_counts = df['protocol'].value_counts()
    total_count = len(df)
    
    for protocol, count in protocol_counts.items():
        percent = count / total_count * 100
        print(f"{protocol}: {count} connections ({percent:.1f}%)")


def analyze_hourly_traffic(df: pd.DataFrame):
    """
    Analyze and display hourly traffic patterns.
    
    Args:
        df: DataFrame containing enriched PF logs
    """
    if 'timestamp' not in df.columns:
        return
    
    print("\nHourly Traffic Distribution:")
    print("-" * 80)
    
    # Convert timestamp to datetime if it's not already
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Extract hour and count connections per hour
    df['hour'] = df['timestamp'].dt.hour
    hourly_counts = df['hour'].value_counts().sort_index()
    
    total_count = len(df)
    for hour, count in hourly_counts.items():
        percent = count / total_count * 100
        print(f"Hour {hour:02d}:00-{hour:02d}:59: {count} connections ({percent:.1f}%)")


def analyze_source_ports(df: pd.DataFrame, num_ports: int = 10):
    """
    Analyze and display source port distribution.
    
    Args:
        df: DataFrame containing enriched PF logs
        num_ports: Number of top source ports to display
    """
    if 'src_port' not in df.columns:
        return
    
    print("\nTop Source Ports Distribution:")
    print("-" * 80)
    
    # Get top source ports
    src_port_counts = df['src_port'].value_counts().head(num_ports)
    
    total_count = len(df)
    for port, count in src_port_counts.items():
        percent = count / total_count * 100
        service_name = get_service_name(port)
        print(f"Port {port} ({service_name}): {count} connections ({percent:.1f}%)")


def analyze_interfaces(df: pd.DataFrame):
    """
    Analyze and display network interface distribution.
    
    Args:
        df: DataFrame containing enriched PF logs
    """
    if 'interface' not in df.columns:
        return
    
    print("\nNetwork Interface Distribution:")
    print("-" * 80)
    
    interface_counts = df['interface'].value_counts()
    total_count = len(df)
    
    for interface, count in interface_counts.items():
        percent = count / total_count * 100
        print(f"Interface {interface}: {count} connections ({percent:.1f}%)")
    
    # Show interfaces by direction if available
    if 'direction' in df.columns:
        print("\nInterface and Direction:")
        print("-" * 80)
        
        direction_interface = df.groupby(['interface', 'direction']).size().reset_index()
        direction_interface.columns = ['interface', 'direction', 'count']
        direction_interface = direction_interface.sort_values(['interface', 'count'], ascending=[True, False])
        
        current_interface = None
        for _, row in direction_interface.iterrows():
            interface = row['interface']
            direction = row['direction']
            count = row['count']
            percent = count / total_count * 100
            
            if interface != current_interface:
                print(f"\nInterface {interface}:")
                current_interface = interface
                
            print(f"  {direction}: {count} connections ({percent:.1f}%)")


def get_service_name(port: int) -> str:
    """
    Get the service name for common ports.
    
    Args:
        port: Port number
        
    Returns:
        Service name or "Unknown" if not in the common ports list
    """
    common_ports = {
        20: "FTP-data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",
        1024: "Reserved",
        1080: "SOCKS",
        1443: "HTTPS-Alt",
        1723: "PPTP",
        1735: "WBEM",
        2017: "Dyn-Discovery",
        3118: "WCCP",
        3128: "HTTP-Proxy",
        3306: "MySQL",
        3311: "SSL-Proxy",
        3322: "SCCS",
        3333: "SIP",
        3343: "MS-Cluster",
        3389: "RDP",
        3407: "LDAP-Admin",
        4020: "HTTP-Alt",
        4040: "H2-Alt",
        4145: "SOCKS-Alt",
        4433: "HTTPS-Alt",
        4443: "HTTPS-Alt",
        4445: "MSRPC",
        5051: "ITA-Agent",
        5060: "SIP",
        5432: "PostgreSQL",
        5443: "HTTPS-Alt",
        5632: "PCAnywhere",
        5633: "SQL-NET",
        5900: "VNC",
        6589: "Minger",
        6991: "SFTPS",
        7001: "WebLogic",
        7789: "OMF",
        8000: "HTTP-Alt",
        8080: "HTTP-Alt",
        8088: "HTTP-Alt",
        8389: "LDAP-Alt",
        8443: "HTTPS-Alt",
        8543: "HTTP-Alt",
        8648: "HTTP-Alt",
        8650: "HTTP-Alt",
        8728: "MikroTik API",
        9080: "HTTP-Alt",
        9396: "WebDAV",
        9443: "HTTPS-Alt",
        10810: "SOCKS-Alt",
        11889: "DICOM",
        27489: "Citrix",
        34567: "DVR",
        55555: "Oracle"
    }
    
    # Try to get the service name from our dictionary
    service_name = common_ports.get(port, "Unknown")
    return service_name


def main():
    """Run the top locations and ports analysis CLI."""
    parser = argparse.ArgumentParser(
        description="Analyze PF log data to find top cities and countries with their top destination ports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis of top cities and countries
  %(prog)s data/enriched.parquet
  
  # Show top 5 cities with top 10 ports per city
  %(prog)s data/enriched.parquet -n 5 -p 10
  
  # Include protocol and hourly traffic analysis
  %(prog)s data/enriched.parquet --protocol --hourly
  
  # Complete analysis with all available options
  %(prog)s data/enriched.parquet --protocol --hourly --source-ports --interfaces
"""
    )
    
    parser.add_argument(
        "input_path",
        help="Path to the Parquet file containing enriched PF logs"
    )
    
    parser.add_argument(
        "-n", "--number",
        type=int,
        default=10,
        help="Number of top cities/countries to display (default: 10)"
    )
    
    parser.add_argument(
        "-p", "--ports",
        type=int,
        default=5,
        help="Number of top destination ports per location to display (default: 5)"
    )
    
    parser.add_argument(
        "--protocol",
        action="store_true",
        help="Include protocol distribution analysis"
    )
    
    parser.add_argument(
        "--hourly",
        action="store_true",
        help="Include hourly traffic distribution analysis"
    )
    
    parser.add_argument(
        "--source-ports",
        action="store_true",
        help="Include source ports distribution analysis"
    )
    
    parser.add_argument(
        "--interfaces",
        action="store_true",
        help="Include network interface distribution analysis"
    )
    
    args = parser.parse_args()
    
    # Load data
    try:
        if not os.path.exists(args.input_path):
            print(f"Error: Input file '{args.input_path}' does not exist.", file=sys.stderr)
            return 1
            
        df = pd.read_parquet(args.input_path)
        
        # Run core analysis
        analyze_top_cities(df, args.number, args.ports)
        analyze_top_countries(df, args.number, args.ports)
        
        # Run optional analyses
        if args.protocol:
            analyze_protocol_distribution(df)
            
        if args.hourly:
            analyze_hourly_traffic(df)
            
        if args.source_ports:
            analyze_source_ports(df)
            
        if args.interfaces:
            analyze_interfaces(df)
            
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())