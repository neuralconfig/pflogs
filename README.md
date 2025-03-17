# PFLogs Project

ML-enhanced security analysis system for PF-based firewalls that identifies attack patterns, predicts threats, and generates security recommendations.

## Features

- Log parsing for PF firewall logs
- IP Geolocation for attack source identification
- Structured data storage in Parquet format
- Anomaly detection (coming soon)
- Attack classification (coming soon)
- Rule generation (coming soon)
- Attack forecasting (coming soon)
- Visualizations (coming soon)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your_username/pflogs.git
   cd pflogs
   ```

2. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install the package in development mode:
   ```bash
   pip install -e .
   ```

4. Download the MaxMind GeoLite2 City database for IP geolocation:
   
   You'll need to create a free MaxMind account at https://www.maxmind.com/en/geolite2/signup and download the GeoLite2 City database in .mmdb format.
   
   ```bash
   # After downloading, place it in a location accessible to your application:
   mkdir -p data/geo
   # Copy the downloaded database to the data/geo directory
   cp /path/to/downloaded/GeoLite2-City.mmdb data/geo/
   ```

## Usage

### Basic Log Parsing

Parse PF logs and display statistics:

```bash
./parse_logs.py /var/log/pf/hostname/yyyy/mm/dd/pf.log
```

Save parsed logs to a Parquet file:

```bash
./parse_logs.py /var/log/pf/hostname/yyyy/mm/dd/pf.log -o /path/to/output.parquet
```

Limit the number of sample entries displayed:

```bash
./parse_logs.py /var/log/pf/hostname/yyyy/mm/dd/pf.log --sample 10
```

### IP Geolocation

Enrich parsed logs with geolocation data:

```bash
./geo_enrich.py /path/to/parsed_logs.parquet -d /path/to/GeoLite2-City.mmdb
```

Save enriched logs to a Parquet file:

```bash
./geo_enrich.py /path/to/parsed_logs.parquet -d /path/to/GeoLite2-City.mmdb -o /path/to/enriched_logs.parquet
```

Display a summary of geolocation data:

```bash
./geo_enrich.py /path/to/parsed_logs.parquet -d /path/to/GeoLite2-City.mmdb --summary
```

Specify a different IP column to geolocate (for destination IPs):

```bash
./geo_enrich.py /path/to/parsed_logs.parquet -d /path/to/GeoLite2-City.mmdb -c dst_ip
```

### Traffic Analysis

Analyze traffic patterns from enriched logs:

```bash
./scripts/top_cities_ports.py /path/to/enriched_logs.parquet
```

Show top 5 cities and 3 ports per city:

```bash
./scripts/top_cities_ports.py /path/to/enriched_logs.parquet -n 5 -p 3
```

Include additional analysis options:

```bash
./scripts/top_cities_ports.py /path/to/enriched_logs.parquet --protocol --hourly --source-ports --interfaces
```

### Using the Python API

#### Log Parsing

```python
from pflogs.core.pf_parser import parse_logs

# Parse logs and get a DataFrame
df = parse_logs("/var/log/pf/hostname/yyyy/mm/dd/pf.log")

# Do analysis with the DataFrame
print(f"Total log entries: {len(df)}")
print(f"Blocked traffic by protocol: {df['protocol'].value_counts()}")
print(f"Top source IPs: {df['src_ip'].value_counts().head(10)}")

# Save to Parquet file
parse_logs("/var/log/pf/hostname/yyyy/mm/dd/pf.log", "/path/to/output.parquet")
```

#### IP Geolocation

```python
import pandas as pd
from pflogs.core.ip_geo import IPGeolocation, enrich_logs_with_geo

# Load parsed logs
df = pd.read_parquet("/path/to/parsed_logs.parquet")

# Enrich with geolocation data (high-level function)
enriched_df = enrich_logs_with_geo(df, "/path/to/GeoLite2-City.mmdb")

# Alternatively, use the IPGeolocation class directly
geo = IPGeolocation("/path/to/GeoLite2-City.mmdb")
enriched_df = geo.enrich_dataframe(df)

# Create a DataFrame with counts by location
location_counts = geo.create_geodata_series(df)
print("Top source locations:")
print(location_counts.head(10))

# Save enriched data to a Parquet file
enriched_df.to_parquet("/path/to/enriched_logs.parquet")
```

## Development

Run tests:
```bash
pytest
```

Format code:
```bash
black pflogs tests
```

Run linter:
```bash
flake8 pflogs tests
```

Run type checker:
```bash
mypy pflogs
```

## License

[MIT](LICENSE)
