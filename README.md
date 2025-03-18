# PFLogs Project

ML-enhanced security analysis system for PF-based firewalls that identifies attack patterns, predicts threats, and generates security recommendations.

## Features

- Log parsing for PF firewall logs
- IP Geolocation and ASN lookup for attack source identification
- Threat intelligence integration with multiple sources
- Compressed log file support (.gz)
- Efficient memory usage for processing large datasets
- Multi-threaded processing for better performance
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

4. Download the MaxMind GeoLite2 databases for IP geolocation and ASN information:
   
   You'll need to create a free MaxMind account at https://www.maxmind.com/en/geolite2/signup and download both the GeoLite2 City and GeoLite2 ASN databases in .mmdb format.
   
   ```bash
   # After downloading, place them in a location accessible to your application:
   mkdir -p data/{geo,threat}
   # Copy the downloaded databases to the data/geo directory
   cp /path/to/downloaded/GeoLite2-City.mmdb data/geo/
   cp /path/to/downloaded/GeoLite2-ASN.mmdb data/geo/
   ```

5. Update threat intelligence data:
   ```bash
   python3 -m scripts.update_threat_intel -o data/threat
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

### Enrichment

#### Geo & ASN Enrichment

Enrich parsed logs with geolocation and ASN data:

```bash
python3 -m scripts.geo_enrich data/output.parquet -g data/geo/GeoLite2-City.mmdb -a data/geo/GeoLite2-ASN.mmdb -o data/enriched.parquet
```

#### Threat Intelligence Enrichment

Enrich logs with threat intelligence data:

```bash
python3 -m scripts.threat_enrich data/output.parquet -t data/threat -o data/enriched.parquet
```

#### Combined Enrichment (Geo, ASN, and Threat Intel)

```bash
python3 -m scripts.enrich data/output.parquet -g data/geo/GeoLite2-City.mmdb -a data/geo/GeoLite2-ASN.mmdb -t data/threat -o data/enriched.parquet
```

Display a summary of enrichment data:

```bash
python3 -m scripts.enrich data/output.parquet -g data/geo/GeoLite2-City.mmdb -a data/geo/GeoLite2-ASN.mmdb -t data/threat --sample 0
```

Update threat intelligence feeds:

```bash
python3 -m scripts.update_threat_intel
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

#### Data Enrichment

```python
import pandas as pd
from pflogs.core.ip_geo import IPGeolocation, enrich_with_geolocation
from pflogs.core.threat_intel import ThreatIntelligence, enrich_with_threat_intel

# Load parsed logs
df = pd.read_parquet("/path/to/parsed_logs.parquet")

# Geo and ASN Enrichment
geo = IPGeolocation(
    geo_db_path="/path/to/GeoLite2-City.mmdb",
    asn_db_path="/path/to/GeoLite2-ASN.mmdb"
)
geo_enriched_df = enrich_with_geolocation(
    df, 
    geo_db_path="/path/to/GeoLite2-City.mmdb",
    asn_db_path="/path/to/GeoLite2-ASN.mmdb"
)

# Threat Intelligence Enrichment
threat_enriched_df = enrich_with_threat_intel(
    geo_enriched_df,
    threat_intel_dir="/path/to/threat"
)

# Alternatively, use the classes directly
geo = IPGeolocation(
    geo_db_path="/path/to/GeoLite2-City.mmdb",
    asn_db_path="/path/to/GeoLite2-ASN.mmdb"
)
geo_enriched_df = geo.enrich_dataframe(df)

ti = ThreatIntelligence(data_dir="/path/to/threat")
fully_enriched_df = ti.enrich_dataframe(geo_enriched_df)

# Save enriched data to a Parquet file
fully_enriched_df.to_parquet("/path/to/enriched_logs.parquet")

# Get threat intelligence statistics
malicious_count = fully_enriched_df['threat_is_malicious'].sum()
print(f"Found {malicious_count} malicious IPs ({malicious_count/len(fully_enriched_df)*100:.1f}%)")
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
