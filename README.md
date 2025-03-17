# PFLogs Project

ML-enhanced security analysis system for PF-based firewalls that identifies attack patterns, predicts threats, and generates security recommendations.

## Features

- Log parsing for PF firewall logs
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

### Using the Python API

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
