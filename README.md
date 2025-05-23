# Cloud Provider Scanner

A comprehensive Python tool that detects which cloud providers are used by websites through multiple analysis methods with high accuracy.

## Features

- **5 Detection Methods** with confidence scoring
- **3 Major Cloud Providers** supported: AWS, GCP, Azure
- **High Accuracy** with multi-signal detection
- **JavaScript Support** via Playwright with requests fallback
- **Batch Processing** from CSV input to CSV output

## Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium
```

### Usage

```bash
# Create test dataset
python scanner.py --create-test-data

# Analyze websites
python scanner.py test_websites.csv

# Analyze custom websites with output file
python scanner.py input.csv --output results.csv

# Debug mode (watch browser automation)
python scanner.py input.csv --visible
```

## Input Format

Create a CSV file with a `url` column:

```csv
url
amazon.com
google.com
microsoft.com
netflix.com
github.com
```

## Output Format

Results are saved to CSV with these columns:

- `url` - Website analyzed
- `primary_cloud_provider` - Main detected provider
- `confidence_score` - Numerical confidence score
- `main_domain_ips` - IP addresses resolved
- `error` - Any errors encountered

## Detection Methods

The tool uses 5 sophisticated detection methods:

1. **IP Range Matching** (40 pts) - Checks if IPs belong to known cloud ranges
2. **SSL Certificate Analysis** (35 pts) - Examines certificate subjects and issuers
3. **Security Headers Analysis** (25 pts) - Provider-specific header patterns
4. **DNS Records Analysis** (30 pts) - Checks MX, TXT, NS, CNAME records
5. **Website Content Analysis** (65 pts) - Scans for cloud provider keywords, SDKs, and assets

## Supported Cloud Providers

- **AWS** (Amazon Web Services) - EC2, S3, CloudFront, Lambda, etc.
- **GCP** (Google Cloud Platform) - Firebase, App Engine, Cloud Storage, etc.
- **Azure** (Microsoft) - App Service, Azure Edge, Azure Storage, etc.

## Command Line Options

```bash
python scanner.py [CSV_FILE] [OPTIONS]

Options:
  --output, -o FILE     Output CSV file (default: results.csv)
  --visible             Run browser in visible mode for debugging
  --create-test-data    Create test dataset with known websites
```

## Streamlit Web Interface

Run the web interface:

```bash
streamlit run streamlit_app.py
```

Features:
- Upload CSV files for bulk analysis
- Real-time progress tracking
- Download results as CSV
- Visual confidence scoring
- Detailed detection method breakdown 