# Cloud Provider Scanner - Focused Version

A precise tool that detects which cloud providers are used by websites by analyzing multiple signals with a focus on backend hosting infrastructure.

## Features

- **IP Range Analysis**: Primary detection method using official cloud provider IP ranges
- **Backend Endpoint Discovery**: Analyzes network requests to discover additional hosting infrastructure
- **Security Headers Analysis**: Detects cloud-specific headers
- **Asset Analysis**: Identifies cloud storage and CDN usage
- **Accuracy Testing**: Built-in testing framework with metrics
- **Streamlit Web Interface**: Easy-to-use web application
- **Robust Deployment**: Works with or without browser dependencies

## Supported Providers

- 🟧 **AWS** (Amazon Web Services)
- 🔵 **GCP** (Google Cloud Platform)  
- 🔷 **Azure** (Microsoft Azure)
- ⚫ **Other** (All other providers)

## Detection Methods & Scoring

The tool uses a weighted scoring system with intelligent fallback:

### Full Analysis Mode (with browsers)
1. **Primary Domain IP Range Analysis** (60 points) - Strongest signal
2. **Backend Endpoint IP Analysis** (40 points) - Secondary signal
3. **Security Headers Analysis** (30 points) - Supporting evidence
4. **Cloud Assets & CDN Analysis** (60 points max) - Supporting evidence

### IP-Only Mode (without browsers)
1. **Primary Domain IP Range Analysis** (60 points) - Most reliable method
2. **Security Headers Analysis** (30 points) - HTTP headers only

**Total possible score**: 190 points (full mode) / 90 points (IP-only mode)  
**Minimum confidence threshold**: 15% to assign a provider

## Installation

### Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Install Playwright browsers (for full functionality):
```bash
playwright install chromium
```

Or run the browser installation script:
```bash
python install_browsers.py
```

### Streamlit Cloud Deployment

The app is configured for seamless Streamlit Cloud deployment:

- **System dependencies**: Automatically installed via `packages.txt`
- **Browser installation**: Automatic during app startup
- **Graceful fallback**: Works in IP-only mode if browsers fail
- **No manual setup required**

## Usage

### Streamlit Web Interface

Run the web application:
```bash
streamlit run app.py
```

The interface automatically detects available features:

- 🚀 **Full Analysis Mode**: When browsers are available
- 🔍 **IP-Only Analysis Mode**: Reliable fallback mode

#### 📊 Analyze Domains
- Upload CSV files with domain names
- Use sample data for testing
- Download results as CSV
- Real-time progress tracking with live results

#### 🧪 Run Accuracy Test
- Test against labeled data in `data/test.csv`
- Get accuracy, precision, and recall metrics
- Live test results with correct/incorrect indicators
- Detailed per-class performance
- Download test results

### Command Line Usage

```python
import asyncio
from detector import CloudProviderDetector

async def analyze_domain():
    detector = CloudProviderDetector()
    result = await detector.analyze_website("example.com")
    print(f"Provider: {result['primary_cloud_provider']}")
    print(f"Confidence: {result['confidence_score']:.1f}%")

asyncio.run(analyze_domain())
```

### Accuracy Testing

```python
from detector import CloudProviderDetector

detector = CloudProviderDetector()
results = detector.run_test("data/test.csv")
print(f"Accuracy: {results['accuracy']:.3f}")
print(f"Precision: {results['precision']:.3f}")
print(f"Recall: {results['recall']:.3f}")
```

## Data Files

The tool uses local IP range files for maximum reliability:

- `data/aws_ranges.json` - AWS IP ranges
- `data/gcp_ranges.json` - Google Cloud IP ranges  
- `data/azure_ranges.json` - Microsoft Azure IP ranges
- `data/test.csv` - Labeled test data for accuracy evaluation

## CSV File Format

For domain analysis, your CSV file should contain:

```csv
domain
netflix.com
spotify.com
github.com
```

The column name can be customized in the web interface.

## Test Data Format

The test data should follow this format:

```csv
record_id,domain,name,cloud_provider
1,example.com,Example Company,AWS
2,test.com,Test Company,GCP
```

## Configuration

### Detector Options

```python
detector = CloudProviderDetector(
    headless=True  # Run browser in headless mode
)
```

### Analysis Focus

This tool focuses on **backend hosting infrastructure**, not CDN or delivery layers. It's optimized for:

- Accurate detection of actual hosting providers
- Robust IP range matching
- Minimal false positives
- High confidence scoring

## Performance

- **IP Range Loading**: ~75,000 ranges loaded in <1 second
- **Domain Analysis**: ~10-30 seconds per domain (depending on complexity)
- **Accuracy**: Optimized for precision over recall

## Limitations

- Only detects AWS, GCP, and Azure (other providers marked as "Other")
- Requires internet connectivity for domain resolution and web scraping
- Some domains may use multiple providers (reports primary only)
- CDN usage may not reflect backend hosting

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License. 