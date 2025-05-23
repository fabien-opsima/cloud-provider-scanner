# Cloud Provider Scanner - Streamlit App

A web-based cloud provider detection tool that analyzes websites to determine which cloud providers host them.

## Features

- **Multi-Signal Detection**: Uses 5 different analysis methods
- **Major Cloud Providers**: AWS, GCP, Azure
- **Web Interface**: Easy-to-use Streamlit interface
- **Batch Processing**: Upload CSV files for bulk analysis
- **Real-time Progress**: See analysis progress in real-time
- **Confidence Scoring**: Weighted confidence scores for each detection

## Detection Methods

1. **IP Range Analysis** (40 points) - Most reliable signal
2. **SSL Certificate Analysis** (35 points) - Certificate issuer detection
3. **Security Headers Analysis** (25 points) - Provider-specific headers
4. **DNS Records Analysis** (30 points) - CNAME and MX record patterns
5. **Website Content Analysis** (65 points) - Keywords, JS libraries, assets

## Quick Start

### Local Development

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   playwright install chromium
   ```

2. **Run the App**:
   ```bash
   streamlit run streamlit_app.py
   ```

3. **Open your browser** to `http://localhost:8501`

### Using the App

1. **Upload a CSV file** with a column containing domain names
2. **Select the domain column** from your CSV
3. **Click "Start Analysis"** to begin detection
4. **Download results** as a CSV file when complete

## CSV Format

Your input CSV should have domains in one column:

```csv
domain
netflix.com
github.com
microsoft.com
firebase.google.com
```

## Supported Cloud Providers

- **AWS** (Amazon Web Services) - 🟧
- **GCP** (Google Cloud Platform) - 🔵  
- **Azure** (Microsoft Azure) - 🔷
- **Other** providers - ⚫

## Configuration

The app automatically detects cloud providers using official IP ranges and signatures.

## Deployment Options

### Streamlit Cloud (Recommended)

1. **Push to GitHub**: Upload your code to a GitHub repository
2. **Connect Streamlit Cloud**: Go to [share.streamlit.io](https://share.streamlit.io)
3. **Deploy**: Connect your GitHub repo and deploy
4. **Configure**: Streamlit Cloud will automatically use `requirements.txt` and `packages.txt`

### Heroku

1. **Create Heroku app:**
   ```bash
   heroku create your-app-name
   ```

2. **Add buildpacks:**
   ```bash
   heroku buildpacks:add --index 1 heroku/python
   heroku buildpacks:add --index 2 https://github.com/heroku/heroku-buildpack-apt
   ```

3. **Create Aptfile:**
   ```
   chromium-browser
   chromium-chromedriver
   ```

4. **Create Procfile:**
   ```
   web: streamlit run streamlit_app.py --server.port=$PORT --server.address=0.0.0.0
   ```

5. **Deploy:**
   ```bash
   git push heroku main
   ```

### Docker

1. **Create Dockerfile:**
   ```dockerfile
   FROM python:3.9-slim

   WORKDIR /app

   # Install system dependencies
   RUN apt-get update && apt-get install -y \
       chromium \
       chromium-driver \
       && rm -rf /var/lib/apt/lists/*

   # Install Python dependencies
   COPY requirements.txt .
   RUN pip install -r requirements.txt

   # Install Playwright
   RUN playwright install chromium

   # Copy app files
   COPY . .

   EXPOSE 8501

   CMD ["streamlit", "run", "streamlit_app.py", "--server.port=8501", "--server.address=0.0.0.0"]
   ```

2. **Build and run:**
   ```bash
   docker build -t cloud-provider-scanner .
   docker run -p 8501:8501 cloud-provider-scanner
   ```

## How It Works

1. **IP Resolution**: Resolves domain names to IP addresses
2. **Range Matching**: Compares IPs against official cloud provider IP ranges
3. **Provider Detection**: Identifies the most likely cloud provider
4. **Confidence Scoring**: Provides confidence scores based on IP matches

## Configuration

### Environment Variables

- `STREAMLIT_SERVER_PORT`: Port to run the app (default: 8501)
- `STREAMLIT_SERVER_ADDRESS`: Address to bind (default: 0.0.0.0)

### Streamlit Configuration

The app includes a `.streamlit/config.toml` file with optimized settings for deployment.

## Troubleshooting

### Common Issues

1. **Playwright Installation**: If you get browser errors, run:
   ```bash
   playwright install chromium
   ```

2. **Memory Issues**: For large CSV files, consider processing in smaller batches

3. **Network Timeouts**: The app uses shorter timeouts for better user experience

4. **CSV Format**: Ensure your CSV has proper headers and the domain column exists

### Performance Tips

- Use headless mode (enabled by default) for faster processing
- Process smaller batches for better responsiveness
- Ensure stable internet connection for IP range downloads

## API Reference

### CloudProviderDetector

Main class for cloud provider detection:

```python
from cloud_provider_scanner.scanner_streamlit import CloudProviderDetector

detector = CloudProviderDetector(headless=True)
await detector.load_cloud_ip_ranges()
result = await detector.analyze_website("example.com")
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Create an issue on GitHub
- Check the troubleshooting section
- Review the configuration options 