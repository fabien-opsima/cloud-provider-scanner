# Cloud Provider Scanner - Streamlit App

A web-based tool for detecting which cloud providers are hosting your domains. Upload a CSV file with domain names and get detailed analysis results with an intuitive interface.

## Features

- 🔍 **Accurate Detection**: Uses official IP ranges from AWS, GCP, Azure, and OVH
- 📊 **Interactive Results**: Sortable, filterable tables with progress bars
- 📈 **Visual Analytics**: Charts showing provider distribution
- 💾 **Export Results**: Download analysis results as CSV
- 🚀 **Easy Upload**: Simple CSV file upload with column name configuration
- 📱 **Responsive Design**: Works on desktop and mobile devices

## Quick Start

### Local Development

1. **Clone and navigate to the directory:**
   ```bash
   cd cloud-provider-scanner
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Playwright browsers:**
   ```bash
   playwright install chromium
   ```

4. **Run the Streamlit app:**
   ```bash
   streamlit run streamlit_app.py
   ```

5. **Open your browser** to `http://localhost:8501`

### Using the App

1. **Upload CSV File**: Click "Upload CSV file with domains" and select your file
2. **Configure Column**: Enter the column name containing your domain names (default: "url")
3. **Start Analysis**: Click "🚀 Start Analysis" to begin processing
4. **View Results**: See real-time progress and detailed results
5. **Download**: Export your results as CSV for further analysis

## CSV File Format

Your CSV file should contain a column with domain names. Example:

```csv
url,company_name
netflix.com,Netflix
spotify.com,Spotify
github.com,GitHub
```

Domains can be with or without protocol:
- ✅ `netflix.com`
- ✅ `https://netflix.com`
- ✅ `http://example.org`

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

## Supported Cloud Providers

- **AWS** (Amazon Web Services) - 🟧
- **GCP** (Google Cloud Platform) - 🔵  
- **Azure** (Microsoft Azure) - 🔷
- **OVH** - 🟠
- **Other** providers - ⚫

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