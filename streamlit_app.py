#!/usr/bin/env python3
"""
Streamlit Cloud Provider Scanner Application

A web interface for detecting cloud providers used by websites.
Upload a CSV file with domains and get cloud provider analysis results.
"""

import streamlit as st
import pandas as pd
import asyncio
import io
from typing import List, Dict
import time

# Import our scanner (we'll create a modified version)
from cloud_provider_scanner.scanner_streamlit import CloudProviderDetector

# Page configuration
st.set_page_config(
    page_title="Cloud Provider Scanner",
    page_icon="☁️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for better styling
st.markdown(
    """
<style>
    .main-header {
        text-align: center;
        padding: 2rem 0;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .results-container {
        border: 1px solid #e0e0e0;
        border-radius: 10px;
        padding: 1rem;
        margin-top: 1rem;
    }
    .metric-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #667eea;
    }
</style>
""",
    unsafe_allow_html=True,
)


def main():
    # Header
    st.markdown(
        """
    <div class="main-header">
        <h1>☁️ Cloud Provider Scanner</h1>
        <p>Detect which cloud providers are hosting your domains</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuration")

        # File upload
        uploaded_file = st.file_uploader(
            "Upload CSV file with domains",
            type=["csv"],
            help="Upload a CSV file containing domain names",
        )

        # Column name input
        domain_column = st.text_input(
            "Domain Column Name",
            value="url",
            help="Enter the column name that contains the domain names",
        )

        # Options
        st.subheader("Analysis Options")
        headless_mode = st.checkbox(
            "Headless browser mode",
            value=True,
            help="Run browser in headless mode for faster processing",
        )

        # Sample data option
        if st.button("📊 Use Sample Data"):
            st.session_state.use_sample_data = True

    # Main content area
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("📤 Upload & Analyze")

        # Check if we should use sample data
        if getattr(st.session_state, "use_sample_data", False):
            # Create sample data
            sample_data = pd.DataFrame(
                {
                    "url": [
                        "netflix.com",
                        "spotify.com",
                        "stackoverflow.com",
                        "github.com",
                        "dropbox.com",
                        "shopify.com",
                        "reddit.com",
                        "discord.com",
                        "paypal.com",
                        "linkedin.com",
                    ]
                }
            )
            st.success("✅ Sample data loaded!")
            process_data(sample_data, "url", headless_mode)

        elif uploaded_file is not None:
            try:
                # Read the uploaded CSV
                df = pd.read_csv(uploaded_file)

                # Display file info
                st.success(f"✅ File uploaded successfully! ({len(df)} rows)")

                # Show preview
                with st.expander("📋 Preview uploaded data"):
                    st.dataframe(df.head(10))

                # Check if domain column exists
                if domain_column not in df.columns:
                    st.error(f"❌ Column '{domain_column}' not found in the CSV file.")
                    st.info(f"Available columns: {', '.join(df.columns)}")
                else:
                    # Start analysis button
                    if st.button("🚀 Start Analysis", type="primary"):
                        process_data(df, domain_column, headless_mode)

            except Exception as e:
                st.error(f"❌ Error reading CSV file: {str(e)}")
        else:
            # Instructions when no file is uploaded
            st.info("""
            👆 **Upload a CSV file** to get started or use sample data
            
            **CSV Requirements:**
            - Must contain a column with domain names
            - Domains can be with or without http/https prefix
            - Example: `netflix.com`, `https://spotify.com`
            """)

    with col2:
        st.subheader("ℹ️ About")
        st.markdown("""
        This tool analyzes domains to detect which cloud provider hosts them:
        
        **Supported Providers:**
        - 🟧 AWS (Amazon Web Services)
        - 🔵 GCP (Google Cloud Platform)  
        - 🔷 Azure (Microsoft Azure)
        - 🟠 OVH
        - ⚫ Other providers
        
        **Detection Method:**
        - IP range analysis using official provider IP ranges
        - Focuses on backend hosting (not CDN)
        - High accuracy for major cloud providers
        """)


def process_data(df: pd.DataFrame, domain_column: str, headless_mode: bool):
    """Process the uploaded data and display results."""

    # Extract URLs
    urls = df[domain_column].dropna().tolist()

    if not urls:
        st.error("❌ No valid URLs found in the specified column.")
        return

    st.subheader(f"🔍 Analyzing {len(urls)} domains...")

    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()

    # Results container
    results_container = st.empty()

    # Run analysis
    try:
        # Initialize detector
        detector = CloudProviderDetector(headless=headless_mode)

        # Create async task for analysis
        async def run_analysis():
            results = []
            await detector.load_cloud_ip_ranges()

            for i, url in enumerate(urls):
                status_text.text(f"Analyzing: {url}")
                progress_bar.progress((i + 1) / len(urls))

                result = await detector.analyze_website(url)
                results.append(result)

                # Show intermediate results
                if (i + 1) % 5 == 0 or i == len(urls) - 1:
                    display_results(results, results_container)

            return results

        # Run the async analysis
        if hasattr(asyncio, "run"):
            results = asyncio.run(run_analysis())
        else:
            # For older Python versions
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            results = loop.run_until_complete(run_analysis())
            loop.close()

        # Final results display
        status_text.text("✅ Analysis complete!")
        progress_bar.progress(1.0)

        # Display final results and summary
        display_final_results(results, df, domain_column)

    except Exception as e:
        st.error(f"❌ Error during analysis: {str(e)}")
        st.info(
            "This might be due to network issues or browser compatibility. Try again or contact support."
        )


def display_results(results: List[Dict], container):
    """Display intermediate results."""
    if not results:
        return

    # Convert to DataFrame
    results_df = pd.DataFrame(
        [
            {
                "Domain": result["url"],
                "Cloud Provider": result["primary_cloud_provider"],
                "Confidence": f"{result['confidence_score']}%",
                "IP Addresses": ", ".join(
                    result.get("details", {}).get("main_domain_ips", [])
                ),
                "Status": "Error"
                if result.get("details", {}).get("error")
                else "Success",
            }
            for result in results
        ]
    )

    with container:
        st.dataframe(results_df, use_container_width=True, hide_index=True)


def display_final_results(
    results: List[Dict], original_df: pd.DataFrame, domain_column: str
):
    """Display final comprehensive results."""

    # Convert results to DataFrame
    results_df = pd.DataFrame(
        [
            {
                "Domain": result["url"],
                "Cloud Provider": result["primary_cloud_provider"],
                "Confidence Score": result["confidence_score"],
                "IP Addresses": ", ".join(
                    result.get("details", {}).get("main_domain_ips", [])
                ),
                "Detected Providers": str(
                    result.get("details", {}).get("detected_providers", {})
                ),
                "Status": "Error"
                if result.get("details", {}).get("error")
                else "Success",
                "Error Message": result.get("details", {}).get("error", ""),
            }
            for result in results
        ]
    )

    # Summary statistics
    st.subheader("📊 Analysis Summary")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Analyzed", len(results))

    with col2:
        successful = len([r for r in results if not r.get("details", {}).get("error")])
        st.metric("Successful", successful)

    with col3:
        failed = len(results) - successful
        st.metric("Failed", failed)

    with col4:
        avg_confidence = (
            sum(r["confidence_score"] for r in results) / len(results) if results else 0
        )
        st.metric("Avg Confidence", f"{avg_confidence:.1f}%")

    # Provider distribution
    provider_counts = results_df["Cloud Provider"].value_counts()

    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("☁️ Provider Distribution")
        st.bar_chart(provider_counts)

    with col2:
        st.subheader("📋 Provider Summary")
        for provider, count in provider_counts.items():
            percentage = (count / len(results)) * 100
            st.write(f"**{provider}**: {count} domains ({percentage:.1f}%)")

    # Detailed results table
    st.subheader("📋 Detailed Results")

    # Filter options
    col1, col2, col3 = st.columns(3)

    with col1:
        provider_filter = st.selectbox(
            "Filter by Provider",
            ["All"] + list(provider_counts.index),
            key="provider_filter",
        )

    with col2:
        status_filter = st.selectbox(
            "Filter by Status", ["All", "Success", "Error"], key="status_filter"
        )

    with col3:
        min_confidence = st.slider(
            "Minimum Confidence", 0, 100, 0, key="confidence_filter"
        )

    # Apply filters
    filtered_df = results_df.copy()

    if provider_filter != "All":
        filtered_df = filtered_df[filtered_df["Cloud Provider"] == provider_filter]

    if status_filter != "All":
        filtered_df = filtered_df[filtered_df["Status"] == status_filter]

    filtered_df = filtered_df[filtered_df["Confidence Score"] >= min_confidence]

    # Display filtered results
    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Confidence Score": st.column_config.ProgressColumn(
                "Confidence Score",
                help="Detection confidence percentage",
                min_value=0,
                max_value=100,
                format="%d%%",
            ),
            "Domain": st.column_config.LinkColumn(
                "Domain", help="Click to visit domain", display_text="https://(.*)"
            ),
        },
    )

    # Download results
    st.subheader("💾 Download Results")

    # Create downloadable CSV
    csv_buffer = io.StringIO()
    results_df.to_csv(csv_buffer, index=False)

    st.download_button(
        label="📥 Download Results as CSV",
        data=csv_buffer.getvalue(),
        file_name=f"cloud_provider_analysis_{int(time.time())}.csv",
        mime="text/csv",
    )


if __name__ == "__main__":
    main()
