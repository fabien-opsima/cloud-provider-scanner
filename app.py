#!/usr/bin/env python3
"""
Streamlit Cloud Provider Scanner Application

A web interface for testing cloud provider detection accuracy.
Features:
- Run accuracy tests against labeled data
- Live crawling activity display with complete details
- Real-time summary metrics
- Always-visible history with full details
- Keep-alive mechanism
- Partial matching for multiple cloud providers
"""

import streamlit as st
import pandas as pd
import asyncio
import time
import threading
from typing import Dict, List

# Import our updated detector
from detector import CloudProviderDetector

# Page configuration
st.set_page_config(
    page_title="Cloud Provider Scanner - Test Mode",
    page_icon="🧪",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Custom CSS for clean styling
st.markdown(
    """
<style>
    .main-header {
        text-align: center;
        padding: 1.5rem 0;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 1.5rem;
    }
    .summary-metrics {
        background: #f8f9fa;
        padding: 1.5rem;
        border-radius: 10px;
        margin-bottom: 1.5rem;
        border: 1px solid #e0e0e0;
    }
    .crawl-activity {
        background: #ffffff;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .crawl-completed {
        background: #f8f9fa;
        border-left: 4px solid #28a745;
    }
    .crawl-active {
        background: #fff3cd;
        border-left: 4px solid #ffc107;
        animation: pulse 2s infinite;
    }
    .crawl-error {
        background: #f8d7da;
        border-left: 4px solid #dc3545;
    }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.7; }
        100% { opacity: 1; }
    }
    .activity-snippet {
        font-family: 'Courier New', monospace;
        font-size: 0.85em;
        background: #f1f3f4;
        padding: 0.5rem;
        border-radius: 4px;
        margin: 0.5rem 0;
        max-height: 200px;
        overflow-y: auto;
    }
    .metric-card {
        text-align: center;
        padding: 1rem;
        background: white;
        border-radius: 8px;
        border: 1px solid #e0e0e0;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: bold;
        margin: 0;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #666;
        margin: 0;
    }
    .metric-percent {
        font-size: 1.2rem;
        font-weight: bold;
        margin-top: 0.5rem;
    }
    .sidebar-info {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
    }
    .result-card {
        background: #ffffff;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .result-card-correct {
        border-left: 4px solid #28a745;
        background: #f8fff8;
    }
    .result-card-wrong {
        border-left: 4px solid #dc3545;
        background: #fff8f8;
    }
    .result-card-unknown {
        border-left: 4px solid #17a2b8;
        background: #f8fcff;
    }
    .detail-section {
        background: #f8f9fa;
        padding: 0.75rem;
        border-radius: 6px;
        margin: 0.5rem 0;
        border-left: 3px solid #007bff;
    }
    .subdomain-item {
        background: #e3f2fd;
        padding: 0.5rem;
        margin: 0.25rem 0;
        border-radius: 4px;
        font-family: monospace;
    }
    .api-call-item {
        background: #f3e5f5;
        padding: 0.5rem;
        margin: 0.25rem 0;
        border-radius: 4px;
        font-family: monospace;
    }
    .ip-match-item {
        background: #e8f5e8;
        padding: 0.5rem;
        margin: 0.25rem 0;
        border-radius: 4px;
        font-family: monospace;
    }
    .scrollable-results {
        max-height: 70vh;
        overflow-y: auto;
        padding-right: 10px;
    }
</style>
""",
    unsafe_allow_html=True,
)


def keep_alive():
    """Keep the app alive by updating a hidden element periodically."""
    if "keep_alive_counter" not in st.session_state:
        st.session_state.keep_alive_counter = 0

    # Increment counter every few seconds
    st.session_state.keep_alive_counter += 1

    # Schedule next update
    threading.Timer(30.0, keep_alive).start()


def check_partial_match(
    expected: str, predicted: str, all_providers: List[str] = None
) -> bool:
    """Check if prediction partially matches expected, considering multiple providers."""
    if predicted == expected:
        return True

    # Handle multiple providers in prediction
    if all_providers and expected in all_providers:
        return True

    # Handle cases where prediction contains expected provider
    expected_lower = expected.lower()
    predicted_lower = predicted.lower()

    if expected_lower in predicted_lower:
        return True

    return False


def main():
    # Start keep-alive mechanism
    if "keep_alive_started" not in st.session_state:
        st.session_state.keep_alive_started = True
        keep_alive()

    # Header
    st.markdown(
        """
    <div class="main-header">
        <h1>🧪 Cloud Provider Detection Test</h1>
        <p>Live accuracy testing with complete crawling details</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Main layout
    col1, col2 = st.columns([3, 1])

    with col2:
        # Sidebar info
        st.markdown(
            """
        <div class="sidebar-info">
            <h3>🎯 Detection Methods</h3>
            <p><strong>XHR API Analysis:</strong> Captures backend API calls from app subdomains</p>
            <p><strong>IP Range Matching:</strong> Matches IPs to official cloud provider ranges</p>
            <p><strong>Direct Cloud Calls:</strong> Detects calls to *.amazonaws.com, *.googleapis.com etc.</p>
            <p><strong>Enhanced Subdomain Exploration:</strong> Tests api.domain, app.domain, admin.domain, dashboard.domain, and other common subdomains</p>
        </div>
        """,
            unsafe_allow_html=True,
        )

        # Keep-alive indicator
        if "keep_alive_counter" in st.session_state:
            st.markdown(f"🔄 **Keep-Alive:** {st.session_state.keep_alive_counter}")

        st.markdown("### ✨ Features")
        st.markdown("""
        - **Complete History:** All results always visible
        - **Partial Matching:** AWS+GCP detection counts as AWS match
        - **Full Details:** Every subdomain, API call, and IP shown
        - **Live Updates:** Real-time crawling activity
        - **Auto Keep-Alive:** Server stays active
        """)

        # Test controls
        st.markdown("### 🚀 Test Controls")

        # Check for browser availability
        try:
            from detector import BROWSERS_AVAILABLE

            if BROWSERS_AVAILABLE:
                st.success("🚀 **Full Analysis Mode**\nBrowser features available")
            else:
                st.info("🔍 **IP-Only Mode**\nUsing IP range analysis")
        except:
            pass

        headless_mode = st.checkbox("Headless browser", value=True)

        if st.button(
            "🧪 Start Accuracy Test", type="primary", use_container_width=True
        ):
            st.session_state.test_running = True
            st.rerun()

        if st.button("🛑 Stop Test", use_container_width=True):
            st.session_state.test_running = False
            st.session_state.test_results = []
            st.rerun()

    with col1:
        # Summary metrics at top
        display_summary_metrics()

        # Test results area
        if getattr(st.session_state, "test_running", False):
            run_live_accuracy_test(headless_mode)
        else:
            st.info("👆 Click 'Start Accuracy Test' to begin live testing")


def display_summary_metrics():
    """Display summary metrics at the top."""
    results = getattr(st.session_state, "test_results", [])

    if not results:
        # Empty state
        st.markdown(
            """
        <div class="summary-metrics">
            <div style="display: flex; justify-content: space-around;">
                <div class="metric-card">
                    <div class="metric-value">0</div>
                    <div class="metric-label">Tested</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">0</div>
                    <div class="metric-label">Unknown</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">0</div>
                    <div class="metric-label">Correct</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">0</div>
                    <div class="metric-label">Wrong</div>
                </div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )
        return

    # Calculate metrics
    total = len(results)
    unknown = sum(1 for r in results if r.get("predicted_label") == "Insufficient Data")
    errors = sum(1 for r in results if r.get("predicted_label") == "Error")
    classified = total - unknown - errors
    correct = sum(
        1
        for r in results
        if r.get("correct", False)
        and r.get("predicted_label") not in ["Insufficient Data", "Error"]
    )
    wrong = classified - correct

    # Calculate percentages
    correct_pct = (correct / classified * 100) if classified > 0 else 0
    wrong_pct = (wrong / classified * 100) if classified > 0 else 0
    unknown_pct = (unknown / total * 100) if total > 0 else 0

    # Display metrics
    st.markdown(
        f"""
    <div class="summary-metrics">
        <div style="display: flex; justify-content: space-around;">
            <div class="metric-card">
                <div class="metric-value">{total}</div>
                <div class="metric-label">Tested</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{unknown}</div>
                <div class="metric-label">Unknown</div>
                <div class="metric-percent">{unknown_pct:.1f}%</div>
            </div>
            <div class="metric-card" style="border-left: 4px solid #28a745;">
                <div class="metric-value" style="color: #28a745;">{correct}</div>
                <div class="metric-label">Correct</div>
                <div class="metric-percent" style="color: #28a745;">{correct_pct:.1f}%</div>
            </div>
            <div class="metric-card" style="border-left: 4px solid #dc3545;">
                <div class="metric-value" style="color: #dc3545;">{wrong}</div>
                <div class="metric-label">Wrong</div>
                <div class="metric-percent" style="color: #dc3545;">{wrong_pct:.1f}%</div>
            </div>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )


def run_live_accuracy_test(headless_mode: bool):
    """Run live accuracy test with real-time updates."""

    # Initialize session state
    if "test_results" not in st.session_state:
        st.session_state.test_results = []
    if "current_test_index" not in st.session_state:
        st.session_state.current_test_index = 0
    if "test_data" not in st.session_state:
        # Load and shuffle test data
        test_df = pd.read_csv("data/test.csv")
        st.session_state.test_data = test_df.sample(frac=1).reset_index(drop=True)

    test_data = st.session_state.test_data
    current_index = st.session_state.current_test_index

    # Check if test is complete
    if current_index >= len(test_data):
        st.success("🎉 **Test Complete!** All domains have been analyzed.")
        st.session_state.test_running = False
        return

    # Get current domain
    current_row = test_data.iloc[current_index]
    domain = current_row["domain"]
    true_label = current_row["cloud_provider"]

    # Display current test
    st.markdown(
        f"### 🔍 Currently Testing: `{domain}` ({current_index + 1}/{len(test_data)})"
    )

    # Create containers for live updates
    activity_container = st.container()

    # Display all previous results (most recent first) - always visible
    if st.session_state.test_results:
        st.markdown("### 📋 All Results (Most Recent First)")
        with st.container():
            st.markdown('<div class="scrollable-results">', unsafe_allow_html=True)
            for result in reversed(st.session_state.test_results):  # Show ALL results
                display_detailed_result(result)
            st.markdown("</div>", unsafe_allow_html=True)

    # Run analysis for current domain
    with activity_container:
        run_single_domain_test(domain, true_label, headless_mode)


def run_single_domain_test(domain: str, true_label: str, headless_mode: bool):
    """Run test for a single domain with live activity display."""

    # Create activity display
    activity_placeholder = st.empty()

    with activity_placeholder.container():
        st.markdown(
            f"""
        <div class="crawl-activity crawl-active">
            <h4>🔄 Analyzing: {domain}</h4>
            <div class="activity-snippet">
                <div>🚀 Starting analysis...</div>
                <div>🌐 Initializing browser...</div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    # Initialize detector
    detector = CloudProviderDetector(headless=headless_mode)

    # Activity log
    activity_log = ["🚀 Starting analysis...", "🌐 Initializing browser..."]

    def update_activity(message):
        activity_log.append(message)
        activity_html = "<br>".join(activity_log[-15:])  # Show last 15 lines

        with activity_placeholder.container():
            st.markdown(
                f"""
            <div class="crawl-activity crawl-active">
                <h4>🔄 Analyzing: {domain}</h4>
                <div class="activity-snippet">
                    {activity_html}
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )
        time.sleep(0.1)  # Small delay for visual effect

    try:
        # Start analysis with live updates
        update_activity("🔍 Exploring main domain...")

        # Run analysis (this would need to be modified to provide live updates)
        result = asyncio.run(detector.analyze_website(domain))

        # Simulate live updates based on result data
        backend_data = result.get("details", {}).get("backend_data", {})
        ip_analysis = result.get("ip_analysis", {})

        # Show subdomain discovery
        if backend_data.get("app_subdomains"):
            for subdomain in backend_data["app_subdomains"]:
                update_activity(f"🏢 Found subdomain: {subdomain}")
        else:
            update_activity("🏢 No app subdomains discovered")

        # Show XHR calls
        if backend_data.get("xhr_api_calls"):
            update_activity(
                f"🔗 Discovered {len(backend_data['xhr_api_calls'])} XHR API calls"
            )
            for api in backend_data["xhr_api_calls"][:3]:
                update_activity(f"   📡 {api}")
        else:
            update_activity("🔗 No XHR API calls found")

        # Show IP analysis
        if ip_analysis.get("cloud_ip_matches"):
            update_activity(
                f"☁️ Found {len(ip_analysis['cloud_ip_matches'])} cloud IP matches"
            )
            for match in ip_analysis["cloud_ip_matches"][:2]:
                update_activity(
                    f"   📍 {match['ip']} → {match['provider']} ({match['ip_range']})"
                )
        elif ip_analysis.get("total_ips_checked", 0) > 0:
            update_activity(
                f"🔍 Checked {ip_analysis['total_ips_checked']} IPs - no cloud matches"
            )

        # Show direct cloud calls
        if backend_data.get("cloud_provider_domains"):
            update_activity(
                f"☁️ Found {len(backend_data['cloud_provider_domains'])} direct cloud calls"
            )
            for call in backend_data["cloud_provider_domains"][:2]:
                if isinstance(call, tuple):
                    update_activity(f"   🎯 {call[0]} → {call[1]}")

        predicted_label = result["primary_cloud_provider"]
        confidence = result.get("confidence_score", 0)
        primary_reason = result.get("primary_reason", "No reason provided")

        # Final result with partial matching
        # Get all detected providers from result
        all_detected_providers = []
        if result.get("details", {}).get("provider_scores"):
            all_detected_providers = [
                p
                for p, score in result["details"]["provider_scores"].items()
                if score > 0
            ]

        is_correct = check_partial_match(
            true_label, predicted_label, all_detected_providers
        )
        status_emoji = (
            "✅"
            if is_correct
            else "❌"
            if predicted_label != "Insufficient Data"
            else "🔍"
        )

        update_activity(
            f"🎯 Analysis complete: {predicted_label} ({confidence}% confidence)"
        )
        update_activity(
            f"{status_emoji} Expected: {true_label}, Got: {predicted_label}"
        )

        # Create result object
        test_result = {
            "domain": domain,
            "true_label": true_label,
            "predicted_label": predicted_label,
            "all_detected_providers": all_detected_providers,
            "confidence": confidence,
            "primary_reason": primary_reason,
            "correct": is_correct
            and predicted_label not in ["Insufficient Data", "Error"],
            "activity_log": activity_log.copy(),
            "backend_data": backend_data,
            "ip_analysis": ip_analysis,
            "timestamp": time.time(),
        }

        # Add to results
        st.session_state.test_results.append(test_result)
        st.session_state.current_test_index += 1

        # Show completed state briefly
        status_class = (
            "crawl-completed"
            if is_correct
            else "crawl-error"
            if predicted_label != "Insufficient Data"
            else "crawl-activity"
        )

        with activity_placeholder.container():
            st.markdown(
                f"""
            <div class="crawl-activity {status_class}">
                <h4>{status_emoji} Completed: {domain} → {predicted_label}</h4>
                <div style="padding: 0.5rem; background: white; border-radius: 4px; margin: 0.5rem 0;">
                    <strong>Expected:</strong> {true_label} | <strong>Got:</strong> {predicted_label} | <strong>Confidence:</strong> {confidence}%
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )

        # Auto-advance to next test after brief pause
        time.sleep(2)
        st.rerun()

    except Exception as e:
        update_activity(f"❌ Error: {str(e)}")

        # Add error result
        test_result = {
            "domain": domain,
            "true_label": true_label,
            "predicted_label": "Error",
            "confidence": 0,
            "primary_reason": f"Analysis failed: {str(e)}",
            "correct": False,
            "activity_log": activity_log.copy(),
            "backend_data": {},
            "ip_analysis": {},
            "timestamp": time.time(),
        }

        st.session_state.test_results.append(test_result)
        st.session_state.current_test_index += 1

        time.sleep(2)
        st.rerun()


def display_detailed_result(result: Dict):
    """Display a completed test result with full details always visible."""
    domain = result["domain"]
    true_label = result["true_label"]
    predicted_label = result["predicted_label"]
    all_detected_providers = result.get("all_detected_providers", [])
    confidence = result["confidence"]
    is_correct = result.get("correct", False)
    backend_data = result.get("backend_data", {})
    ip_analysis = result.get("ip_analysis", {})

    # Status styling
    if predicted_label == "Error":
        status_emoji = "❌"
        card_class = "result-card-wrong"
        status_text = "ERROR"
    elif predicted_label == "Insufficient Data":
        status_emoji = "🔍"
        card_class = "result-card-unknown"
        status_text = "INSUFFICIENT DATA"
    elif is_correct:
        status_emoji = "✅"
        card_class = "result-card-correct"
        status_text = "CORRECT"
    else:
        status_emoji = "❌"
        card_class = "result-card-wrong"
        status_text = "WRONG"

    # Create detailed result card
    st.markdown(
        f"""
    <div class="result-card {card_class}">
        <h4>{status_emoji} {domain} → {predicted_label} ({status_text})</h4>
        <div style="margin: 0.5rem 0;">
            <strong>Expected:</strong> {true_label} | 
            <strong>Predicted:</strong> {predicted_label} | 
            <strong>Confidence:</strong> {confidence}%
        </div>
    """,
        unsafe_allow_html=True,
    )

    # Show all detected providers if multiple
    if len(all_detected_providers) > 1:
        providers_text = ", ".join(all_detected_providers)
        st.markdown(f"**🔍 All Detected Providers:** {providers_text}")

    # Show primary reason
    st.markdown(f"**💡 Primary Reason:** {result['primary_reason']}")

    # Detailed sections
    col1, col2 = st.columns([1, 1])

    with col1:
        # Subdomains section
        st.markdown('<div class="detail-section">', unsafe_allow_html=True)
        st.markdown("**🏢 Subdomains Explored:**")
        if backend_data.get("app_subdomains"):
            for subdomain in backend_data["app_subdomains"]:
                st.markdown(
                    f'<div class="subdomain-item">📍 {subdomain}</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.markdown("*No subdomains discovered*")
        st.markdown("</div>", unsafe_allow_html=True)

        # XHR API Calls section
        st.markdown('<div class="detail-section">', unsafe_allow_html=True)
        st.markdown("**🔗 XHR API Calls:**")
        if backend_data.get("xhr_api_calls"):
            for api in backend_data["xhr_api_calls"]:
                st.markdown(
                    f'<div class="api-call-item">📡 {api}</div>', unsafe_allow_html=True
                )
        else:
            st.markdown("*No XHR API calls found*")
        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        # IP Analysis section
        st.markdown('<div class="detail-section">', unsafe_allow_html=True)
        st.markdown("**📍 IP Analysis & Cloud Matches:**")
        if ip_analysis.get("cloud_ip_matches"):
            for match in ip_analysis["cloud_ip_matches"]:
                api_domain = match.get("api_domain", "unknown")
                ip = match.get("ip", "unknown")
                provider = match.get("provider", "unknown")
                ip_range = match.get("ip_range", "unknown")
                st.markdown(
                    f'<div class="ip-match-item">☁️ <strong>{api_domain}</strong><br>IP: {ip} → {provider}<br>Range: {ip_range}</div>',
                    unsafe_allow_html=True,
                )
        elif ip_analysis.get("total_ips_checked", 0) > 0:
            st.markdown(
                f"*Checked {ip_analysis['total_ips_checked']} IPs - no cloud matches*"
            )
        else:
            st.markdown("*No IP analysis performed*")
        st.markdown("</div>", unsafe_allow_html=True)

        # Direct Cloud Calls section
        st.markdown('<div class="detail-section">', unsafe_allow_html=True)
        st.markdown("**☁️ Direct Cloud Provider Calls:**")
        if backend_data.get("cloud_provider_domains"):
            for call in backend_data["cloud_provider_domains"]:
                if isinstance(call, tuple) and len(call) >= 2:
                    domain_call, provider_name = call[0], call[1]
                    service_type = call[2] if len(call) > 2 else ""
                    service_text = f" ({service_type})" if service_type else ""
                    st.markdown(
                        f'<div class="api-call-item">🎯 {domain_call} → {provider_name}{service_text}</div>',
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f'<div class="api-call-item">🎯 {call}</div>',
                        unsafe_allow_html=True,
                    )
        else:
            st.markdown("*No direct cloud provider calls detected*")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("---")


if __name__ == "__main__":
    main()
