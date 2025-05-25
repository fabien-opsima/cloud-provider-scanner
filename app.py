#!/usr/bin/env python3
"""
Streamlit Cloud Provider Scanner Application

A web interface for testing cloud provider detection accuracy.
Features:
- Run accuracy tests against labeled data
- Live crawling activity display
- Real-time summary metrics
- Collapsible detailed logs
"""

import streamlit as st
import pandas as pd
import asyncio
import time
from typing import Dict

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
</style>
""",
    unsafe_allow_html=True,
)


def main():
    # Header
    st.markdown(
        """
    <div class="main-header">
        <h1>🧪 Cloud Provider Detection Test</h1>
        <p>Live accuracy testing with real-time crawling activity</p>
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
        </div>
        """,
            unsafe_allow_html=True,
        )

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

    # Display previous results (most recent first)
    if st.session_state.test_results:
        st.markdown("### 📋 Previous Results")
        for result in reversed(st.session_state.test_results[-10:]):  # Show last 10
            display_completed_result(result)

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

        # Final result
        is_correct = predicted_label == true_label
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


def display_completed_result(result: Dict):
    """Display a completed test result in collapsed form."""
    domain = result["domain"]
    true_label = result["true_label"]
    predicted_label = result["predicted_label"]
    confidence = result["confidence"]
    is_correct = result.get("correct", False)

    # Status styling
    if predicted_label == "Error":
        status_emoji = "❌"
        status_class = "crawl-error"
        status_text = "ERROR"
    elif predicted_label == "Insufficient Data":
        status_emoji = "🔍"
        status_class = "crawl-activity"
        status_text = "INSUFFICIENT DATA"
    elif is_correct:
        status_emoji = "✅"
        status_class = "crawl-completed"
        status_text = "CORRECT"
    else:
        status_emoji = "❌"
        status_class = "crawl-error"
        status_text = "WRONG"

    # Expandable result
    with st.expander(
        f"{status_emoji} {domain} → {predicted_label} ({status_text})", expanded=False
    ):
        col1, col2 = st.columns([2, 1])

        with col1:
            st.write(f"**Expected:** {true_label}")
            st.write(f"**Predicted:** {predicted_label}")
            st.write(f"**Confidence:** {confidence}%")
            st.write(f"**Reason:** {result['primary_reason']}")

            # Show activity log
            if result.get("activity_log"):
                st.write("**Activity Log:**")
                log_text = "\n".join(result["activity_log"])
                st.code(log_text, language="text")

        with col2:
            # Quick stats
            backend_data = result.get("backend_data", {})
            ip_analysis = result.get("ip_analysis", {})

            st.metric("Subdomains", len(backend_data.get("app_subdomains", [])))
            st.metric("XHR Calls", len(backend_data.get("xhr_api_calls", [])))
            st.metric("Cloud IPs", ip_analysis.get("cloud_matches", 0))
            st.metric(
                "Direct Calls", len(backend_data.get("cloud_provider_domains", []))
            )


if __name__ == "__main__":
    main()
