#!/usr/bin/env python3
"""
Browser installation script for Streamlit Cloud deployment
"""

import subprocess
import sys


def install_playwright_browsers():
    """Install Playwright browsers with proper error handling."""
    print("🚀 Installing Playwright browsers for Streamlit Cloud...")

    try:
        # Install browsers
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes timeout
        )

        if result.returncode == 0:
            print("✅ Browser installation successful!")
            print(result.stdout)

            # Test the installation
            test_result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from playwright.sync_api import sync_playwright; p = sync_playwright(); browser = p.start().chromium.launch(headless=True); browser.close()",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if test_result.returncode == 0:
                print("✅ Browser test successful!")
                return True
            else:
                print(f"❌ Browser test failed: {test_result.stderr}")
                return False

        else:
            print(f"❌ Browser installation failed: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print("❌ Browser installation timed out")
        return False
    except Exception as e:
        print(f"❌ Browser installation error: {e}")
        return False


if __name__ == "__main__":
    success = install_playwright_browsers()
    sys.exit(0 if success else 1)
