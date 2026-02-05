"""
AI Gateway POC - Demo Test Script

Run this script to test all detection scenarios from command line.
Make sure the server is running first: python main.py
"""

import httpx
import json
import time

API_URL = "http://localhost:8000"

# Test scenarios
TEST_CASES = [
    {
        "name": "Clean Query (Should PASS)",
        "content": "What is machine learning? Explain in simple terms.",
        "expected": "ALLOWED"
    },
    {
        "name": "Aadhaar Number Detection",
        "content": "My Aadhaar number is 2345 6789 0123, can you verify it?",
        "expected": "BLOCKED/LOCAL_LLM"
    },
    {
        "name": "PAN Card Detection",
        "content": "Please process PAN: ABCDE1234F for tax calculation",
        "expected": "BLOCKED/LOCAL_LLM"
    },
    {
        "name": "Phone Number Detection",
        "content": "Call me at +91 98765 43210 for details",
        "expected": "BLOCKED/LOCAL_LLM"
    },
    {
        "name": "Credit Card Detection",
        "content": "My card number is 4111111111111111",
        "expected": "BLOCKED/LOCAL_LLM"
    },
    {
        "name": "API Key Detection",
        "content": 'Here is my config: api_key = "sk-abc123xyz456789012345678901234567890"',
        "expected": "BLOCKED/LOCAL_LLM"
    },
    {
        "name": "AWS Access Key Detection",
        "content": "Use this: AKIAIOSFODNN7EXAMPLE",
        "expected": "BLOCKED/LOCAL_LLM"
    },
    {
        "name": "Database Connection String",
        "content": "Connect using: mysql://admin:password123@db.company.com/production",
        "expected": "BLOCKED/LOCAL_LLM"
    },
    {
        "name": "Private Key Detection",
        "content": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg...",
        "expected": "BLOCKED/LOCAL_LLM"
    },
    {
        "name": "Blocked Keyword - Confidential",
        "content": "This is a confidential document about our strategy",
        "expected": "BLOCKED/LOCAL_LLM"
    },
    {
        "name": "Blocked Keyword - Trading Algorithm",
        "content": "Here is our trading algorithm implementation",
        "expected": "BLOCKED/LOCAL_LLM"
    },
    {
        "name": "Blocked Keyword - UPSI",
        "content": "This contains UPSI about upcoming merger",
        "expected": "BLOCKED/LOCAL_LLM"
    },
    {
        "name": "Email Detection (Medium Severity)",
        "content": "Send it to john.doe@company.internal.com",
        "expected": "BLOCKED/LOCAL_LLM"
    },
    {
        "name": "IFSC Code Detection",
        "content": "Transfer to IFSC: SBIN0001234",
        "expected": "May pass (MEDIUM severity)"
    },
    {
        "name": "Demat Account Detection",
        "content": "My demat account is IN12345678901234",
        "expected": "BLOCKED/LOCAL_LLM"
    },
    {
        "name": "Multiple Detections",
        "content": "My Aadhaar is 2345 6789 0123 and PAN is ABCDE1234F. This is confidential.",
        "expected": "BLOCKED/LOCAL_LLM (multiple)"
    },
]


def print_header(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def print_result(test_name, response, expected):
    status = response.get("status", "ERROR")

    # Color coding (ANSI)
    if status == "ALLOWED":
        color = "\033[92m"  # Green
    elif status == "BLOCKED":
        color = "\033[91m"  # Red
    elif status == "ROUTED_TO_LOCAL_LLM":
        color = "\033[95m"  # Purple
    else:
        color = "\033[93m"  # Yellow

    reset = "\033[0m"

    print(f"\n{'─' * 50}")
    print(f"Test: {test_name}")
    print(f"Status: {color}{status}{reset}")
    print(f"Expected: {expected}")

    if response.get("detections"):
        print(f"Detections: {len(response['detections'])}")
        for d in response["detections"][:3]:
            print(f"  - {d.get('type')}: {d.get('description')}")

    if response.get("error"):
        print(f"Error: {response['error']}")


def test_scan_only(content):
    """Test scanner without calling external API"""
    response = httpx.post(
        f"{API_URL}/api/scan",
        json={"content": content},
        timeout=30
    )
    return response.json()


def test_chat(content, user_id="demo_user"):
    """Test full chat endpoint"""
    response = httpx.post(
        f"{API_URL}/api/chat",
        json={
            "messages": [{"role": "user", "content": content}],
            "user_id": user_id
        },
        timeout=60
    )

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 403:
        return response.json()
    elif response.status_code == 429:
        return {"status": "RATE_LIMITED", "error": response.json().get("error")}
    else:
        return {"status": "ERROR", "error": f"HTTP {response.status_code}"}


def run_scan_tests():
    """Run scanner tests (no API calls)"""
    print_header("SCANNER TESTS (No API Calls)")

    for test in TEST_CASES:
        result = test_scan_only(test["content"])
        scan = result.get("scan_result", {})

        print(f"\n{'─' * 50}")
        print(f"Test: {test['name']}")
        print(f"Is Sensitive: {'Yes' if scan.get('is_sensitive') else 'No'}")
        print(f"Would Route To: {result.get('would_route_to')}")
        print(f"Severity: {scan.get('severity')}")

        if scan.get("detections"):
            print(f"Detections ({len(scan['detections'])}):")
            for d in scan["detections"]:
                print(f"  - [{d.get('severity')}] {d.get('type')}: {d.get('description')}")


def run_chat_tests():
    """Run full chat tests (requires API key)"""
    print_header("CHAT TESTS (With API Calls)")

    for i, test in enumerate(TEST_CASES):
        print(f"\n[{i+1}/{len(TEST_CASES)}] Testing: {test['name']}")

        result = test_chat(test["content"])
        print_result(test["name"], result, test["expected"])

        # Small delay to avoid rate limiting
        time.sleep(0.5)


def check_health():
    """Check if server is running"""
    try:
        response = httpx.get(f"{API_URL}/api/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"\n✓ Server is running")
            print(f"  Active Provider: {data.get('config', {}).get('active_provider')}")
            print(f"  Local LLM Mode: {data.get('config', {}).get('local_llm_mode')}")
            return True
    except:
        pass

    print("\n✗ Server is not running!")
    print("  Start it with: python main.py")
    return False


def get_stats():
    """Get current statistics"""
    response = httpx.get(f"{API_URL}/api/logs/stats", timeout=10)
    if response.status_code == 200:
        stats = response.json()
        print_header("CURRENT STATISTICS")
        print(f"Total Requests: {stats.get('total_requests', 0)}")
        print(f"Allowed: {stats.get('by_action', {}).get('ALLOWED', 0)}")
        print(f"Blocked: {stats.get('by_action', {}).get('BLOCKED', 0)}")
        print(f"Local LLM: {stats.get('by_action', {}).get('ROUTED_LOCAL_LLM', 0)}")


def main():
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║           AI Gateway POC - Demo Test Script              ║
    ║                  Motilal Oswal                           ║
    ╚══════════════════════════════════════════════════════════╝
    """)

    if not check_health():
        return

    print("\nSelect test mode:")
    print("1. Scanner Only (no API calls)")
    print("2. Full Chat Tests (requires API key)")
    print("3. View Statistics")
    print("4. Run All")

    choice = input("\nEnter choice (1-4): ").strip()

    if choice == "1":
        run_scan_tests()
    elif choice == "2":
        run_chat_tests()
    elif choice == "3":
        get_stats()
    elif choice == "4":
        run_scan_tests()
        input("\nPress Enter to continue with chat tests...")
        run_chat_tests()
        get_stats()
    else:
        print("Invalid choice")

    print("\n" + "=" * 60)
    print("  Demo Complete!")
    print("  Open http://localhost:8000 to view the dashboard")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
