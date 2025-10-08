#Filter -one for URLs and one for IP addresses
from malicious_ip_filter import MaliciousIPFilter 
from malicious_url_filter import MaliciousURLFilter 
from search_indexer import run_crawler_simulation

# Helper functions to quickly load the malicious URL/IP data from files
from helper_functions import load_malicious_urls_from_csv,load_ips_from_text_file

# --- Added imports for validation & canonicalization ---
import re
import ipaddress
from urllib.parse import urlparse, urlunparse, unquote


def canonicalize_url(raw_url: str) -> str:
    """
    Canonicalize URL for consistent matching:
      - Ensure scheme present (if missing, treat as invalid)
      - Lowercase scheme and hostname
      - Remove default ports (80 for http, 443 for https)
      - Percent-decode the path/query where appropriate
      - Strip fragments

    Returns canonicalized URL string on success, or an empty string on failure.
    """
    try:
        parsed = urlparse(raw_url)
    except Exception:
        return ""

    # require explicit scheme and network location
    if not parsed.scheme or not parsed.netloc:
        return ""

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        # we don't accept javascript:, data:, ftp:, etc. for canonicalization here
        return ""

    # Lowercase hostname (netloc may include credentials or port)
    netloc = parsed.netloc

    # Reject credentials embedded in URL (user:pass@host)
    if "@" in netloc:
        return ""

    # Separate hostname and optional port
    host = netloc
    port = None
    if ":" in netloc:
        host_part, port_part = netloc.rsplit(":", 1)
        # If port_part isn't numeric, treat whole netloc as hostname (IPv6 cases will have brackets)
        if port_part.isdigit():
            host = host_part
            port = int(port_part)

    host = host.lower()

    # Remove default ports
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    if port:
        netloc = f"{host}:{port}"
    else:
        netloc = host

    # percent-decode path and query for canonical comparison
    path = unquote(parsed.path or "")
    query = unquote(parsed.query or "")

    # strip fragment (parsed.fragment)
    fragment = ""

    canonical = urlunparse((scheme, netloc, path or '/', '', query, fragment))
    return canonical


def is_valid_url_format(raw_url: str) -> bool:
    """
    Lightweight syntactic checks for URL before canonicalization:
      - not empty
      - allowed scheme (http/https)
      - no suspicious patterns like javascript:, data:, embedded credentials, or obvious binary downloads
    """
    if not raw_url or not raw_url.strip():
        return False

    raw_url = raw_url.strip()

    # quick reject of clearly malicious schemes
    if re.search(r"^\s*(javascript:|data:|vbscript:)", raw_url, re.IGNORECASE):
        return False

    # tiny sanity: must contain :// for a scheme-based URL
    if "://" not in raw_url:
        return False

    # Reject common suspicious substrings
    suspicious_substrings = ["@", "base64", "\\.exe", "\\.zip", "\\.js"]
    for s in suspicious_substrings:
        if re.search(s, raw_url, re.IGNORECASE):
            # note: this is a conservative check — adjust if you want fewer false positives
            return False

    # Try parsing
    parsed = urlparse(raw_url)
    if not parsed.scheme or not parsed.netloc:
        return False

    if parsed.scheme.lower() not in ("http", "https"):
        return False

    return True


def is_valid_ip_format(ip_str: str) -> bool:
    """
    Validate IPv4 or IPv6 address using ipaddress module. Returns True if valid.
    """
    try:
        # ip_address will raise ValueError for invalid addresses
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def run_interactive_checker():
    """
    Main function to run the interactive malicious URL checker with real data.
    """
    #  Step 1: Load the data
    # The filename should match what you saved the CSV as.
    URL_DATASET_FILENAME = 'datasets/malicious_urls.csv'
    IP_DATASET_FILENAME = 'datasets/bad_ip_dataset.txt'
    known_malicious_urls = load_malicious_urls_from_csv(URL_DATASET_FILENAME)
    known_malicious_ips = load_ips_from_text_file(IP_DATASET_FILENAME)

    if known_malicious_urls is None:
        return 
    # Count how many bad URLs and IPs we have
    EXPECTED_URLS_IN_BLACKLIST = len(known_malicious_urls)
    EXPECTED_IPS_IN_BLACKLIST = len(known_malicious_ips)
    # Set how much chance we’re okay with for a “false alarm”
    DESIRED_FP_PROBABILITY = 0.01
    print("Choose the option from below : ")
    print("-------------------------------")
    print("1. Check for malicious URL")
    print("2. Check for malicious IP")
    print("3. Check for website ")
    print("4. Exit")

    print()
    choice = 0
    
    while (choice != 4):
        choice = int(input("Enter the choice : "))
        if (choice == 1):
            # Make a Bloom filter just big enough for all known bad URLs
            url_filter = MaliciousURLFilter(EXPECTED_URLS_IN_BLACKLIST, DESIRED_FP_PROBABILITY)
            # Fill the filter with all the bad URLs we loaded
            print(f"--- Populating filter with {len(known_malicious_urls)} known malicious URLs... ---")
            # Canonicalize dataset entries as we insert them for consistent matching
            for url in known_malicious_urls:
                try:
                    canonical = canonicalize_url(url)
                    if canonical:
                        url_filter.add(canonical)
                    else:
                        # fallback: add the raw string if canonicalization failed
                        url_filter.add(url)
                except Exception:
                    # resilient: ignore bad entries in dataset
                    continue
            print("--- Filter is ready. ---\n")

            print("## Interactive Malicious URL Checker ##")
            print("Enter a URL to check if it's on the blacklist.")
            
            while True:
                user_input = input("\nEnter a URL (or type 'exit' to quit): ").strip()
                if user_input.lower() == 'exit':
                    print("Exiting checker.")
                    break
                if not user_input:
                    continue

                # Validation first
                if not is_valid_url_format(user_input):
                    print(f"   > ❌ Invalid or suspicious URL format: '{user_input}'")
                    print("Invalid URL format. Please enter a valid address starting with 'https://'.")

                    continue

                canonical = canonicalize_url(user_input)
                if not canonical:
                    print(f"   > ❌ Failed to canonicalize URL: '{user_input}' — treated as suspicious.")
                    continue

                # Membership check uses canonical form
                if canonical in url_filter:
                    print(f"   > 🚩 Warning: '{user_input}' (canonical: {canonical}) is PROBABLY MALICIOUS.")
                    print("   > Recommendation: Avoid this site.")
                else:
                    print(f"   > ✅ Result: '{user_input}' is DEFINITELY SAFE (not on our blacklist).")

        elif (choice == 2):
            ip_filter = MaliciousIPFilter(known_malicious_ips, DESIRED_FP_PROBABILITY)

            # Step 3: Populate the Filter 
            print(f"--- Populating filter with {len(known_malicious_ips)} known malicious IPs... ---")
            for ip in known_malicious_ips:
                try:
                    # normalize IP using ipaddress
                    canonical_ip = str(ipaddress.ip_address(ip))
                    ip_filter.add(canonical_ip)
                except Exception:
                    # ignore malformed IPs in dataset
                    continue
            print("--- Filter is ready. ---\n")
            print(" Interactive Malicious IP Checker ")
            print("Enter an IP to check if it's on the blacklist.")
            while True:
                user_input = input("\nEnter an IP (or type 'exit' to quit): ").strip()
                if user_input.lower() == 'exit':
                    print("Exiting checker.")
                    break
                if not user_input:
                    continue

                if not is_valid_ip_format(user_input):
                    print(f"   > ❌ Invalid IP address format: '{user_input}'")
                    continue

                canonical_ip = str(ipaddress.ip_address(user_input))
                if canonical_ip in ip_filter:
                    print(f"   > 🚩 Warning: '{user_input}' is PROBABLY MALICIOUS.")
                    print("   > Recommendation: Avoid this site.")
                else:
                    print(f"   > ✅ Result: '{user_input}' is DEFINITELY SAFE (not on our blacklist).")
        elif (choice == 3):
            run_crawler_simulation()


if __name__ == "__main__":
    run_interactive_checker()
