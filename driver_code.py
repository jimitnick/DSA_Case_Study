from malicious_ip_filter import MaliciousIPFilter
from malicious_url_filter import MaliciousURLFilter
from search_indexer import run_crawler_simulation
from helper_functions import load_malicious_urls_from_csv, load_ips_from_text_file
import re
import ipaddress

def is_valid_url(url):
    pattern = re.compile(r'^(https?://)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$')
    return bool(pattern.match(url))

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

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
    URL_DATASET_FILENAME = 'datasets/malicious_urls.csv'
    IP_DATASET_FILENAME = 'datasets/bad_ip_dataset.txt'

    known_malicious_urls = load_malicious_urls_from_csv(URL_DATASET_FILENAME)
    known_malicious_ips = load_ips_from_text_file(IP_DATASET_FILENAME)

    if not known_malicious_urls or not known_malicious_ips:
        print("Error: Could not load malicious datasets. Please verify dataset paths.")
        return

    EXPECTED_URLS_IN_BLACKLIST = len(known_malicious_urls)
    EXPECTED_IPS_IN_BLACKLIST = len(known_malicious_ips)
    # Set how much chance we’re okay with for a “false alarm”
    DESIRED_FP_PROBABILITY = 0.01

    url_filter = MaliciousURLFilter(EXPECTED_URLS_IN_BLACKLIST, DESIRED_FP_PROBABILITY)
    ip_filter = MaliciousIPFilter(EXPECTED_IPS_IN_BLACKLIST, DESIRED_FP_PROBABILITY)

    for url in known_malicious_urls:
        url_filter.add(url.strip().lower())
    for ip in known_malicious_ips:
        ip_filter.add(ip.strip().lower())

    while True:
        print("\n==============================")
        print(" Malicious Checker Menu ")
        print("==============================")
        print("1. Check for malicious URL")
        print("2. Check for malicious IP")
        print("3. Check for website")
        print("4. Exit")

        try:
            choice = int(input("Enter your choice: ").strip())
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 4.")
            continue

        if choice == 1:
            print("\n--- Malicious URL Checker ---")
            while True:
                user_input = input("Enter a URL (or type 'exit' to go back): ").strip().lower()
                if user_input == 'exit':
                    break
                if not user_input:
                    continue
                if not is_valid_url(user_input):
                    print("The URL should be in the format: https://example.com")
                    continue

                if user_input in url_filter:
                    print(f"Warning: '{user_input}' is probably malicious.")
                else:
                    print(f"'{user_input}' is not in the blacklist.")

        elif choice == 2:
            print("\n--- Malicious IP Checker ---")
            while True:
                user_input = input("Enter an IP (or type 'exit' to go back): ").strip().lower()
                if user_input == 'exit':
                    break
                if not user_input:
                    continue
                if not is_valid_ip(user_input):
                    print("Invalid IP format. Please enter a valid IPv4 or IPv6 address.")
                    continue

                if user_input in ip_filter:
                    print(f"Warning: '{user_input}' is probably malicious.")
                else:
                    print(f"'{user_input}' is not in the blacklist.")

        elif choice == 3:
            run_crawler_simulation()

        elif choice == 4:
            print("Exiting program.")
            break

        else:
            print("Invalid choice. Please select between 1 and 4.")

if __name__ == "__main__":
    run_interactive_checker()
