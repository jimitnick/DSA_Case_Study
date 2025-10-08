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
