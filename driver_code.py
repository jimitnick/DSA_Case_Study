#Filter -one for URLs and one for IP addresses
from malicious_ip_filter import MaliciousIPFilter 
from malicious_url_filter import MaliciousURLFilter 
from search_indexer import run_crawler_simulation

# Helper functions to quickly load the malicious URL/IP data from files
from helper_functions import load_malicious_urls_from_csv,load_ips_from_text_file

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
            for url in known_malicious_urls:
                url_filter.add(url)
            print("--- Filter is ready. ---\n")

            print("## Interactive Malicious URL Checker ##")
            print("Enter a URL to check if it's on the blacklist.")
            
            while True:
                user_input = input("\nEnter a URL (or type 'exit' to quit): ").strip().lower()
                if user_input == 'exit':
                    print("Exiting checker.")
                    break
                if not user_input:
                    continue
                # Check if the URL is in the filter    
                if user_input in url_filter:
                    print(f">Warning: '{user_input}' is PROBABLY MALICIOUS.")
                    print(">Recommendation: Avoid this site.")
                else:
                    print(f"   >Result: '{user_input}' is DEFINITELY SAFE (not on our blacklist).")
        elif (choice == 2):
            ip_filter = MaliciousIPFilter(known_malicious_ips, DESIRED_FP_PROBABILITY)

            # Step 3: Populate the Filter 
            print(f"--- Populating filter with {len(known_malicious_ips)} known malicious IPs... ---")
            for ip in known_malicious_ips:
                ip_filter.add(ip)
            print("--- Filter is ready. ---\n")
            print(" Interactive Malicious IP Checker ")
            print("Enter an IP to check if it's on the blacklist.")
            while True:
                user_input = input("\nEnter an IP (or type 'exit' to quit): ").strip().lower()
                if user_input == 'exit':
                    print("Exiting checker.")
                    break
                if not user_input:
                    continue
                if user_input in ip_filter:
                    print(f"> Warning: '{user_input}' is PROBABLY MALICIOUS.")
                    print("> Recommendation: Avoid this site.")
                else:
                    print(f"   > ✅ Result: '{user_input}' is DEFINITELY SAFE (not on our blacklist).")
        elif (choice == 3):
            run_crawler_simulation()

if __name__ == "__main__":
    run_interactive_checker()