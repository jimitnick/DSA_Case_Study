import math
import random
import csv  # <-- ADD THIS IMPORT

# ==============================================================================
#  BLOOM FILTER IMPLEMENTATION (This part remains the same)
# ==============================================================================

class MaliciousURLFilter:
    """
    A Bloom Filter implementation from scratch, optimized for checking a URL blacklist.
    It calculates its own optimal parameters and uses double hashing.
    """
    def __init__(self, num_items, fp_prob):
        if not (0 < fp_prob < 1):
            raise ValueError("False positive probability must be between 0 and 1.")
        if not num_items > 0:
            raise ValueError("Number of items must be greater than 0.")
        self.size = self._calculate_optimal_size(num_items, fp_prob)
        self.hash_count = self._calculate_optimal_hash_count(self.size, num_items)
        self.bit_array = [0] * self.size
        print(f"## Filter Initialized ##")
        print(f"   - Target Items (n): {num_items}")
        print(f"   - FP Probability (p): {fp_prob:.2%}")
        print(f"   - Optimal Size (m): {self.size} bits")
        print(f"   - Optimal Hashes (k): {self.hash_count}\n")

    def _calculate_optimal_size(self, n, p):
        m = - (n * math.log(p)) / (math.log(2) ** 2)
        return int(math.ceil(m))

    def _calculate_optimal_hash_count(self, m, n):
        k = (m / n) * math.log(2)
        return int(math.ceil(k))

    def _hash_djb2(self, s: str):
        hash_val = 5381
        for char in s:
            hash_val = ((hash_val << 5) + hash_val) + ord(char)
        return hash_val

    def _get_hashes(self, item):
        hash1 = hash(item)
        hash2 = self._hash_djb2(item)
        for i in range(self.hash_count):
            yield (hash1 + i * hash2) % self.size
            
    def add(self, item):
        for digest in self._get_hashes(item):
            self.bit_array[digest] = 1

    def __contains__(self, item):
        for digest in self._get_hashes(item):
            if self.bit_array[digest] == 0:
                return False
        return True

# ==============================================================================
#  UPDATED DATA LOADING AND INTERACTIVE CHECKER
# ==============================================================================

# --- NEW FUNCTION TO LOAD DATA FROM THE CSV ---
def load_malicious_urls_from_csv(filename):
    """
    Loads URLs from the PhishTank CSV dataset.
    """
    urls = []
    print(f"--- Loading malicious URLs from '{filename}'... ---")
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader)  # Skip the header row
            for row in reader:
                if row:  # Ensure the row is not empty
                    # The URL is in the second column (index 1)
                    urls.append(row[1])
    except FileNotFoundError:
        print(f"   [Error] The file '{filename}' was not found.")
        print("   Please download it from PhishTank and save it in the same directory.")
        return None
    except Exception as e:
        print(f"   [Error] An error occurred while reading the file: {e}")
        return None
        
    print(f"--- Loaded {len(urls)} URLs successfully ---\n")
    return urls

def run_interactive_checker():
    """
    Main function to run the interactive malicious URL checker with real data.
    """
    # --- Step 1: Load the data ---
    # The filename should match what you saved the CSV as.
    DATASET_FILENAME = 'malicious_urls.csv'
    known_malicious_urls = load_malicious_urls_from_csv(DATASET_FILENAME)

    if known_malicious_urls is None:
        return # Stop execution if the file failed to load

    # --- Step 2: Configuration ---
    # The number of items is now the actual length of our dataset
    EXPECTED_URLS_IN_BLACKLIST = len(known_malicious_urls)
    DESIRED_FP_PROBABILITY = 0.01

    url_filter = MaliciousURLFilter(EXPECTED_URLS_IN_BLACKLIST, DESIRED_FP_PROBABILITY)

    # --- Step 3: Populate the Filter ---
    print(f"--- Populating filter with {len(known_malicious_urls)} known malicious URLs... ---")
    for url in known_malicious_urls:
        url_filter.add(url)
    print("--- Filter is ready. ---\n")

    # --- Step 4: Interactive Loop ---
    print("## 🕵️ Interactive Malicious URL Checker ##")
    print("Enter a URL to check if it's on the blacklist.")
    
    while True:
        user_input = input("\nEnter a URL (or type 'exit' to quit): ").strip().lower()
        if user_input == 'exit':
            print("Exiting checker.")
            break
        if not user_input:
            continue
            
        if user_input in url_filter:
            print(f"   > 🚩 Warning: '{user_input}' is PROBABLY MALICIOUS.")
            print("   > Recommendation: Avoid this site.")
        else:
            print(f"   > ✅ Result: '{user_input}' is DEFINITELY SAFE (not on our blacklist).")

if __name__ == "__main__":
    run_interactive_checker()