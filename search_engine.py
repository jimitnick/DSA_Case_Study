import math # Standard library for log calculations

class MaliciousURLFilter:
    """
    A Bloom Filter implementation from scratch, optimized for checking a URL blacklist.
    It calculates its own optimal parameters and uses double hashing.
    """

    def __init__(self, num_items, fp_prob):
        """
        Initializes the Bloom Filter.

        Args:
            num_items (int): The expected number of items to be stored (n).
            fp_prob (float): The desired false positive probability (e.g., 0.01 for 1%).
        """
        if not (0 < fp_prob < 1):
            raise ValueError("False positive probability must be between 0 and 1.")
        if not num_items > 0:
            raise ValueError("Number of items must be greater than 0.")
            
        # 1. Calculate optimal parameters for the filter
        self.size = self._calculate_optimal_size(num_items, fp_prob)
        self.hash_count = self._calculate_optimal_hash_count(self.size, num_items)
        
        # 2. Initialize the bit array (using a standard Python list)
        self.bit_array = [0] * self.size
        
        print(f"## Filter Initialized ##")
        print(f"   - Target Items (n): {num_items}")
        print(f"   - FP Probability (p): {fp_prob:.2%}")
        print(f"   - Optimal Size (m): {self.size} bits")
        print(f"   - Optimal Hashes (k): {self.hash_count}\n")


    def _calculate_optimal_size(self, n, p):
        """
        Calculates the optimal bit array size (m).
        Formula: m = - (n * ln(p)) / (ln(2)^2)
        """
        m = - (n * math.log(p)) / (math.log(2) ** 2)
        return int(math.ceil(m))

    def _calculate_optimal_hash_count(self, m, n):
        """
        Calculates the optimal number of hash functions (k).
        Formula: k = (m / n) * ln(2)
        """
        k = (m / n) * math.log(2)
        return int(math.ceil(k))

    def _hash_djb2(self, s: str):
        """
        A simple, non-cryptographic hash function (DJB2).
        Provides the second hash for our double hashing technique.
        """
        hash_val = 5381
        for char in s:
            hash_val = ((hash_val << 5) + hash_val) + ord(char)
        return hash_val

    def _get_hashes(self, item):
        """
        Generates k hash digests for an item using double hashing.
        """
        # Use Python's built-in hash for the first value
        hash1 = hash(item)
        # Use our custom implementation for the second
        hash2 = self._hash_djb2(item)

        for i in range(self.hash_count):
            # The double hashing formula: (h1(x) + i * h2(x)) % m
            yield (hash1 + i * hash2) % self.size
            
    def add(self, item):
        """
        Adds an item to the Bloom Filter by setting bits to 1.
        """
        for digest in self._get_hashes(item):
            self.bit_array[digest] = 1
        print(f"   ✔️ Added '{item}'")

    def __contains__(self, item):
        """
        Checks if an item is probably in the set. Allows using the `in` keyword.
        """
        for digest in self._get_hashes(item):
            if self.bit_array[digest] == 0:
                # If any bit is 0, it's definitely not in the set
                return False
        # If all bits were 1, it's probably in the set
        return True

# --- Simulation ---

def run_search_engine_simulation():
    """
    Main function to run the malicious URL checker simulation.
    """
    print("## 🌐 Search Engine: Malicious URL Blacklist Simulation ##\n")

    # --- Step 1: Configuration ---
    # Let's say we have a blacklist of 50,000 malicious URLs
    # and we can tolerate a 1% false positive rate.
    EXPECTED_URLS_IN_BLACKLIST = 50000
    DESIRED_FP_PROBABILITY = 0.01

    # Initialize our filter with these parameters
    url_filter = MaliciousURLFilter(EXPECTED_URLS_IN_BLACKLIST, DESIRED_FP_PROBABILITY)

    # --- Step 2: Populate the Filter ---
    # We'll use a small sample for this demonstration.
    known_malicious_urls = [
        "evil-phishing-site.com/login",
        "malware-distributor.net/download.exe",
        "crypto-scam.org/invest",
        "fake-bank-of-world.com/verify"
    ]
    print("--- Populating filter with known malicious URLs ---")
    for url in known_malicious_urls:
        url_filter.add(url)
    print("--- Filter population complete ---\n")

    # --- Step 3: Test the Filter ---
    # A list of URLs a web crawler might encounter.
    urls_to_check = [
        # Case 1: A URL that is actually malicious
        "evil-phishing-site.com/login",
        # Case 2: A URL that is definitely safe
        "google.com",
        # Case 3: A URL that is safe but might cause a collision
        "this-is-a-safe-url.com"
    ]

    print("--- Crawler checking URLs against the filter ---")
    for url in urls_to_check:
        print(f"Checking '{url}'...")
        if url in url_filter:
            # This could be a true positive or a false positive
            if url in known_malicious_urls:
                print("   ➡️ Result: PROBABLY MALICIOUS.")
                print("   ✅ Verdict: CORRECT (True Positive). URL is on our blacklist.\n")
            else:
                print("   ➡️ Result: PROBABLY MALICIOUS.")
                print("   ⚠️  Verdict: INCORRECT (False Positive). All hash bits happened to be 1 by chance. The crawler would skip this safe URL.\n")
        else:
            # This is a definite negative
            print("   ➡️ Result: DEFINITELY SAFE.")
            print("   ✅ Verdict: CORRECT (True Negative). URL is not on our blacklist.\n")

if __name__ == "__main__":
    run_search_engine_simulation()