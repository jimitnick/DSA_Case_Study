import math
import csv

# ==============================================================================
#  BLOOM FILTER IMPLEMENTATION
# ==============================================================================

class VisitedURLFilter:
    """
    A Bloom Filter implementation from scratch, used to track visited URLs
    for a web crawler to avoid re-fetching pages in a single session.
    """
    def __init__(self, num_items, fp_prob):
        if not (0 < fp_prob < 1):
            raise ValueError("False positive probability must be between 0 and 1.")
        if not num_items > 0:
            raise ValueError("Number of items must be greater than 0.")
            
        self.size = self._calculate_optimal_size(num_items, fp_prob)
        self.hash_count = self._calculate_optimal_hash_count(self.size, num_items)
        self.bit_array = [0] * self.size
        
        print(f"## Visited URL Filter Initialized ##")
        print(f"   - Estimated unique URLs (n): {num_items}")
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
#  WEB CRAWLER SIMULATION (WITHOUT PERSISTENCE)
# ==============================================================================

def run_crawler_simulation():
    """
    Simulates a web crawler using a Bloom filter for a single run.
    """
    DATASET_FILE = "tranco_list.csv"
    CRAWL_LIMIT = 50000  # Process the top 50,000 sites from the list

    # --- Step 1: Load the list of URLs to crawl ---
    try:
        with open(DATASET_FILE, 'r') as f:
            reader = csv.reader(f)
            # Read all domains up to our limit
            urls_to_process = [row[1] for i, row in enumerate(reader) if i < CRAWL_LIMIT]
        print(f"--- Successfully loaded {len(urls_to_process)} URLs to process. ---\n")
    except FileNotFoundError:
        print(f"[Error] Dataset '{DATASET_FILE}' not found. Please download it from Tranco.")
        return

    # --- Step 2: Initialize a fresh filter ---
    url_filter = VisitedURLFilter(num_items=len(urls_to_process), fp_prob=0.01)

    print(f"## 🕷️ Starting Web Crawler Simulation ##")
    
    # --- Step 3: Process all URLs ---
    new_urls_found = 0
    duplicates_skipped = 0
    for url in urls_to_process:
        if url not in url_filter:
            # Simulate fetching and indexing the new URL
            url_filter.add(url)
            new_urls_found += 1
        else:
            # This URL is a duplicate in our list
            duplicates_skipped += 1
    
    print(f"--- Processing complete. ---")
    print(f"   - Unique URLs indexed: {new_urls_found}")
    print(f"   - Duplicate URLs skipped: {duplicates_skipped}")

    # --- Step 4: Enter Interactive Mode ---
    print("\n## 🕵️ Interactive 'is_visited' Checker ##")
    print("Enter a domain to check if it was visited in this session.")
    
    while True:
        user_input = input("\nEnter domain (or 'exit' to quit): ").strip().lower()
        if user_input == 'exit':
            break
        if not user_input:
            continue
        
        if user_input in url_filter:
            print(f"   > ✅ Result: '{user_input}' was PROBABLY VISITED by the crawler.")
        else:
            print(f"   > ❌ Result: '{user_input}' was DEFINITELY NOT VISITED.")

if __name__ == "__main__":
    run_crawler_simulation()