import math
import csv

class VisitedURLFilter:
    """
    A Bloom Filter implementation from scratch, used to track visited URLs
    for a web crawler to avoid re-fetching pages in a single session.
    """
    def __init__(self, num_items, fp_prob):
        # ⏱️ Time Complexity: O(1)
        if not (0 < fp_prob < 1):
            raise ValueError("False positive probability must be between 0 and 1.")
        if not num_items > 0:
            raise ValueError("Number of items must be greater than 0.")
            
        self.size = self._calculate_optimal_size(num_items, fp_prob)
        self.hash_count = self._calculate_optimal_hash_count(self.size, num_items)
        self.bit_array = [0] * self.size
        
        print(f"## Visited URL Filter Initialized ##")
        print(f"- Estimated unique URLs (n): {num_items}")
        print(f"- FP Probability (p): {fp_prob:.2%}")
        print(f"- Optimal Size (m): {self.size} bits")
        print(f"- Optimal Hashes (k): {self.hash_count}\n")

    def _calculate_optimal_size(self, n, p):
        # ⏱️ Time Complexity: O(1)
        m = - (n * math.log(p)) / (math.log(2) ** 2)
        return int(math.ceil(m))

    def _calculate_optimal_hash_count(self, m, n):
        # ⏱️ Time Complexity: O(1)
        k = (m / n) * math.log(2)
        return int(math.ceil(k))

    def _hash_djb2(self, s: str):
        # ⏱️ Time Complexity: O(n), where n is the length of the string `s`
        hash_val = 5381
        for char in s:
            hash_val = ((hash_val << 5) + hash_val) + ord(char)
        return hash_val

    def _get_hashes(self, item):
        # ⏱️ Time Complexity: O(k), where k = number of hash functions (self.hash_count)
        hash1 = hash(item)
        hash2 = self._hash_djb2(item)
        for i in range(self.hash_count):
            yield (hash1 + i * hash2) % self.size
            
    def add(self, item):
        # ⏱️ Time Complexity: O(k), where k = number of hash functions
        for digest in self._get_hashes(item):
            self.bit_array[digest] = 1

    def __contains__(self, item):
        # ⏱️ Time Complexity: O(k), where k = number of hash functions
        # If any bit is 0 → the item was never added (definitely not visited).
        # If all bits are 1 → the item is probably visited (false positive possible).
        for digest in self._get_hashes(item):
            if self.bit_array[digest] == 0:
                return False
        return True


#  WEB CRAWLER SIMULATION (WITHOUT PERSISTENCE)

def run_crawler_simulation():
    # ⏱️ Time Complexity:
    # - Loading CSV: O(C), where C = number of URLs (CRAWL_LIMIT)
    # - Initializing filter: O(1)
    # - Processing all URLs: O(C * k), where k = number of hash functions
    # - Each membership check / add: O(k)
    # - Overall: O(C * k)
    DATASET_FILE = "datasets/tranco_list.csv"
    CRAWL_LIMIT = 50000

    try:
        with open(DATASET_FILE, 'r') as f:
            reader = csv.reader(f)
            urls_to_process = [row[1] for i, row in enumerate(reader) if i < CRAWL_LIMIT]
        print(f"--- Successfully loaded {len(urls_to_process)} URLs to process. ---\n")
    except FileNotFoundError:
        print(f"[Error] Dataset '{DATASET_FILE}' not found. Please download it from Tranco.")
        return

    url_filter = VisitedURLFilter(num_items=len(urls_to_process), fp_prob=0.01)

    print(f"## 🕷️ Starting Web Crawler Simulation ##")
    
    new_urls_found = 0
    duplicates_skipped = 0
    for url in urls_to_process:
        # CORRECTED LINE: Use the 'in' operator
        if url not in url_filter:
            url_filter.add(url)
            new_urls_found += 1
        else:
            duplicates_skipped += 1
    
    print(f"--- Processing complete. ---")
    print(f"- Unique URLs indexed: {new_urls_found}")
    print(f"- Duplicate URLs skipped: {duplicates_skipped}")

    print("\n Interactive 'is_visited' Checker ")
    print("Enter a domain to check if it was visited in this session.")
    
    while True:
        user_input = input("\nEnter domain (or 'exit' to quit): ").strip().lower()
        if user_input == 'exit':
            break
        if not user_input:
            continue
        
        # CORRECTED LINE: Use the 'in' operator
        if user_input in url_filter:
            print(f"> Result: '{user_input}' was PROBABLY VISITED by the crawler.")
        else:
            print(f"> Result: '{user_input}' was DEFINITELY NOT VISITED.")
            
            url_filter.add(user_input)
            print(f"> Result: '{user_input}' has been added to the url filter.")

if __name__ == "__main__":
    run_crawler_simulation()
