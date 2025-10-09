import math 

class MaliciousURLFilter:
    """
    A Bloom Filter implementation from scratch, optimized for checking a URL blacklist.
    It calculates its own optimal parameters and uses double hashing.
    """
    # m,n- sizes of the bit arrays.
    def __init__(self, num_items, fp_prob):
        # Time Complexity: O(1) for setup + O(m) for initializing bit array
        # Space Complexity: O(m)
        if not (0 < fp_prob < 1):
            raise ValueError("False positive probability must be between 0 and 1.")
        if not num_items > 0:
            raise ValueError("Number of items must be greater than 0.")
        self.size = self._calculate_optimal_size(num_items, fp_prob)  # O(1)
        self.hash_count = self._calculate_optimal_hash_count(self.size, num_items)  # O(1)
        self.bit_array = [0] * self.size  # O(m)
        print(f"## Filter Initialized ##")
        print(f"- Target Items (n): {num_items}")
        print(f"- FP Probability (p): {fp_prob:.2%}")
        print(f"- Optimal Size (m): {self.size} bits")
        print(f"- Optimal Hashes (k): {self.hash_count}\n")

    def _calculate_optimal_size(self, n, p):
        #Calculates the optimal array size (m).
        # Time Complexity: O(1)
        # Space Complexity: O(1)
        m = - (n * math.log(p)) / (math.log(2) ** 2)
        return int(math.ceil(m))

    def _calculate_optimal_hash_count(self, m, n):
        #Calculates the optimal number of hash functions (k).
        # Time Complexity: O(1)
        # Space Complexity: O(1)
        k = (m / n) * math.log(2)
        return int(math.ceil(k))

    def _hash_djb2(self, s: str):
        #Second hash function for double hashing (DJB2).
        # Time Complexity: O(L), where L = length of string
        # Space Complexity: O(1)
        hash_val = 5381
        for char in s:
            hash_val = ((hash_val << 5) + hash_val) + ord(char)
        return hash_val

    def _get_hashes(self, item):
        #Generates k indices using Double Hashing: (h1 + i * h2) mod m.
        # Time Complexity: O(k)
        # Space Complexity: O(1)
        # item is treated as a string (the IP address)
        hash1 = hash(item)          # O(L)
        hash2 = self._hash_djb2(item)  # O(L)
        for i in range(self.hash_count):
            yield (hash1 + i * hash2) % self.size  # O(1) per iteration
            
    def add(self, item):
        #Adds a single IP address string to the filter.
        # Time Complexity: O(k)
        # Space Complexity: O(1)
        for digest in self._get_hashes(item):
            self.bit_array[digest] = 1

    def __contains__(self, item):
        #Checks if a URL is possibly malicious.
        # Time Complexity: O(k)
        # Space Complexity: O(1)
        for digest in self._get_hashes(item):
            if self.bit_array[digest] == 0:
                return False
        return True
