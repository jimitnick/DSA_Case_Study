import math 

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