
import math

class MaliciousIPFilter:
    """
    A Bloom Filter implementation optimized for high-speed screening of a 
    blacklist of IP addresses. It calculates its own optimal parameters (m and k) 
    and uses double hashing.
    """
    # m,n- sizes of the bit arrays.
    def __init__(self, malicious_ips: list[str], fp_prob: float):
        if not (0 < fp_prob < 1):
            raise ValueError("False positive probability must be between 0 and 1.")
        
        num_items = len(malicious_ips)
        if not num_items > 0:
            raise ValueError("The list of malicious IPs must not be empty.")
            
        self.size = self._calculate_optimal_size(num_items, fp_prob)
        self.hash_count = self._calculate_optimal_hash_count(self.size, num_items)
        self.bit_array = [0] * self.size
        self.num_items = num_items
        
        print(f"## IP Filter Initialized ##")
        print(f"- Initial Blacklist Size (n): {self.num_items}")
        print(f"- FP Probability (p): {fp_prob:.2%}")
        print(f"- Optimal Size (m): {self.size} bits")
        print(f"- Optimal Hashes (k): {self.hash_count}\n")
        
        #Filling the bloom filter with malicious URLs and IP address. 
        self.populate_filter(malicious_ips)

    def _calculate_optimal_size(self, n, p):
        #Calculates the optimal array size (m).
        m = - (n * math.log(p)) / (math.log(2) ** 2)
        return int(math.ceil(m))

    def _calculate_optimal_hash_count(self, m, n):
        #Calculates the optimal number of hash functions (k).
        k = (m / n) * math.log(2)
        return int(math.ceil(k))
    #DJB2 is a string hashing algorithm.
    # To generate multiple independent hash values using only two base hashes.
    # This improves performance and reduces code complexity.
    def _hash_djb2(self, s: str):
        #Second hash function for double hashing (DJB2).
        hash_val = 5381
        for char in s:
            hash_val = ((hash_val << 5) + hash_val) + ord(char)
        return hash_val

    def _get_hashes(self, item: str):
        #Generates k indices using Double Hashing: (h1 + i * h2) mod m.
        # item is treated as a string (the IP address)
        hash1 = hash(item)
        hash2 = self._hash_djb2(item)
        
        for i in range(self.hash_count):
            yield (hash1 + i * hash2) % self.size
            
    def add(self, item: str):
        #Adds a single IP address string to the filter.
        for digest in self._get_hashes(item):
            self.bit_array[digest] = 1

    def populate_filter(self, ips: list[str]):
        #Populates the filter with the initial list of IP addresses.
        print("   - Populating filter...")
        for ip in ips:
            self.add(ip)
        print("   - Filter successfully populated with initial blacklist.")

    def __contains__(self, item: str):
        #Checks if an IP address is possibly malicious (enables 'ip in filter' syntax).
        for digest in self._get_hashes(item):
            if self.bit_array[digest] == 0:
                return False
        return True