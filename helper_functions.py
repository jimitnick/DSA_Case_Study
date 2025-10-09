import csv 

# Loading the malicious URLs from the CSV file.
def load_malicious_urls_from_csv(filename):
    urls = []
    print(f"--- Loading malicious URLs from '{filename}'... ---")
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader)  # O(1) - Skip the header row
            for row in reader:  # O(n) - Iterate through n rows
                if row:  
                    urls.append(row[1])  # O(1) - Append operation
    except FileNotFoundError:
        print(f"   [Error] The file '{filename}' was not found.")
        print("   Please download it from PhishTank and save it in the same directory.")
        return None
    except Exception as e:
        print(f"   [Error] An error occurred while reading the file: {e}")
        return None
        
    print(f"--- Loaded {len(urls)} URLs successfully ---\n")
    return urls  # Overall Time Complexity: O(n), Space Complexity: O(n)


# Loading the IPs from the text file.
def load_ips_from_text_file(filename):
    ips = []
    print(f"--- Loading malicious IPs from '{filename}' ---")
    try:
        with open(filename, 'r') as f:
            reader = f.readlines()  # O(m) - Reads all m lines into memory
        for i in reader:  # O(m) - Loop through each line
            ips.append(i.rstrip("\n"))  # O(1) per append and strip
    except:   
        print("Error loading the file")
    print(f"--- Loaded {len(ips)} URLs successfully ---\n")
    return ips  # Overall Time Complexity: O(m), Space Complexity: O(m)
