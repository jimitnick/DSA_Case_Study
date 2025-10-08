import csv 

def load_malicious_urls_from_csv(filename):
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

def load_ips_from_text_file(filename):
    ips = []
    print(f"--- Loading malicious IPs from '{filename}' ---")
    try:
        with open(filename,'r') as f:
            reader = f.readlines()
        for i in reader:
            ips.append(i.rstrip("\n"))
    except:   
        print("Error loading the file")
    print(f"--- Loaded {len(ips)} URLs successfully ---\n")
    return ips