import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

# Pulling directly from a clean OSINT text list mirror that is natively one domain per line
source_url = "https://githubusercontent.com"
response = requests.get(source_url, headers=headers)
lines = response.text.splitlines()

clean_domains = set()

for line in lines:
    line = line.strip()
    
    # Skip comment headers, empty lines, or invalid JSON structures
    if not line or line.startswith('#') or '{' in line or '"' in line:
        continue
        
    # Standardize string data for the firewall
    clean_domains.add(line.lower())

# Save the sorted, clean domains to the flat file
with open("pa-clean-domains.txt", "w") as f:
    for domain in sorted(clean_domains):
        f.write(f"{domain}\n")
