import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

# Pulling a native, pre-scrubbed 1-domain-per-line flat malware infrastructure file
source_url = "https://githubusercontent.com"
clean_domains = set()

try:
    response = requests.get(source_url, headers=headers)
    if response.status_code == 200:
        lines = response.text.splitlines()
        for line in lines:
            domain = line.strip()
            # Skip comment headers or empty formatting lines
            if not domain or domain.startswith('#') or '{' in domain or '"' in domain:
                continue
            
            # Save the pure domain string natively
            clean_domains.add(domain.lower())
            
except Exception as e:
    print(f"Execution Error: {e}")

# Save the clean, sorted domains back to your flat text file
with open("pa-clean-domains.txt", "w") as f:
    for domain in sorted(clean_domains):
        f.write(f"{domain}\n")
