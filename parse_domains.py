import os
import re
import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

domain_sources = {
    "TweetFeed Domains": "https://tweetfeed.live",
    "CyberHost Malware": "https://cyberhost.uk",
    "Phishing.Army Extended": "https://phishing.army",
    "CERT.pl Domains": "https://cert.pl",
    "Phishing-Database Active 2": "https://githubusercontent.com"
}

master_domain_set = set()

# A robust Regex that strictly matches a valid Domain/FQDN structure:
# Allows numbers, letters, dashes, and dots. Rejects HTML, JS, braces, quotes, or JSON data.
DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9_]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9_]{0,62})+$')

print("🚀 Starting Master Domain Threat Intelligence Aggregation...")

for feed_name, url in domain_sources.items():
    try:
        response = requests.get(url, headers=headers, timeout=45)
        if response.status_code != 200:
            print(f" ⚠️ Skipping {feed_name}: HTTP Error {response.status_code}")
            continue
            
        # Stop landing page contamination right at the threshold
        if "text/html" in response.headers.get("Content-Type", "").lower() or "<html" in response.text[:2000].lower():
            print(f" ❌ Security Warning: {feed_name} returned an HTML block page. Skipping to protect feed data.")
            continue
            
        lines = response.text.splitlines()
        feed_count = 0
        
        for line in lines:
            line = line.strip()
            
            # Skip documentation, comments, empty rows, or adblock style meta definitions
            if not line or line.startswith('#') or line.startswith(';') or line.startswith('//') or line.startswith('!'):
                continue
                
            # Tokenize row contents by any whitespace block to extract the bare domain token
            tokens = line.split()
            if not tokens:
                continue
            domain_candidate = tokens.lower()
            
            # Remove any trailing inline comment parts if present (e.g., 'domain.com # Malicious')
            domain_candidate = domain_candidate.split('#').split(';')[0].strip()
            
            # Validate the candidate strictly using the Domain Regex
            if DOMAIN_REGEX.match(domain_candidate):
                master_domain_set.add(domain_candidate)
                feed_count += 1
                    
        print(f" ✅ {feed_name}: Ingested {feed_count:,} valid domains successfully.")
        
    except Exception as e:
        print(f" ❌ Error processing {feed_name}: {str(e)}")

print(f"📊 Consolidated unique domain database size: {len(master_domain_set):,} items.")

# Save directly to the current working directory root so git can find it
base_dir = os.path.dirname(os.path.abspath(__file__))
output_file = os.path.join(base_dir, "pa-clean-domains.txt")

with open(output_file, "w") as f:
    for domain in sorted(master_domain_set):
        f.write(f"{domain}\n")

print(f"✅ Success! Generated master domain file with {len(master_domain_set):,} records.")
