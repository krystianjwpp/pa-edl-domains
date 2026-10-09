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

# Matches valid domains/FQDNs and discards HTML tags, JSON formatting, brackets, or code snippets
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
            print(f" ❌ Security Warning: {feed_name} returned an HTML block page. Skipping.")
            continue
            
        lines = response.text.splitlines()
        feed_count = 0
        
        for line in lines:
            line = line.strip()
            
            # Skip documentation, comments, or adblock meta rows
            if not line or line.startswith('#') or line.startswith(';') or line.startswith('//') or line.startswith('!'):
                continue
                
            # Bulletproof comment stripping: splits line and takes everything before the comment flag
            clean_string = line.split('#')[0].split(';')[0].strip()
            if not clean_string:
                continue
                
            # Isolate the core domain string token out of whitespace columns
            tokens = clean_string.split()
            if not tokens:
                continue
                
            # Convert the domain string securely to lowercase
            domain_candidate = tokens[0].lower()
            
            # Validate format and append to unique set (automatic deduplication)
            if DOMAIN_REGEX.match(domain_candidate):
                master_domain_set.add(domain_candidate)
                feed_count += 1
                    
        print(f" ✅ {feed_name}: Ingested {feed_count:,} valid domains successfully.")
        
    except Exception as e:
        print(f" ❌ Error processing {feed_name}: {str(e)}")

print(f"📊 Consolidated unique domain database size: {len(master_domain_set):,} items.")

# Save directly to the current working directory root so git can commit it
base_dir = os.path.dirname(os.path.abspath(__file__))
output_file = os.path.join(base_dir, "pa-clean-domains.txt")

with open(output_file, "w") as f:
    for domain in sorted(master_domain_set):
        f.write(f"{domain}\n")

print(f"✅ Success! Generated master domain file with {len(master_domain_set):?} records.")
