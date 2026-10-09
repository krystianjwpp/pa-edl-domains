import os
import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

domain_sources = {
    "TweetFeed Domains": "https://api.tweetfeed.live/v1/blocklist/domains.txt",
    "CyberHost Malware": "https://cyberhost.uk",
    "Phishing.Army Extended": "https://phishing.army",
    "CERT.pl Domains": "https://cert.pl",
    "Phishing-Database Active 2": "https://githubusercontent.com"
}

master_domain_set = set()

print("🚀 Starting Master Domain Threat Intelligence Aggregation...")

for feed_name, url in domain_sources.items():
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code != 200:
            print(f" ⚠️ Skipping {feed_name}: HTTP Error {response.status_code}")
            continue
            
        # SAFETY CHECK: If a provider returns an HTML landing page instead of raw text, skip it entirely
        if "text/html" in response.headers.get("Content-Type", "").lower() or "<html" in response.text.lower():
            print(f" ❌ Security Warning: {feed_name} returned a web block/HTML page instead of raw text. Skipping.")
            continue
            
        lines = response.text.splitlines()
        feed_count = 0
        
        for line in lines:
            line = line.strip()
            
            # Skip empty rows, standard doc comments, or adblock style meta fields
            if not line or line.startswith('#') or line.startswith(';') or line.startswith('//') or line.startswith('!'):
                continue
                
            # Tokenize row contents by any whitespace block
            tokens = line.split()
            if not tokens:
                continue
                
            domain_candidate = tokens[0].lower()
            
            # HARD VALIDATION: A valid domain will never contain HTML/JS programming syntax
            # This cleanly screens out hidden scripts, brackets, and jQuery tokens
            if any(char in domain_candidate for char in ['<', '>', '{', '}', '$', '(', ')', '"', "'"]):
                continue
                
            # Double check that the candidate contains a standard TLD dot notation structure
            if '.' in domain_candidate and len(domain_candidate) > 3:
                master_domain_set.add(domain_candidate)
                feed_count += 1
                    
        print(f" ✅ {feed_name}: Ingested {feed_count:,} unique domains successfully.")
        
    except Exception as e:
        print(f" ❌ Error processing {feed_name}: {str(e)}")

print(f"📊 Consolidated unique domain database size: {len(master_domain_set):,} items.")

# Save directly to the current working directory root so git can commit it cleanly
base_dir = os.path.dirname(os.path.abspath(__file__))
output_file = os.path.join(base_dir, "pa-clean-domains.txt")

with open(output_file, "w") as f:
    for domain in sorted(master_domain_set):
        f.write(f"{domain}\n")

print(f"✅ Success! Generated master domain file at: {output_file}")
