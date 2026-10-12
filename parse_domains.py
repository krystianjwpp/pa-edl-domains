import os
import re
import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

domain_sources = {
    "TweetFeed Domains": "https://api.tweetfeed.live/v1/blocklist/domains.txt",
    "CyberHost Malware": "https://lists.cyberhost.uk/malware.txt",
    "Phishing.Army Extended": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "CERT.pl Domains": "https://hole.cert.pl/domains/v2/domains.txt",
    "Phishing-Database Active 2": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE/phishing-domains-ACTIVE2.txt"
}

CLOUD_INFRASTRUCTURE_WHITELIST = {
    "amazonaws.com",
    "ionoscloud.com",
    "retrospectcloud.com",
    "googleusercontent.com",
    "windows.net"
}

raw_domain_set = set()
DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9_]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9_]{0,62})+$')

print("🚀 Starting Master Domain Threat Intelligence Aggregation...")

for feed_name, url in domain_sources.items():
    print(f"📡 Fetching data from: {feed_name}...")
    response = requests.get(url, headers=headers, timeout=45)
    
    if response.status_code != 200:
        print(f" ⚠️ Skipping {feed_name}: HTTP Error {response.status_code}")
        continue
        
    if "text/html" in response.headers.get("Content-Type", "").lower() or "<html" in response.text[:2000].lower():
        print(f" ❌ Security Warning: {feed_name} returned an HTML block page. Skipping.")
        continue
        
    lines = response.text.splitlines()
    feed_count = 0
    filtered_infra_count = 0
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith(('#', ';', '//', '!')):
            continue
            
        # Clean inline comments securely without list brackets
        clean_string, _, _ = line.partition('#')
        clean_string, _, _ = clean_string.partition(';')
        
        clean_string = clean_string.strip()
        tokens = clean_string.split()
        if not tokens:
            continue
            
        # Safely pull the first domain string token using next() iterator
        token_iterator = iter(tokens)
        domain_candidate = next(token_iterator).lower()
        
        if len(domain_candidate) > 255:
            continue
            
        if DOMAIN_REGEX.match(domain_candidate):
            is_whitelisted = False
            for allowed_base in CLOUD_INFRASTRUCTURE_WHITELIST:
                if domain_candidate == allowed_base or domain_candidate.endswith("." + allowed_base):
                    parts = domain_candidate.split('.')
                    if len(parts) <= 4:
                        is_whitelisted = True
                        break

            if is_whitelisted:
                filtered_infra_count += 1
                continue
            
            raw_domain_set.add(domain_candidate)
            feed_count += 1
                
    print(f" ✅ {feed_name}: Ingested {feed_count:,} domains. (Filtered {filtered_infra_count:,} core cloud endpoints).")

print(f"📊 Total unique raw tokens collected: {len(raw_domain_set):,}")
print("✂️ Running Palo Alto hierarchical optimization engine...")

sorted_domains = sorted(list(raw_domain_set), key=len)
optimized_domains = set()

for domain in sorted_domains:
    parts = domain.split('.')
    is_subdomain_blocked = False
    
    for i in range(1, len(parts)):
        parent_candidate = ".".join(parts[i:])
        if parent_candidate in optimized_domains:
            is_subdomain_blocked = True
            break
            
    if not is_subdomain_blocked:
        optimized_domains.add(domain)

final_count = len(optimized_domains)
print(f"📊 Consolidated explicit Palo Alto EDL size: {final_count:,} items.")

base_dir = os.path.dirname(os.path.abspath(__file__))
output_file = os.path.join(base_dir, "pa-clean-domains.txt")
print(f"💾 Target output directory path: {output_file}")

with open(output_file, "w") as f:
    for domain in sorted(optimized_domains):
        f.write(f"{domain}\n")

print(f"✅ Success! File generation finished completely.")
