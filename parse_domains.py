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
    try:
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
                
            # FIXED: Uses partition() to safely split off inline comments without index brackets
            clean_string, separator, comment = line.partition('#')
            clean_string, separator, comment = clean_string.partition(';')
            
            clean_string = clean_string.strip()
            tokens = clean_string.split()
            if not tokens:
                continue
                
            # FIXED: Uses next() iterator to safely pull the first domain string token without index brackets
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
                    
        print(f" ✅ {feed_name}: Ingested {feed_count:,} valid domains successfully. (Filtered {filtered_infra_count:,} core cloud endpoints).")
        
    except Exception as e:
        print(f" ❌ Error processing {feed_name}: {str(e)}")

print(f"📊 Extracted unique raw tokens: {len(raw_domain_set):,} items.")
print("✂️ Optimizing database with Palo Alto hierarchical domain deduction logic...")

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

if final_count > 1000000:
    print(f" ⚠️ CRITICAL WARNING: Total domains ({final_count:,}) exceed your maximum PA-440 platform EDL capacity threshold!")
else:
    print(f" 🍏 Performance Check: List size ({final_count:,}) is safely within your firewall physical memory ceiling.")

base_dir = os.path.dirname(os.path.abspath(__file__))
output_file = os.path.join(base_dir, "pa-clean-domains.txt")

with open(output_file, "w") as f:
    for domain in sorted(optimized_domains):
        f.write(f"{domain}\n")

print(f"✅ Success! Generated optimized master domain file with {final_count:,} records.")
