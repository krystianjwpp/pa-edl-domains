import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

master_domain_set = set()

# ==========================================
# SOURCE 1: DAVIDONZO OSINT THREAT INTEL
# ==========================================
source_1_url = "https://githubusercontent.com"
try:
    response = requests.get(source_1_url, headers=headers)
    if response.status_code == 200:
        lines = response.text.splitlines()
        for line in lines:
            naked_domain = line.strip()
            if not naked_domain or naked_domain.startswith('#') or '{' in naked_domain or '"' in naked_domain or 'localhost' in naked_domain:
                continue
            
            # Pure index finding to strip trailing paths safely
            slash_idx = naked_domain.find('/')
            if slash_idx != -1:
                naked_domain = naked_domain[:slash_idx]
                
            # Pure index finding to strip port numbers safely
            colon_idx = naked_domain.find(':')
            if colon_idx != -1:
                naked_domain = naked_domain[:colon_idx]
            
            # Drop trailing spaces and filter out direct IP addresses
            naked_domain = naked_domain.strip()
            clean_host_check = naked_domain.replace('.', '')
            if not clean_host_check.isdigit() and naked_domain:
                master_domain_set.add(naked_domain.lower())
except Exception as e:
    print(f"Error processing Source 1: {e}")

# ==========================================
# SOURCE 2: EMERGING THREATS OPEN BLOCKS
# ==========================================
source_2_url = "https://githubusercontent.com"
try:
    response = requests.get(source_2_url, headers=headers)
    if response.status_code == 200:
        lines = response.text.splitlines()
        for line in lines:
            naked_domain = line.strip()
            if not naked_domain or naked_domain.startswith('#') or '{' in naked_domain or '"' in naked_domain or 'localhost' in naked_domain:
                continue
                
            slash_idx = naked_domain.find('/')
            if slash_idx != -1:
                naked_domain = naked_domain[:slash_idx]
                
            colon_idx = naked_domain.find(':')
            if colon_idx != -1:
                naked_domain = naked_domain[:colon_idx]
                
            naked_domain = naked_domain.strip()
            clean_host_check = naked_domain.replace('.', '')
            if not clean_host_check.isdigit() and naked_domain:
                master_domain_set.add(naked_domain.lower())
except Exception as e:
    print(f"Error processing Source 2: {e}")

# ==========================================
# WRITE THE MERGED DATA TO A FLAT EDL FILE
# ==========================================
with open("pa-clean-domains.txt", "w") as f:
    for domain in sorted(master_domain_set):
        f.write(f"{domain}\n")
print(f"Successfully processed and wrote {len(master_domain_set)} clean domains.")
