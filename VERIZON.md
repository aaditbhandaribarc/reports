# 2025 Verizon Data Breach Investigations Report (DBIR) - Detailed Summary

## Executive Overview
The 2025 DBIR analyzed **22,052 security incidents**, including **12,195 confirmed data breaches** from 139 countries worldwide—the highest number ever analyzed in a single report. The report reveals significant shifts in the threat landscape, particularly around third-party involvement, ransomware evolution, and exploitation of edge device vulnerabilities.

---

## Key Statistics & Trends

### Initial Access Vectors
- **Exploitation of vulnerabilities: 20%** (34% increase from prior year)
- **Use of stolen credentials: 22%** (down from 31%)
- **Phishing: 15%**
- **Edge devices and VPNs** now represent 22% of exploitation targets (up from 3%)

### Ransomware Growth
- Present in **44% of all breaches** (up from 32%)
- **Median ransom payment: $115,000** (down from $150,000)
- **64% of victims refused to pay** (up from 50%)
- Disproportionately affects SMBs: **88% of SMB breaches** vs. 39% for large organizations

### Third-Party Involvement
- **30% of breaches** involved third parties (doubled from 15%)
- Major incidents: Snowflake, Change Healthcare, CDK Global, Blue Yonder

---

## Threat Actors & Motives

### Actor Categories
- **External actors: 96%** of breaches
- **Internal actors: 2%** (primarily errors)
- **Partners: 1%**

### Threat Actor Types
- **Organized crime: 85%** (Financial motive)
- **State-sponsored actors: 15%** (Espionage motive)
- **Nation-state actors** also engage in financially motivated attacks (28% of state-sponsored incidents)

### Motivations
- **Financial: 90%** of breaches
- **Espionage: 17%** (163% increase, nearly tripled)
- **Ideology: 2%**

### Notable Threat Groups Mentioned
- **UNC5221/UTA0178** (Chinese APT) - Ivanti Connect Secure attacks
- **APT28/Forest Blizzard** (Russian) - Using GooseEgg tool
- **APT29/Midnight Blizzard** (Russian) - Email system compromises
- **Volt Typhoon** (Chinese) - Critical infrastructure targeting
- **Salt Typhoon** (Chinese) - Telecommunications espionage campaign
- **Kimsuky/Sparkling Pisces** (North Korean) - Job-themed phishing
- **Mint Sandstorm** (Iranian) - Various campaigns
- **Storm-0940** (Chinese) - Password spray attacks using CovertNetwork-1658/Quad7 botnet
- **LockBit** - Ransomware group (Operation Cronos disruption)
- **BlackSuit/Royal** - Ransomware rebranding
- **8Base, Akira, Black Basta, RansomHub** - Active ransomware groups
- **Evil Corp** - $300M in damages
- **Scattered Spider** - Phishing and cryptocurrency targeting

---

## Tactics, Techniques & Procedures (TTPs)

### Top Attack Patterns (Incident Classification)
1. **System Intrusion: 53%** of breaches
   - Complex attacks using hacking + malware
   - Ransomware deployment
   - Espionage operations

2. **Social Engineering: 17%**
   - Phishing
   - Pretexting
   - Prompt bombing (MFA fatigue attacks)

3. **Basic Web Application Attacks: 12%**
   - Credential abuse
   - SQL injection
   - API exploitation

4. **Miscellaneous Errors: 12%**
   - Misdelivery (60% of errors)
   - Misconfiguration
   - Publishing errors

5. **Privilege Misuse: 6%**

6. **Denial of Service: 6%**

### Attack Actions

#### Malware (Top Varieties)
- **Ransomware: 44%** of breaches
- **Backdoors/C2 establishment**
- **Infostealers** (LummaStealer, FakeCall, RedLine, META)
- **Keyloggers**
- **Magecart** (payment card skimming - 1% of System Intrusion, 80% of payment breaches)

#### Hacking Techniques
- **Use of stolen credentials: 22%**
- **Exploit vulnerability: 20%**
- **Brute force attacks**
- **SQL injection**
- **Backdoor installation**
- **Command and control (C2)**

#### Social Engineering
- **Phishing: 77%** of social attacks
- **Pretexting: 7%**
- **Prompt bombing: 20%** (MFA fatigue)
- **Baiting** (malicious software via SEO)
- **Business Email Compromise (BEC): $6.3 billion** transferred in 2024

#### MFA Bypass Techniques
- **Token theft: 31%**
- **Adversary-in-the-Middle (AiTM)**
- **Prompt bombing/MFA interrupt**
- **Password dumping**
- **SIM swapping/Hijacking**

---

## Vulnerabilities & Exploits

### Critical Zero-Days Exploited in 2024
- **Ivanti Connect Secure/Policy Secure** (CVE-2023-6548, CVE-2023-6549, CVE-2024-21887, CVE-2024-21893)
- **Fortinet FortiOS SSL VPN** (CVE-2024-21762, CVE-2024-23113, CVE-2024-47575)
- **Palo Alto Networks GlobalProtect** (CVE-2024-3400)
- **Cisco ASA/FTD** (ArcaneDoor campaign, CVE-2024-20359)
- **Citrix NetScaler ADC/Gateway** (two zero-days)
- **Google Chrome V8 engine** (CVE-2024-5274)
- **Jenkins servers** (CVE-2024-23897)
- **Atlassian Confluence**
- **VMware ESXi** (CVE-2024-37085)
- **Juniper Mist Premium Analytics**
- **Progress Telerik**
- **ServiceNow Now Platform** (CVE-2024-4879, CVE-2024-5217)
- **Versa Director** (CVE-2024-39717)
- **XZ Utils** (supply chain backdoor)

### Vulnerability Management Statistics
- **Median time to full remediation: 32 days** (edge devices)
- Only **54% fully remediated** throughout the year
- **Median time to mass exploit: 5 days** (KEV catalog)
- **Edge device vulnerabilities: 0 days median** (9 of 17 exploited on/before CVE publication)

---

## Indicators of Compromise (IOCs) & Infrastructure

### Credential Compromise Ecosystem

#### Infostealer Statistics
- **30% of compromised systems** were enterprise-licensed devices
- **46% of systems with corporate logins** were non-managed (BYOD)
- **54% of ransomware victims** had domains in infostealer logs
- **40% had corporate email addresses** in compromised credentials

#### Leaked Secrets in Code Repositories
- **Median time to remediate: 94 days**
- **Web application infrastructure: 39%** of disclosed secrets
- **JSON Web Tokens (JWT): 66%** of web app secrets
- **GitLab tokens: 50%** of dev/CI/CD secrets
- **Google Cloud API keys: 43%** of cloud infrastructure secrets

#### Compromised Database Passwords
- **2.8 billion passwords** posted for sale in 2024
- **63 million records with weak MD5 hashes**
- Only **3% of unique passwords** meet complexity requirements

### Attack Vectors by Asset Type
- **Web applications: 24%**
- **Email: 19%**
- **VPN: 10%**
- **Other network services: 9%**
- **Desktop sharing: 4%**

### GenAI Security Concerns
- **15% of employees** routinely access GenAI on corporate devices
- **72% use non-corporate email** identifiers
- **17% use corporate email without integrated authentication**
- **AI-assisted malicious emails doubled** (5% to 10%) over two years

---

## Attack Targets

### By Industry (Top Victims)
1. **Manufacturing: 3,837 incidents** (1,607 breaches)
2. **Finance & Insurance: 3,336 incidents** (927 breaches)
3. **Healthcare: 1,710 incidents** (1,542 breaches)
4. **Professional Services: 2,549 incidents** (1,147 breaches)
5. **Public Sector: 1,422 incidents** (946 breaches)
6. **Information: 1,589 incidents** (784 breaches)
7. **Education: 1,075 incidents** (851 breaches)
8. **Retail: 837 incidents** (419 breaches)

### By Organization Size
- **SMBs (<1,000 employees): 3,049 incidents** (2,842 breaches)
  - 88% experienced ransomware
  - 98% attacked by external actors
  
- **Large Organizations (>1,000): 982 incidents** (751 breaches)
  - 39% experienced ransomware
  - 75% attacked by external actors
  - 18% error-related breaches

### By Asset Type
- **Servers: 95%** of breaches
- **Person assets: 60%** (human element)
- **User devices**
- **Remote access servers** (growing target)
- **Edge devices** (firewalls, VPNs, routers)

### Geographic Distribution (by Region)
- **North America (NA): 6,361 incidents** (2,867 breaches)
- **EMEA: 9,062 incidents** (5,321 breaches)
- **APAC: 2,687 incidents** (1,374 breaches)
- **LAC: 657 incidents** (413 breaches)

---

## Data Compromised

### Most Common Data Types
1. **Internal data: 85%** (reports, plans, emails, secrets)
2. **Personal data: 95%** (in Miscellaneous Errors)
3. **Credentials: 35%**
4. **Medical: 45%** (Healthcare specific)
5. **Other: 44%**
6. **Secrets: 25%**
7. **Bank data: 10%**
8. **Payment card data: 1%** (continuing decline)
9. **Sensitive Personal: 10%** (government IDs, passports)

---

## Notable Campaigns & Breaches

### Major Third-Party Incidents
1. **Snowflake** (April 2024)
   - ~165 organizations affected
   - Stolen credentials used (80% previously exposed)
   - Lack of mandatory MFA
   - Threat actor: UNC5537

2. **Change Healthcare**
   - Ransomware + data breach
   - Millions of records
   - Operational disruption

3. **CDK Global**
   - BlackSuit ransomware (Royal rebrand)
   - Auto dealership disruptions

4. **Blue Yonder**
   - Ransomware
   - Affected Starbucks, supermarkets

5. **CrowdStrike Outage** (July 2024)
   - Not malicious (programming error)
   - Faulty Falcon Sensor update
   - Global Windows systems disruption
   - Aviation, healthcare, finance affected

6. **National Public Data**
   - 2.9 billion records leaked
   - SSNs, DOB, addresses (US, Canada, UK)
   - SMB with handful of employees

### Supply Chain Attacks
- **XZ Utils backdoor** (March 2024)
  - Targeted social engineering since 2021
  - Open-source software compromise
  
- **polyfill.io** (July 2024)
  - Largest digital supply chain attack
  - JavaScript library injecting malware
  - Hundreds of thousands affected

### Magecart Operations
- **Median monthly visitors to compromised sites: 7,000**
- **Median infection duration: <30 days**
- **43,324 websites** in multi-year dataset
- Targets e-commerce sites opportunistically

---

## DDoS Attack Evolution
- **Median growth since 2018: 200%+** in size
- **Upper bounds BPS: 1,000% increase**
- **Record attack: 3.8 Tbps** (October 2024, Cloudflare)
- **Top targets:** Finance (35%), Manufacturing (28%), Professional Services (17%)
- **Gorilla Botnet:** 300,000 attacks in September 2024

---

## Human Element

### Overall Impact
- **60% of breaches** involved human element (stable)
- **15% median click rate** on phishing simulations
- **1.5% minimum** persistent clickers despite training

### Training Effectiveness
- **Recent training (<30 days):**
  - **21% report rate** (vs 5% baseline)
  - **4x relative increase** in reporting
  - **5% relative impact** on click rates

### Error Breakdown
- **Misdelivery: 72%** of end-user errors
- **Misconfiguration** (databases exposed)
- **Publishing errors**
- **Classification errors**

---

## Espionage Operations

### State-Sponsored Activity
- **70% use vulnerability exploitation** for initial access
- **28% have financial secondary motive**
- **Espionage-motivated breaches: 17%** (tripled from prior year)

### Specific Campaigns
- **Salt Typhoon** (Chinese)
  - U.S. telecommunications targeting
  - Verizon and other carriers affected
  - Phone calls of senior political figures recorded
  
- **Storm-0940** (Chinese)
  - North America/Europe targets
  - Think tanks, government, NGOs, law firms, defense
  - Quad7 botnet (CovertNetwork-1658)
  - Password spray attacks

- **Iranian Operations**
  - 2024 U.S. presidential election targeting
  - Influence operations + ransomware
  - Healthcare and Financial sectors

- **North Korean IT Workers**
  - Masquerading as workers from allowed countries
  - Data exfiltration + extortion
  - Industrial-scale fake employee operations

---

## Regional Analysis

### APAC
- **System Intrusion: 83%**
- **Espionage motive: 34%**
- **Organized crime: 80%**
- **State-affiliated: 33%**

### EMEA
- **System Intrusion: 53%**
- **Internal actors: 29%** (highest of all regions)
- **Financial motive: 87%**
- **Espionage: 18%**

### North America
- **System Intrusion: 90%**
- **Medical data: 35%** (Healthcare heavy)
- **Financial motive: 95%**

### Public Sector Specific
- **Federal:** Espionage (33%), Financial (63%)
- **SLTT:** Financial (96%), Errors prominent
- **Ransomware: 30%** across all government levels
- **70% cite lack of funding** as top concern
- **80% have <5 security staff**

---

## Law Enforcement Actions

### Major Disruptions in 2024
1. **Operation Cronos** (February)
   - LockBit ransomware takedown
   - Infrastructure seized, ~2,200 bitcoin
   - Developer arrested (Rostislav Panev)
   - Operator indicted (Dmitry Khoroshev - $10M bounty)

2. **Operation Destabilise** (December)
   - Russian money laundering networks
   - 84 arrests, £20M seized

3. **Operation PowerOFF** (December)
   - 27 DDoS-for-hire platforms disrupted
   - 300 users identified

4. **Volt Typhoon Botnet** (September)
   - Operation Raptor Train
   - 200,000+ IoT devices freed

5. **Rydox Marketplace** (December)
   - 18,000 cybercriminal users

6. **Bohemia/Cannabia** (October)
   - Dark web market (€12M monthly)

### Notable Indictments
- **Sergey Ivanov & Timur Shakhmametov** (Russian) - Billion-dollar money laundering
- **Maxim Rudometov** (Russian) - RedLine infostealer
- **Evgenii Ptitsyn** (Russian) - Phobos ransomware ($16M)
- **Scattered Spider members** (5 charged)
- **14 North Korean nationals** - Fraudulent IT employment scheme
- **Mikhail Matveev/Wazawaka** (Russian) - Charged by Russia (rare)
- **USDoD** (hacker) - Arrested in Brazil

---

## Recommended Controls (CIS Critical Security Controls)

### Top Priority Areas

**Account Management [5]**
- Inventory accounts
- Disable dormant accounts
- Restrict admin privileges

**Access Control [6]**
- MFA for externally-exposed applications
- MFA for remote network access
- Access granting/revoking processes

**Vulnerability Management [7]**
- Establish vulnerability management process
- Establish remediation process
- Automated patch management
- Prioritize edge devices and internet-facing assets

**Data Protection [3]**
- Data management process
- Data inventory
- Data access control
- Segmentation based on sensitivity
- DLP solutions

**Security Awareness Training [14]**
- Regular phishing simulations
- Focus on reporting suspicious activity
- BEC awareness
- Data handling best practices

**Malware Defenses [10]**
- Deploy anti-malware
- Automatic signature updates

**Incident Response [17]**
- Designate incident handlers
- Establish reporting contacts
- Enterprise incident reporting process

---

## Emerging Threats

### AI/GenAI Risks
- **Malicious AI use** by state actors confirmed (OpenAI, Google reports)
- **Synthetically generated phishing emails** doubled
- **Data leakage to GenAI platforms**
- **DeepSeek model** leaked chat history (January 2025)
- **Mobile device OS integration** creating new attack surface

### New Attack Techniques
- **Prompt bombing** - MFA fatigue
- **LLMjacking** - Compromised cloud credentials to abuse LLMs
- **FakeCall malware** - Advanced vishing, call interception
- **Mamba 2FA** - Phishing-as-a-Service platform
- **Violence as a service** - Cyber + physical threats combined

### IoT & Edge Computing
- **Compromised ASUS routers** in DDoS attacks
- **Edge device vulnerabilities** exploited at scale
- **BYOD risks** amplified by new technologies

---

## Key Recommendations Summary

1. **Patch edge devices immediately** - Median 0-day to exploit
2. **Enforce MFA everywhere** - Especially for third-party services
3. **Monitor for stolen credentials** - 54% of ransomware victims had credentials in infostealer logs
4. **Vet third-party vendors** - 30% breach involvement
5. **Implement network segmentation** - Limit lateral movement
6. **Focus on detection, not just prevention** - Assume credentials may be compromised
7. **Train employees continuously** - Focus on reporting, not just click prevention
8. **Secure code repositories** - 94-day median to remediate leaked secrets
9. **Plan for ransomware** - Have offline backups, don't assume you won't be hit
10. **Collaborate with law enforcement** - Essential for disruption operations

---

## Conclusion

The 2025 DBIR reveals a threat landscape dominated by opportunistic ransomware attacks, sophisticated state-sponsored espionage, and the growing complexity of third-party risk. Attackers are increasingly exploiting edge device vulnerabilities and stolen credentials at scale, with median time-to-exploit measured in days or hours. Small businesses face disproportionate ransomware impact, while all organizations must contend with the expanding attack surface created by cloud services, supply chain dependencies, and emerging technologies like GenAI. Effective defense requires rapid patching, strong authentication, continuous monitoring, and collaboration between private sector and law enforcement.
