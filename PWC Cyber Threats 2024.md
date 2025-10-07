# PWC Cyber Threat 2024
Report Link: https://www.pwc.com/gx/en/cyber/cyber-threats-2024.pdf

### 1. Attacker name/ Group name
The report identifies numerous threat actors, either by their PwC designation or common industry names:
*   **Ransomware/Cybercrime Groups:**
    *   **LockBit 3.0** (also referred to as White Janus)
    *   **ALPH-V** (also known as BlackCat or White Dev 101)
    *   **DarkAngels** (RaaS operation)
    *   **Termite ransomware**
    *   **CLOP**
    *   **Scattered Spider** (also known as White Dev 164)
    *   **White Rabbit** (Ransomware)
    *   **Black Basta**
    *   **StealC** (Information stealer, developed by White Dev 183)
*   **Nation-State/Espionage Groups:**
    *   **Blue Dev 5** (Russia-based, also known as NOBELIUM, APT29)
    *   **Red Dev 49** (China-based, also known as Volt Typhoon)
    *   **Salt Typhoon** (China-based)
    *   **Yellow Garuda** (Iran-based)
    *   **Black Shoggoth** (North Korea-based, also known as APT37)
    *   **Blue Callisto** (Russia-based, also known as COLDRIVER)
    *   **Blue Athena** (Russia-based, also known as APT28, Forest Blizzard)
    *   **Blue Otso** (Russia-based, also known as Gamaredon Group)
    *   **Commercial Spyware Vendors:**
    *   **Grey Anqa** (NSO Group)
    *   **Grey Mazzikim** (Candiru)

### 2. APT Name
The report connects several of its tracked groups to common Advanced Persistent Threat (APT) designations:
*   **APT29:** An alias for the Russia-based group **Blue Dev 5** (NOBELIUM).
*   **APT37:** An alias for the North Korea-based group **Black Shoggoth**.
*   **APT28:** An alias for the Russia-based group **Blue Athena** (Fancy Bear, Forest Blizzard).
*   **APT35:** An alias for the Iran-based group **Yellow Garuda** (Charming Kitten).

### 3. Exploited vulnerability and it's short description
The report highlights a significant number of vulnerabilities exploited in 2024:
*   **Microsoft Defender SmartScreen (CVE-2024-21412, CVE-2024-2135):** Used to bypass the screening mechanisms of the SmartScreen technology.
*   **Ivanti Connect Security VPN (CVE-2023-46805, CVE-2024-21887):** Allowed attackers to bypass authentication and execute arbitrary commands.
*   **Fortra Go Anywhere MFT (CVE-2024-0204):** Allowed an unauthorized user to create an administrator account and execute remote code.
*   **Fortinet FortiOS RCE (CVE-2024-21762):** A remote code execution vulnerability that was exploited a day after its public disclosure.
*   **XZ Utils (CVE-2024-3094):** A zero-day vulnerability in a UNIX compression package that would allow unauthenticated remote access, inserted via a sophisticated social engineering campaign.
*   **Palo Alto GlobalProtect Gateway (CVE-2024-3400):** A zero-day vulnerability exploited against GlobalProtect technology.
*   **ESXi hypervisor (CVE-2024-37085):** A domain groups vulnerability leveraged by an affiliate of the Black Basta ransomware program.
*   **Windows Error Reporting Service (CVE-2024-26169):** An n-day vulnerability leveraged by an affiliate of the Black Basta ransomware.
*   **Internet Explorer (CVE-2024-38178):** A zero-day vulnerability in an Internet Explorer library used by the North Korea-based actor Black Shoggoth for initial access.
*   **Cleo FTP solution (CVE-2024-50623):** A vulnerability that was exploited even after an initial patch was released.
*   **Older, Patched Vulnerabilities:** The report notes that many attacks, particularly ransomware, exploited older vulnerabilities in edge devices like **Ivanti VPN Appliances, Oracle WebLogic Server, and FortiGate SSL**.

### 4. Target country, organization, sector name etc.
*   **Geopolitical Targeting:**
    *   **Ukraine and NATO-aligned countries:** Primary targets for Russia-based threat actors.
    *   **Israel:** A key focus for Iran-based threat actors.
    *   **Taiwan:** Targeted by China-based actors for espionage, focusing on defense and government institutions.
    *   **United States:** Targeted by various actors, including China (critical national infrastructure like energy and water), Iran (election influence), and North Korea (remote IT job fraud).
    *   **EU Governments:** Targeted for espionage by Russia-based actors.
    *   **German Politicians:** Targeted in a phishing campaign by a Russia-based actor.
*   **Sector Targeting:**
    *   **Critical National Infrastructure (CNI):** Energy, water, and telecommunications sectors were targeted by China-based actors.
    *   **Technology and Telecommunications:** Major US broadband providers were infiltrated by the "Salt Typhoon" group.
    *   **Government and Defense:** A consistent target for espionage-motivated actors from Russia, China, and North Korea.
    *   **Global Supply Chain:** Blue Yonder, a supply chain management company, was hit by ransomware, causing downstream disruption.

### 5. IOCs
The report is a strategic overview of cyber threats and trends. It **does not contain** any specific, tactical Indicators of Compromise (IOCs) such as file hashes, IP addresses, or malicious domains.

### 6. Attack Tactics, Techniques and Procedures
*   **Initial Access:**
    *   A significant shift away from phishing towards the **exploitation of vulnerabilities**, especially in public-facing edge devices (VPNs, firewalls).
    *   Use of **Initial Access Brokers (IABs)** to purchase previously obtained credentials.
    *   **Social engineering** by North Korean actors to obtain remote IT jobs, gaining insider access.
*   **Execution and Evasion:**
    *   Widespread adoption of **commercial proxy networks** by China-based actors to obfuscate their origin and hinder attribution.
    *   **Living-off-the-Land (LotL)** techniques, such as using native utilities like PowerShell, remain common for post-access activity.
    *   Use of **AI-driven tools** for creating more effective phishing kits and social engineering lures.
*   **Impact and Monetization:**
    *   **Ransomware-as-a-Service (RaaS)** remains a dominant model, with 2024 seeing the highest number of victims posted to leak sites.
    *   **"Big Game Hunting"** where ransomware groups target large, high-value organizations for massive payouts (e.g., the $75 million ransom paid to DarkAngels).
    *   **Disinformation and Influence Operations**, particularly by Russia and Iran-based actors, to influence narratives during elections.
*   **Infrastructure and Tooling:**
    *   Compromising the infrastructure of other threat actors to masquerade as them during operations.
    *   Use of credential stealers like **RedLine** and botnets like **Amadey** in the post-exploitation phase.

### 7. Short summary of entire content
The PwC "Cyber Threats 2024: A Year in Retrospect" report details a year characterized by an increase in emboldened cyber threat activity, driven by a volatile geopolitical landscape and the increased availability of advanced tools. Key trends include a major shift by sophisticated actors from phishing to exploiting vulnerabilities in edge devices for initial access, and the widespread use of commercial proxy networks by China-based actors to hide their tracks. The ransomware ecosystem was more active than ever, setting records for leak site victims despite law enforcement takedowns. North Korea pivoted from large-scale supply chain attacks to more traditional espionage and a novel campaign of securing remote IT jobs to gain insider access and funds. The report also highlights the growing role of AI in lowering the barrier for less sophisticated attackers and the use of disinformation campaigns by nation-states to influence global events.

### 8. Recommendation/ recommended actions
The report is analytical rather than prescriptive and does not have a formal recommendations section. However, it implies the following necessary actions for defenders:
*   **Improve Patch Management:** Prioritize patching of internet-facing "edge devices" like VPNs and firewalls, as these are primary targets. Do not neglect older, known vulnerabilities.
*   **Enhance Situational Awareness:** Understand that geopolitical tensions directly correlate with cyber threat activity and prepare defenses accordingly.
*   **Focus on Insider Threats:** Develop policies and detection mechanisms to counter the threat posed by insiders, highlighted by the North Korean IT worker campaign.
*   **Strengthen Network Defenses:** Implement intrusion prevention systems and conduct consistent log analysis of edge devices to detect compromises, especially from zero-day exploits.

### 9. Detection Techniques
The report does not specify detection techniques but notes that threat actor TTPs are making detection more difficult. For example:
*   The use of **commercial proxy networks** by China-based actors makes it challenging to identify the true source of an attack.
*   **Living-off-the-Land** techniques that abuse legitimate system tools are inherently harder to detect than custom malware.
*   The report implicitly highlights the need for **robust log analysis** and **behavioral monitoring** to spot anomalies.

### 10. Prevention techniques
The report implies several key prevention strategies:
*   **Vulnerability Management:** A robust and timely patching program is the most critical preventative measure against the most common initial access vector seen in 2024.
*   **Architectural Security:** Map the organization's entire network architecture to eliminate "shadow IT" and ensure all devices, especially on the perimeter, are secured and monitored.
*   **Supply Chain Security:** Vet third-party software and be aware of the risks associated with open-source dependencies.
*   **User Awareness and Vetting:** For organizations hiring remote workers, enhanced identity verification and background checks are crucial to prevent infiltration by actors posing as legitimate candidates.

### 11. Yara rules
The provided report **does not contain** any YARA rules.

### 12. Sigma rules
The provided report **does not contain** any Sigma rules.
