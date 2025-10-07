# CrowdStrike 2025 Global Threat Report
Report Link: https://go.crowdstrike.com/rs/281-OBQ-266/images/CrowdStrikeGlobalThreatReport2025.pdf?version=0
### 1. Attacker name/ Group name
The report uses CrowdStrike's naming convention (e.g., SPIDER for eCrime, PANDA for China-nexus, CHOLLIMA for DPRK-nexus). Specific adversaries mentioned include:
*   **eCrime Adversaries:**
    *   **CURLY SPIDER:** A fast and adaptive eCrime actor specializing in high-speed, hands-on intrusions via social engineering.
    *   **WANDERING SPIDER:** The group behind the Black Basta ransomware, known to collaborate with CURLY SPIDER.
    *   **SCATTERED SPIDER:** A prolific eCrime actor known for help desk social engineering and targeting cloud environments.
    *   **CHATTY SPIDER:** A Russia-based eCrime adversary using callback phishing for data theft and extortion.
    *   **PLUMP SPIDER:** A Brazil-based eCrime adversary using vishing to conduct wire fraud.
    *   **NITRO SPIDER:** An eCrime actor using malvertising and LLM-generated decoy sites.
    *   **APT INC:** A Big Game Hunting (BGH) ransomware operator.
*   **Nation-State Adversaries:**
    *   **FAMOUS CHOLLIMA (DPRK/North Korea):** Innovated currency generation operations using large-scale IT worker schemes and insider threats.
    *   **LABYRINTH CHOLLIMA, VELVET CHOLLIMA, SILENT CHOLLIMA (DPRK/North Korea):** Consistently targeted defense and aerospace entities.
    *   **China-Nexus Adversaries (PANDA):** Activity surged 150%. Seven new groups were named, including:
        *   **LIMINAL PANDA:** Targets telecommunications networks.
        *   **LOCKSMITH PANDA:** Targets technology, gaming, and energy in Taiwan and Indonesia.
        *   **OPERATOR PANDA:** Targets telecom and professional services, exploiting internet-facing appliances.
        *   **VAULT PANDA:** Targets the financial services sector.
        *   **ENVOY PANDA:** Targets government entities in Africa and the Middle East.
    *   **Green Cicada (China-aligned):** An Information Operations (IO) network using LLMs for disinformation.
    *   **FANCY BEAR (Russia):** Leveraged a Microsoft Outlook vulnerability.
*   **Other Adversaries:**
    *   **COMRADE SAIGA (Kazakhstan):** A newly named adversary.

### 2. APT Name
The report does not heavily use standard "APT" naming but does mention **FANCY BEAR**, which is a well-known alias for **APT28**. The primary naming convention is CrowdStrike's own (BEAR for Russia, PANDA for China, etc.).

### 3. Exploited vulnerability and it's short description
The report emphasizes vulnerability chaining and exploiting proprietary operating systems on network appliances. Specific vulnerabilities mentioned include:
*   **GlobalProtect PAN-OS Gateway (CVE-2024-3400):** An unattributed threat actor likely used Generative AI to develop an alleged (but ineffective) command injection exploit for this vulnerability.
*   **Palo Alto Networks PAN-OS (CVE-2024-0012 & CVE-2024-9474):** An authentication bypass and a privilege escalation vulnerability were chained by threat actors.
*   **Cisco IOS (CVE-2023-20198 & CVE-2023-20273):** A privilege escalation and a command injection vulnerability were likely chained by OPERATOR PANDA to target U.S. telecom entities.
*   **Microsoft Outlook (CVE-2023-23397, CVE-2023-29324, CVE-2023-35384):** A series of vulnerabilities and subsequent bypasses in Outlook, exploited by FANCY BEAR, that allow an attacker to trigger an authentication attempt to an attacker-controlled server.
*   **Windows mskssrv driver (CVE-2023-29360, CVE-2024-35250):** A series of local privilege escalation vulnerabilities that have become a focus for researchers and threat actors.

### 4. Target country, organization, sector name etc.
*   **Most Targeted Industries (Interactive Intrusions):**
    1.  Technology (23%)
    2.  Consulting and Professional Services (15%)
    3.  Manufacturing (12%)
    4.  Retail (11%)
    5.  Financial Services (10%)
*   **Geographical Targeting:**
    *   North America remains the most targeted region (53% of interactive intrusions).
    *   China-nexus actors targeted all sectors and regions globally, with a 200-300% increase in attacks on financial services, media, manufacturing, and engineering.
    *   FAMOUS CHOLLIMA (DPRK) targeted companies in North America, Western Europe, and East Asia for fraudulent employment.
*   **Specific Organizational Targets:**
    *   IT Help Desks are a primary target for social engineering attacks.
    *   Defense and Aerospace entities were consistently targeted by DPRK-nexus groups.

### 5. IOCs
The report is a high-level strategic overview and **does not contain** specific technical Indicators of Compromise (IOCs) like file hashes, IP addresses, or domains.

### 6. Attack Tactics, Techniques and Procedures
*   **Initial Access:**
    *   **Social Engineering:** A massive shift towards human-centric attacks. Vishing (voice phishing) attacks grew 442% in H2 2024.
    *   **Help Desk Social Engineering:** Impersonating employees to persuade IT help desk staff to reset passwords and MFA.
    *   **Callback Phishing:** Lure emails (e.g., fake invoices) prompt the victim to call a number, initiating a social engineering interaction.
    *   **Access Brokerage:** The business of selling initial access to networks is booming, with advertisements up 50% year-over-year.
*   **Lateral Movement & Execution:**
    *   **Malware-Free Attacks:** 79% of detections were malware-free, relying on hands-on-keyboard techniques and legitimate tools (e.g., RMM tools like Microsoft Quick Assist, PowerShell, curl).
    *   **Rapid Breakout Time:** The average time for an eCrime adversary to move laterally from initial compromise fell to just 48 minutes, with the fastest observed at 51 seconds.
    *   **Cloud-Conscious Tactics:** Abusing valid cloud accounts (35% of cloud incidents), exploiting cloud misconfigurations, and using cloud management tools for lateral movement.
*   **Defense Evasion & Persistence:**
    *   **Indicator Removal:** Deleting or modifying logs and emails to hide malicious activity.
    *   **Legitimate Tool Abuse:** Using trusted software like RMM tools to blend in with normal administrative activity.
    *   **Backdoor Accounts:** Creating new user accounts (as seen with CURLY SPIDER) to ensure persistent access.
*   **Use of Generative AI (GenAI):**
    *   **Social Engineering:** FAMOUS CHOLLIMA used GenAI to create fake LinkedIn profiles and plausible interview responses. Deepfake video and voice clones were used in BEC fraud.
    *   **Malicious Content Creation:** Used to generate content for spam campaigns (Snake Keylogger), destructive PowerShell scripts (APT INC), and decoy websites (NITRO SPIDER).

### 7. Short summary of entire content
The CrowdStrike 2025 Global Threat Report identifies the "enterprising adversary" as the central theme for 2024—threat actors are becoming more efficient, business-like, and innovative. A major trend is the dramatic shift from malware-based attacks to human-focused social engineering, with vishing and help desk impersonation skyrocketing. Consequently, 79% of observed intrusions were malware-free. Adversary speed has reached an all-time high, with the average eCrime "breakout time" dropping to 48 minutes. Nation-state activity also surged, with China-nexus intrusions increasing by 150%. North Korea's FAMOUS CHOLLIMA perfected a large-scale IT worker scheme to generate revenue and gain insider access. Generative AI has become a key tool for adversaries, used to enhance social engineering, create deepfakes for BEC fraud, and generate malicious content. The report emphasizes that adversaries are increasingly targeting identities and exploiting vulnerabilities in cloud and network perimeter devices.

### 8. Recommendation/ recommended actions
The report provides five main recommendations for defenders:
1.  **Secure the entire identity ecosystem:** Adopt phishing-resistant MFA (like hardware keys), enforce strong IAM policies, and use identity threat detection tools.
2.  **Eliminate cross-domain visibility gaps:** Modernize detection with XDR and next-gen SIEM to correlate suspicious behaviors across endpoints, cloud, and identity systems.
3.  **Defend the cloud as core infrastructure:** Use Cloud-Native Application Protection Platforms (CNAPPs) with cloud detection and response (CDR) to counter misconfigurations and stolen credential abuse.
4.  **Prioritize vulnerabilities with an adversary-centric approach:** Focus patching on critical internet-facing services (web servers, VPNs) and use exposure management tools to identify the vulnerabilities that matter most.
5.  **Know your adversary and be prepared:** Use threat intelligence to understand attacker TTPs, conduct user awareness training, and perform tabletop and red/blue team exercises.

### 9. Detection Techniques
*   **Real-time Threat Detection:** Essential to counter the rapid breakout times of modern adversaries.
*   **Proactive Threat Hunting:** Use intelligence-led hunting (like CrowdStrike OverWatch) to identify pre-attack behaviors and suspicious activity that evades automated defenses.
*   **User Behavior-Based Monitoring:** Implement solutions to detect anomalies in user activity, especially in SaaS and cloud environments.
*   **Cross-Domain Correlation:** Use XDR and next-gen SIEM platforms to connect disparate alerts from endpoints, cloud, and identity systems to see the full attack path.
*   **Monitoring for Social Engineering Indicators:** Monitor for unusual MFA reset requests (especially outside business hours) and multiple users registering the same device for MFA.

### 10. Prevention techniques
*   **Phishing-Resistant MFA:** Implement hardware-based FIDO2 devices (e.g., YubiKeys) or number matching to prevent MFA bypass.
*   **Strong Identity and Access Management (IAM):** Enforce strong password policies, implement least-privilege principles, and conduct regular audits of user permissions.
*   **User Education:** Train employees to recognize vishing, phishing, and other social engineering tactics. Train help desk staff to be cautious with reset requests and require stronger forms of identity verification (e.g., video authentication).
*   **Vulnerability Management:** Aggressively patch critical systems, especially internet-facing network appliances.
*   **Secure SaaS Configuration:** Regularly review and update SaaS application settings and disable unnecessary features or integrations.

### 11. Yara rules
The provided report **does not contain** any YARA rules.

### 12. Sigma rules
The provided report **does not contain** any Sigma rules.
