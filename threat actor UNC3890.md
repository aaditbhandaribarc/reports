### **1. Attacker Name or Attacker Group Name**

UNC3890

### **2. APT Name**

The report does not assign a specific APT name. UNC3890 is an uncategorized threat actor, but Mandiant assesses with moderate confidence that it is an Iran-nexus group. It is noted to have connections to other Iranian clusters of activity, such as UNC2448 (linked to APT35/Charming Kitten and the IRGC).

### **3. Exploited Vulnerability Number and its Short Description**

The report does not mention the exploitation of a specific CVE-numbered vulnerability. The actor's initial access relies on social engineering, credential harvesting, and a watering hole attack rather than exploiting a specific software flaw.

### **4. Target Country, Organization, Sector etc. Name**

*   **Target Country:** Israel
*   **Target Sectors:**
    *   Shipping (primary focus)
    *   Government
    *   Energy
    *   Healthcare
    *   Aviation
*   **Targeted Entities:** While the focus is on Israel, some targeted entities, particularly in the shipping sector, are global companies.

### **5. IOCs (Indicators of Compromise)**

**Malware Families:**
*   **SUGARUSH:** A custom backdoor that establishes a reverse shell over TCP.
*   **SUGARDUMP:** A credential harvesting utility for Chromium-based browsers.
*   **METASPLOIT:** Publicly available penetration testing framework.
*   **NORTHSTAR C2:** Open-source C2 framework.

**MD5 Hashes:**
*   **SUGARDUMP (early versions):**
    *   `f362a2d9194a09eaca7d2fa04d89e1e5`
    *   `08dc5c2af21ecee6f2b25ebdd02a9079`
*   **SUGARDUMP (SMTP dropper):** `ae0a16b6feddd53d1d52ff50d85a42d5`
*   **SUGARDUMP (SMTP payload):** `084ad50044d6650f9ed314e99351a608`
*   **SUGARDUMP (SMTP lure video):** `d8fb3b6f5681cf5eec2b89be9b632b05`
*   **SUGARDUMP (HTTP lure):** `639f83fa4265ddbb43e85b763fe3dbac`
*   **SUGARUSH:**
    *   `37bdb9ea33b2fe621587c887f6fb2989`
    *   `3f045ebb014d859a4e7d15a4cf827957`
    *   `a7a2d6a533b913bc50d14e91bcf6c716`
    *   `d528e96271e791fab5818c01d4bc139f`
*   **PowerShell Downloaders:**
    *   `d5671df2af6478ac108e92ba596d5557`
    *   `2a09c5d85667334d9accbd0e06ae9418`
    *   `c5116a9818dcd48b8e9fb1ddf022df29`
*   **METASPLOIT Payloads:**
    *   `fcc09a4262b9ca899ba08150e287caa9`
    *   `d47bbec805c00a549ab364d20a884519`
    *   `6dbd612bbc7986cf8beb9984b473330a`
    *   `3b2a719ffb12a291acbfe9056daf52a7`
    *   `f97c0f19e84c79e9423b4420531f5a25`
*   **NORTHSTAR C2 Stager:** `2fe42c52826787e24ea81c17303484f9`
*   **Other Tools:**
    *   `f538cb2e584116a586a50d607d517cfd` (UNICORN)
    *   `532f5c8a85b706ccc317b9d4158014bf` (PowerShell TCP ReverseShell)

**IP Addresses:**
*   `143.110.155[.]195` (NorthStar C2 server)
*   `128.199.6[.]246` (Malware hosting, Watering Hole C2, Fake Login Pages)
*   `161.35.123[.]176` (SUGARUSH C2, Reverse Shell C2, Malicious Domains)
*   `104.237.155[.]129` (C2 server)
*   `146.185.219[.]88` (C2 server)
*   `159.223.164[.]185` (C2 server)
*   `144.202.123[.]248` (C2 server)

**Domains:**
*   `lirikedin[.]com` (xn--lirkedin-vkb[.]com)
*   `pfizerpoll[.]com`
*   `fileupload[.]shop`
*   `celebritylife[.]news`
*   `naturaldolls[.]store`
*   `xxx-doll[.]com`
*   `office365update[.]live`
*   `rnfacebook[.]com`
*   `aspiremovecentraldays[.]net` (suspect)

### **6. Attack Tactics, Techniques, and Procedure Names (MITRE ATT&CK)**

*   **Resource Development:**
    *   **T1587.001 - Develop Capabilities: Malware**
    *   **T1588.002 - Obtain Capabilities: Tool**
*   **Initial Access:**
    *   **T1566.002 - Phishing: Spearphishing Link**
    *   **T1189 - Drive-by Compromise (Watering Hole)**
*   **Execution:**
    *   **T1053 - Scheduled Task/Job**
    *   **T1059.003 - Command and Scripting Interpreter: Windows Command Shell**
    *   **T1569.002 - System Services: Service Execution**
    *   **T1204.002 - User Execution: Malicious File**
*   **Persistence:**
    *   **T1053.005 - Scheduled Task/Job: Scheduled Task**
    *   **T1543.003 - Create or Modify System Process: Windows Service**
*   **Credential Access:**
    *   **T1555.003 - Credentials from Password Stores: Credentials from Web Browsers**
    *   **T1056.001 - Input Capture: Keylogging**
    *   **T1056.003 - Input Capture: Web Portal Capture**
*   **Command and Control:**
    *   **T1102.002 - Web Service: Bidirectional Communication**
    *   **T1572 - Protocol Tunneling**
*   **Exfiltration:**
    *   **T1041 - Exfiltration Over C2 Channel**
    *   **T1567 - Exfiltration Over Web Service**

### **7. Short Summary of Entire Content**

Mandiant has been tracking UNC3890, a suspected Iranian espionage group active since at least late 2020. The group primarily targets Israeli organizations in the shipping, government, energy, and healthcare sectors. Their methods include social engineering with fake job offers and commercials for robotic dolls, as well as a watering hole attack on an Israeli shipping company's login page. UNC3890 uses custom malware, including the `SUGARUSH` backdoor and the `SUGARDUMP` credential stealer, alongside public tools like METASPLOIT and NorthStar C2. A unique characteristic is their exfiltration of stolen data via legitimate email services like Gmail, Yahoo, and Yandex, likely to evade detection. Technical evidence, such as Farsi words in malware strings and shared PDB paths with other IRGC-linked actors, supports the attribution to Iran.

### **8. Recommendation or Recommended Actions**

The report does not provide a specific list of recommendations, but based on the TTPs, organizations should:
*   Implement robust email security to detect and block phishing lures.
*   Train employees to identify social engineering attempts, including fake job offers and suspicious login pages.
*   Monitor for and restrict the use of unauthorized software and tools like METASPLOIT.
*   Enforce strong credential policies and multi-factor authentication to mitigate the impact of credential theft.
*   Monitor network traffic for unusual outbound connections, especially to known malicious infrastructure and via non-standard protocols or services like SMTP to public email providers.

### **9. Detection Techniques**

*   Monitor for network connections to the IOCs (IPs and domains) listed above.
*   Scan endpoints for files matching the provided MD5 hashes.
*   Look for the creation of new services named "Service1" or scheduled tasks like "MicrosoftInternetExplorerCrashRepoeterTaskMachineUA".
*   Inspect for suspicious POST requests from legitimate login pages to unknown domains, which could indicate a watering hole.
*   Monitor for unusual email traffic from servers or endpoints to external providers like Yandex, Yahoo, and Gmail, especially via SMTP on port 587.

### **10. Prevention Techniques**

*   Block access to known malicious domains and IP addresses at the network perimeter.
*   Use endpoint protection to prevent the execution of known malicious files.
*   Implement security awareness training focused on phishing and social engineering.
*   Secure web browsers to prevent credential theft.
*   Restrict the ability of users to install and run unauthorized applications.

### **11. YARA Rules**

No YARA rules are provided in the report.

### **12. Sigma Rules**

No Sigma rules are provided in the report.
