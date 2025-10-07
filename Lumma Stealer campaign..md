### **1. Attacker Name or Attacker Group Name**

The report attributes the campaign to an **unnamed threat actor**. CrowdStrike Intelligence assesses with moderate confidence that this activity is linked to the same actor behind a June 2024 opportunistic spam flood and voice phishing (vishing) campaign, based on shared C2 infrastructure.

### **2. APT Name**

There is no specific APT (Advanced Persistent Threat) group name mentioned or attributed to this campaign in the document.

### **3. Exploited Vulnerability Number and its Short Description**

The campaign does not exploit a specific CVE-numbered vulnerability. Instead, it uses a **social engineering lure** based on a recent, legitimate security event. The phishing campaign was initiated on July 23, 2024, shortly after July 19, 2024, when CrowdStrike identified and fixed an issue in a content update for its Falcon sensor that impacted Windows operating systems. The attackers capitalized on this event to create a believable pretext for their malicious "update."

### **4. Target Country, Organization, Sector etc. Name**

The campaign appears to target **corporate networks** and **CrowdStrike customers**. The use of a phishing domain impersonating CrowdStrike and the link to a previous campaign that targeted corporate networks suggest a focus on enterprise environments. The "Additional Resources" section also links to an operation targeting **LATAM-Based CrowdStrike Customers**.

### **5. IOCs (Indicators of Compromise)**

**Phishing Domains:**
*   `crowdstrike-office365[.]com`
*   `go.microsoft.crowdstrike-office365[.]com`

**Command-and-Control (C2) Infrastructure:**
*   `iiaiyitre[.]pa`
*   `indexterityszcoxp[.]shop`
*   `lariatedzugspd[.]shop`
*   `callosallsaospz[.]shop`
*   `outpointsozp[.]shop`
*   `liernessfornicsa[.]shop`
*   `upknittsoappz[.]shop`
*   `shepherdlyopzc[.]shop`
*   `unseaffarignsk[.]shop`
*   `warrantelespsz[.]shop`

**File Hashes (SHA256):**
*   **Lumma Stealer Payload:**
    *   `d669078a7cdcf71fb3f2c077d43f7f9c9fdbdb9af6f4d454d23a718c6286302a`
*   **MSI Loader / Installers:**
    *   `c3e50ca693f88678d1a6e05c870f605d18ad2ce5cfec6064b7b2fe81716d40b0` (plenrco.exe, self-extracting archive)
    *   `c1e27b2e7db4fba9f011317ff86b0d638fe720b945e933b286bb3cf6cdb60b6f` (SymposiumTaiwan.exe, NSIS installer)
    *   `1e06ef09d9e487fd54dbb70784898bff5c3ee25d87f468c9c5d0dfb8948fb45c`
    *   `e9cd2429628e3955dd1f7c714fbaa3e3b85bfaac0bc31582cf9c5232cb8fc352`
    *   `bb7a19963b422ed31b0b942eeaad7388421bc270a8513337f8ec043a84a4f11c`
    *   `aca54f9f5398342566e02470854aff48c53659be0c0cb83d3ce1fd05430375f8`
    *   `3ed535bbcd9d4980ec8bc60cd64804e9c9617b7d88723d3b05e6ad35821c3fe7`
*   **CypherIt AutoIt Loader Script:**
    *   `2856b7d3948dfb5231056e52437257757839880732849c2e2a35de3103c64768`
*   **Batch Script Loader in NSIS Installer:**
    *   `6217436a326d1abcd78a838d60ab5de1fee8a62cda9f0d49116f9c36dc29d6fa`
*   **Associated ZIP/RAR Files:**
    *   `922b1f00115dfac831078bb5e5571640e95dbd0d6d4022186e5aa4165082c6b2`
    *   `56f2aedb86d26da157b178203cec09faff26e659f6f2be916597c9dd4825d69f`
    *   `e6b00ee585b008f110829df68c01a62d3bfac1ffe7d65298c8a4e4109b8a7319`
    *   `b5c0610bc01cfc3dafc9c976cb00fe7240430f0d03ec5e112a0b3f153f93b49a`
    *   `280900902df7bb855b27614884b369e5e0da25ff22efacc59443a4f593ccd145`
    *   `a992cee863a4668698af92b4f9bd427d7a827996bf09824b89beff21578b49bd`

### **6. Attack Tactics, Techniques, and Procedures (TTPs)**

The campaign employs a multi-stage infection chain using the following TTPs:

*   **Initial Access:**
    *   **Phishing:** Uses a lure based on a legitimate CrowdStrike Falcon sensor update, delivered from the domain `crowdstrike-office365[.]com`.
*   **Execution:**
    *   **T1204 - User Execution:** The user is tricked into running a malicious Microsoft Installer (MSI) file disguised as a legitimate update.
    *   **Scripting Interpreter: Windows Command Shell:** A batch script is used to run the AutoIt executable.
*   **Defense Evasion:**
    *   **T1027.002 - Obfuscated Files or Information: Software Packing:** The final payload, **Lumma Stealer**, is packed using the **CypherIt** packer/loader.
    *   **Heavily Obfuscated AutoIt Script:** The CypherIt loader uses string obfuscation to hinder static analysis.
    *   **Anti-Analysis Checks:** The AutoIt loader checks for specific hostnames (`tz`, `NfZtFbPfH`, `ELICZ`), the username `test22`, the presence of a sandbox file (`C:\aaa_TouchMeNot_.txt`), and running AV processes (`avastui.exe`, `bdagent.exe`) before proceeding.
*   **Collection & Exfiltration:**
    *   **T1041 - Exfiltration Over C2 Channel:** Lumma Stealer collects browser credentials, cookies, and autofill data and sends it to its C2 server.

### **7. Short Summary**

On July 23, 2024, CrowdStrike Intelligence identified a phishing campaign distributing the **Lumma Stealer** information-stealing malware. The threat actor registered the domain `crowdstrike-office365[.]com` to impersonate CrowdStrike, luring victims with a fake Falcon sensor update. The initial payload is a Microsoft Installer (MSI) file that executes a series of self-extracting archives and installers. The final stage uses a heavily obfuscated AutoIt script loader, **CypherIt**, to decrypt and run Lumma Stealer. The campaign employs anti-analysis techniques to evade detection and is linked to a previous June 2024 campaign that used spam and vishing, indicating a persistent threat actor targeting corporate environments.

### **8. Recommendations / Recommended Actions**

*   Only accept software updates delivered through official CrowdStrike channels and follow the support team's technical guidance.
*   Train users to avoid executing files from untrusted or unsolicited sources.
*   Instruct users to check website certificates on download pages to verify the software's origin.
*   Use browser settings to enable download protection, which can warn about potentially harmful websites or downloads.
*   Consider blocking AutoIt executables (`.exe`, `.pif`) in the corporate environment if they are not required for business operations.

### **9. Detection Techniques**

A **Falcon LogScale Query** is provided to detect the activity described in the report. The query hunts for specific SHA256 hashes and domain names associated with the campaign.

### **10. Prevention Techniques**

Prevention relies on a combination of technical controls and user awareness, as outlined in the recommendations:
*   **Technical Controls:** Strict software deployment policies, browser security settings, and blocking unnecessary applications like AutoIt.
*   **User Awareness Training:** Educating users on phishing tactics, verifying software sources, and the risks of executing unknown files.

### **11. YARA Rules**

The document does not contain any YARA rules.

### **12. Sigma Rules**

The document does not contain any Sigma rules.
