### **1. Attacker Name or Attacker Group Name**

IMPERIAL KITTEN

### **2. APT Name**

IMPERIAL KITTEN is the designated name for this adversary. It is noted to have a connection to the Islamic Revolutionary Guard Corps (IRGC) and has been active since at least 2017.

### **3. Exploited Vulnerability Number and its Short Description**

The group does not rely on a single, specific vulnerability. Their initial access methods are varied and include:
*   **One-day exploits:** Exploiting recently disclosed vulnerabilities before patches are widely applied.
*   **SQL Injection:** Injecting malicious SQL code to manipulate backend databases and gain unauthorized access.
*   **Stolen VPN credentials:** Using compromised credentials to bypass perimeter defenses and access internal networks.

### **4. Target Country, Organization, Sector etc. Name**

*   **Target Region:** Middle East
*   **Target Country:** Primarily Israel
*   **Target Sectors:**
    *   Transportation
    *   Logistics
    *   Technology
    *   Maritime
    *   Defense
    *   Telecommunications
    *   Energy
    *   Consulting and Professional Services

### **5. IOCs (Indicators of Compromise)**

**Domains (SWC Infrastructure):**
*   `cdn.jguery[.]org`
*   `cdn-analytics[.]co`
*   `jquery-cdn[.]online`
*   `jquery-stack[.]online`
*   `cdnpakage[.]com`
*   `fastanalizer[.]live`
*   `fastanalytics[.]live`
*   `hotjar[.]info`
*   `jquery-code-download[.]online`
*   `analytics-service[.]cloud`
*   `analytics-service[.]online`
*   `prostatistics[.]live`
*   `blackcrocodil[.]online`
*   `updatenewnet[.]com`

**IP Addresses:**
*   `146[.]185[.]219[.]220`
*   `193[.]182[.]144[.]12`
*   `194[.]62[.]42[.]98`
*   `64[.]176[.]165[.]70`
*   `95[.]164[.]61[.]253`
*   `95[.]164[.]61[.]254`
*   `45[.]155[.]37[.]105`
*   `64[.]176[.]165[.]229`
*   `193[.]182[.]144[.]175`
*   `103[.]105[.]49[.]108`
*   `149[.]248[.]54[.]40`

**File Hashes (SHA256):**
*   **Macro-enabled Excel Lure:**
    *   `b588058e831d3a8a6c5983b30fc8d8aa5a711b5dfe9a7e816fe0307567073aed`
*   **Python Reverse Shell Payload:**
    *   `cc7120942edde86e480a961fceff66783e71958684ad1307ffbe0e97070fd4fd`
*   **IMAPLoader Samples:**
    *   `b7a7e9eeec8e4635e96f6c30950f4fbdcd2bba336`
    *   `5c945a2be61f1f86da618a6225bc9d84f05f2c836b8432415ff5cc13534cfe2e`
    *   `87ccd1c15adc9ba952a07cd89295e0411b72cd4653b168f9b3f26c7a88d19b91`
*   **StandardKeyboard Sample (WindowsServiceLive.exe):**
    *   `d3677394cb45b0eb7a7f563d2032088a8a10e12048ad74bae5fd9482f0aead01`
*   **Discord C2 Malware (Final Stage):**
    *   `3bba5e32f142ed1c2f9d763765e9395db5e42afe8d0a4a372f1f429118b71446`

**Email Addresses (C2):**
*   `noah.harrison@yandex[.]com`
*   `giorgosgreen@yandex[.]com`
*   `oliv.morris@yandex[.]com`
*   `harri5on.patricia@yandex[.]com`
*   `d3nisharris@yandex[.]com`
*   `hardi.lorel@yandex[.]com`
*   `itdep@update-platform-check[.]online`
*   `office@update-platform-check[.]online`

### **6. Attack Tactics, Techniques, and Procedure Names (MITRE ATT&CK)**

*   **Resource Development:**
    *   **T1584 - Infrastructure: Web Services:** Use of compromised websites for strategic web compromise (SWC) operations.
*   **Initial Access:**
    *   **T1189 - Drive-by Compromise:** Luring victims to adversary-controlled sites (SWC) to serve malware.
    *   **T1190 - Exploit Public-Facing Application:** Use of one-day exploits.
    *   **T1199 - Phishing:** Delivering malicious Microsoft Excel documents.
*   **Execution:**
    *   **T1059.003 - Command and Scripting Interpreter: Windows Command Shell:** `IMAPLoader` collects system information via `cmd.exe`.
    *   **T1059.005 - Command and Scripting Interpreter: Visual Basic:** Malicious VBS scripts in Excel documents install a Python backconnect shell.
    *   **T1059.006 - Command and Scripting Interpreter: Python:** Malicious Excel documents drop a Python-based backconnect shell.
*   **Persistence:**
    *   **T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder:** `IMAPLoader` persists through the registry Run key.
*   **Defense Evasion:**
    *   **T1055 - Process Injection:** `IMAPLoader` executes via AppDomain Manager injection.
    *   **T1140 - Deobfuscate/Decode Files or Information:** `IMAPLoader` and `SUGARRUSH` obfuscate C2 addresses.
*   **Discovery:**
    *   **T1518.001 - Software Discovery: Security Software Discovery:** `IMAPLoader` enumerates installed antivirus software.
*   **Collection:**
    *   **T1005 - Data from Local System:** `IMAPLoader` beacons local system configuration and username to C2.
*   **Command and Control:**
    *   **T1071.003 - Application Layer Protocol: Mail Protocols:** `IMAPLoader`, `StandardKeyboard`, and `SUGARRUSH` use email (IMAP) for C2 communications.

### **7. Short Summary of Entire Content**

CrowdStrike has attributed a series of strategic web compromise (SWC) and phishing campaigns targeting the transportation, logistics, and technology sectors in the Middle East, particularly Israel, to the Iran-linked adversary IMPERIAL KITTEN. Active since at least 2017, the group uses a variety of initial access techniques including one-day exploits, SQL injection, and stolen VPN credentials. The investigation uncovered novel malware families, including `IMAPLoader` and `StandardKeyboard`, which use email (specifically IMAP over Yandex) for command and control. These tools are used for data exfiltration, credential theft, and maintaining persistence. The campaign leverages job-themed lures and malicious Excel documents to deliver a Python-based reverse shell, demonstrating a continued evolution of the adversary's TTPs.

### **8. Recommendation or Recommended Actions**

While the document does not provide a specific list of recommendations, the described TTPs imply the need for:
*   Timely patching of public-facing applications to mitigate one-day exploits.
*   Implementation of robust security for web applications to prevent SQL injection.
*   Enforcing strong multi-factor authentication (MFA) on VPNs and other remote access solutions.
*   User awareness training to recognize and report phishing attempts.
*   Monitoring and blocking suspicious email traffic to known malicious C2 domains.

### **9. Detection Techniques**

Detection can be achieved by:
*   Monitoring for network connections to the IOCs listed above (IPs and domains).
*   Searching for the presence of the specified file hashes on endpoints.
*   Inspecting registry run keys for persistence mechanisms like `StandardPS2Key`.
*   Analyzing network traffic for IMAP communications with unusual patterns or destinations (e.g., `imap.yandex[.]com`).

### **10. Prevention Techniques**

Prevention strategies include:
*   Disabling macros in Microsoft Office documents received from external sources.
*   Implementing application whitelisting to prevent the execution of unauthorized interpreters like Python or tools like PAExec.
*   Hardening endpoints to prevent credential theft from memory (e.g., LSASS protection).
*   Using a web application firewall (WAF) to protect against SQL injection and other web-based attacks.

### **11. YARA Rules**

The document does not contain any YARA rules.

### **12. Sigma Rules**

The document does not contain any Sigma rules.
