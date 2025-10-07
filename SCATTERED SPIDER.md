### **1. Attacker Name or Attacker Group Name**

SCATTERED SPIDER

### **2. APT Name**

The report identifies the group as SCATTERED SPIDER. No specific APT designation is provided.

### **3. Exploited Vulnerability Number and its Short Description**

*   **CVE-2015-2291:** This is a vulnerability in the Intel Ethernet diagnostics driver for Windows (`iqvw64.sys`). The adversary exploits this legitimately signed but vulnerable driver to load their own malicious, unsigned kernel driver into the Windows kernel. This technique is known as Bring-Your-Own-Vulnerable-Driver (BYOVD).

### **4. Target Country, Organization, Sector etc. Name**

*   **Target Sectors:** Telecommunications (telecom) and Business Process Outsourcing (BPO).
*   **End Objective:** To gain access to mobile carrier networks.

### **5. IOCs (Indicators of Compromise)**

**File Hashes (SHA256):**
*   `b6e82a4e6d8b715588bf4252f896e40b766ef981d941d0968f29a3a444f68fef` (Malicious 64-bit Windows kernel driver)

**Vulnerable Driver:**
*   **Filename:** `iqvw64.sys` (Intel Ethernet diagnostics driver)

**Malicious Driver Signing Certificate Information:**
*   **Stolen Certificate:**
    *   **Issued To:** Global Software, LLC
    *   **Serial Number:** `31 11 00 fb 8d ee 5e 09 37 6b 69 a8 f6 23 e0 ee`
    *   **Validity:** 2018-05-14 to 2021-06-18
*   **Self-Signed Test Certificate:**
    *   **Serial Number:** `23 43 9d 9d d3 2a a7 b2 4b bb 6e 31 64 fb 47 53`
    *   **Validity:** Ends 2032-12-23

### **6. Attack Tactics, Techniques, and Procedure Names (MITRE ATT&CK)**

The adversary employs several TTPs to bypass endpoint security:

*   **Defense Evasion (TA0005):**
    *   **T1562.001 - Impair Defenses: Disable or Modify Tools:** The primary goal of the malicious driver is to disable endpoint security products, including CrowdStrike Falcon, Microsoft Defender for Endpoint, Palo Alto Networks Cortex XDR, and SentinelOne.
    *   **T1211 - Exploitation for Defense Evasion:** The core tactic involves using the Bring-Your-Own-Vulnerable-Driver (BYOVD) method to bypass Windows kernel protections and load a malicious driver.
    *   The malicious driver patches the target security product's driver (`csagent.sys`) in memory at hard-coded offsets to neutralize its functionality.
*   **Persistence (TA0003) & Privilege Escalation (TA0004):**
    *   **T1068 - Exploitation for Privilege Escalation:** By loading a driver into the kernel via the vulnerable `iqvw64.sys`, the adversary escalates privileges to kernel level.
*   **Initial Access:**
    *   The report references a previous campaign where the actor used multifactor authentication (MFA) notification fatigue tactics.

### **7. Short Summary of Entire Content**

The threat actor SCATTERED SPIDER is conducting campaigns targeting telecommunications and BPO sectors to access mobile carrier networks. They are using a "Bring-Your-Own-Vulnerable-Driver" (BYOVD) tactic to bypass endpoint security products. Specifically, they exploit a known vulnerability (CVE-2015-2291) in a legitimate, signed Intel driver (`iqvw64.sys`) to load their own malicious kernel driver. This driver, signed with stolen or self-signed certificates, is designed to find and patch the kernel components of security products like CrowdStrike Falcon (`csagent.sys`), effectively disabling them. This allows the adversary to proceed with their objectives undetected.

### **8. Recommendation or Recommended Actions**

*   **Patch Vulnerable Drivers:** Prioritize patching the vulnerable Intel Ethernet Driver (CVE-2015-2291) to close the initial vector for the BYOVD attack. Use vulnerability management tools like Falcon Spotlight to identify hosts with this driver.
*   **Enable Memory Integrity:** Evaluate and enable Microsoft's Hypervisor-Protected Code Integrity (HVCI), a component of Virtualization-Based Security (VBS), to prevent unauthorized code and drivers from being loaded into the kernel.
*   **Harden Authentication:** Implement additional scrutiny for legitimate login activity and require two-factor authentication for approvals originating from unexpected assets, accounts, or locations.

### **9. Detection Techniques**

*   **Endpoint Detection and Response (EDR):** The CrowdStrike Falcon platform is capable of detecting and preventing the attempt to load the malicious kernel driver.
*   **Vulnerability Scanning:** Use tools like Falcon Spotlight to scan for the presence of the vulnerable `iqvw64.sys` driver across the environment.
*   **Configuration Auditing:** Monitor the status of HVCI across endpoints using tools like Falcon Insight XDR's Zero Trust Assessment dashboard.

### **10. Prevention Techniques**

*   **Enable Sensor Tampering Protection:** This feature must be enabled in the endpoint protection policy to prevent adversaries from disabling or modifying the security agent.
*   **Configure Anti-Malware Policies:** Set both the Cloud Anti-malware and Sensor Anti-malware prevention sliders to "Moderate" or higher.
*   **Patch Management:** Maintain a rigorous patch management program to address known vulnerabilities in drivers and software.
*   **Enable HVCI:** Deploy Hypervisor-Protected Code Integrity to enforce kernel memory protections and block this class of attack.

### **11. YARA Rules**

No YARA rules are provided in the report.

### **12. Sigma Rules**

No Sigma rules are provided in the report.
