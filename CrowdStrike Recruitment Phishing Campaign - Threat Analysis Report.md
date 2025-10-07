# CrowdStrike Recruitment Phishing Campaign - Threat Analysis Report

**Report Date:** October 7, 2025  
**Incident Date:** January 7, 2025  
**Classification:** Phishing Campaign with Cryptomining Payload

---

## 1. Attacker Name or Attacker Group Name

**Unknown/Unattributed Threat Actor**

The threat actor behind this campaign has not been publicly attributed to any known cybercrime group. The campaign appears to be financially motivated, utilizing cryptomining operations.

---

## 2. APT Name

**Not Applicable**

This campaign does not appear to be associated with an Advanced Persistent Threat (APT) group. The attack is characterized as a financially motivated cybercrime operation rather than state-sponsored espionage.

---

## 3. Exploited Vulnerability Number and Short Description

**No CVE Vulnerabilities Exploited**

This campaign does not exploit technical vulnerabilities in software systems. Instead, it relies entirely on social engineering tactics targeting job seekers through:
- Brand impersonation of CrowdStrike recruitment
- Fraudulent employment offers
- Malicious downloads disguised as legitimate application software

---

## 4. Target Country, Organization, Sector, etc.

**Primary Targets:**
- **Sector:** Job seekers and professionals in the cybersecurity industry
- **Organization:** Individuals interested in CrowdStrike employment opportunities
- **Geographic Scope:** Global (not limited to specific countries)
- **Victim Profile:** Professionals responding to recruitment communications, particularly those in technical and cybersecurity roles

---

## 5. IOCs (Indicators of Compromise)

### Network Indicators

| Indicator | Type | Description |
|-----------|------|-------------|
| cscrm-hiring[.]com | Domain | Phishing site domain |
| https[:]//cscrm-hiring[.]com/cs-applicant-crm-installer[.]zip | URL | Malicious executable download URL |
| 93.115.172[.]41 | IP Address | Threat actor pool and data server |
| http[:]//93.115.172[.]41/private/aW5zdHJ1Y3Rpb25zCg==.txt | URL | XMRig configuration file |
| 93.115.172[.]41:1300 | IP:Port | Mining pool hosted by threat actor |

### File Hashes

| SHA-256 Hash | Description |
|--------------|-------------|
| 96558bd6be9bcd8d25aed03b996db893ed7563cf10304dffe6423905772bbfa1 | ZIP file containing fake CRM application |
| 62f3a21db99bcd45371ca4845c7296af81ce3ff6f0adcaee3f1698317dd4898b | Fake CRM application executable (Rust-based) |
| 7c370211602fcb54bc988c40feeb3c45ce249a8ac5f063b2eb5410a42adcc030 | XMRig configuration text file |

### Host-Based Indicators

| Path | Description |
|------|-------------|
| %TEMP%\System\temp.zip | Downloaded ZIP containing XMRig |
| %TEMP%\System\process.exe | Persistent copy of XMRig |
| %LOCALAPPDATA%\System32\config.exe | Persistent copy of fake CRM executable |
| %LOCALAPPDATA%\System32\process.exe | Persistent copy of XMRig |
| %APPDATA%\Microsoft\Windows\Start Menu\Programs\Maintenance\info.txt | Text file created by malware |
| %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\startup.bat | Persistent batch file |

### Registry Indicators

| Registry Path | Description |
|---------------|-------------|
| HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\config | Persistent autorun entry |

---

## 6. Attack Tactics, Techniques, and Procedures (TTPs)

### MITRE ATT&CK Framework Mapping

#### Initial Access
- **T1566.002 - Phishing: Spearphishing Link**
  - Phishing emails impersonating CrowdStrike recruitment
  - Links directing to malicious download site

#### Execution
- **T1204.002 - User Execution: Malicious File**
  - Victims manually execute downloaded fake application
- **T1059.003 - Command and Scripting Interpreter: Windows Command Shell**
  - Batch script execution for persistence

#### Defense Evasion
- **T1497.001 - Virtualization/Sandbox Evasion: System Checks**
  - Debugger detection using IsDebuggerPresent API
  - Minimum process count verification
  - CPU core count validation
  - Scanning for analysis/virtualization tools
- **T1036.005 - Masquerading: Match Legitimate Name or Location**
  - Fake error messages to appear legitimate
  - Impersonation of recruitment process

#### Persistence
- **T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys**
  - Registry autorun key creation
- **T1547.009 - Boot or Logon Autostart Execution: Shortcut Modification**
  - Startup folder batch script deployment

#### Resource Development
- **T1583.001 - Acquire Infrastructure: Domains**
  - Registration of cscrm-hiring[.]com domain
- **T1587.001 - Develop Capabilities: Malware**
  - Custom Rust-based downloader development

#### Impact
- **T1496 - Resource Hijacking**
  - XMRig cryptominer deployment
  - Unauthorized cryptocurrency mining

### Attack Flow Summary

1. **Initial Contact:** Phishing email impersonating CrowdStrike recruitment
2. **Social Engineering:** Victims directed to fake hiring portal
3. **Malware Delivery:** Windows executable disguised as "CRM application"
4. **Anti-Analysis Checks:** Multiple environment validation checks
5. **Payload Download:** XMRig cryptominer and configuration retrieval
6. **Execution:** Cryptominer launched with attacker-controlled pool
7. **Persistence:** Multiple mechanisms (registry keys, startup scripts)

---

## 7. Executive Summary

On January 7, 2025, CrowdStrike identified a sophisticated phishing campaign exploiting its recruitment branding to distribute cryptomining malware. The attack vector leverages social engineering targeting job seekers by impersonating legitimate CrowdStrike hiring communications.

**Attack Characteristics:**
- Victims receive phishing emails claiming to be part of a CrowdStrike recruitment process
- A malicious website (cscrm-hiring[.]com) offers fake "employee CRM application" downloads
- A Rust-written Windows executable serves as a downloader for the XMRig cryptocurrency miner
- The malware implements sophisticated anti-analysis and evasion techniques
- Multiple persistence mechanisms ensure continued operation

**Impact:**
- Unauthorized cryptocurrency mining consumes victim system resources
- Potential degradation of system performance
- Financial gain for threat actors through mining operations
- Reputational damage through brand impersonation

**Threat Level:** Medium to High for targeted individuals and organizations

---

## 8. Recommendations and Recommended Actions

### Immediate Actions

**For Individuals:**
1. **Verify Communications:** Always verify CrowdStrike recruitment emails by contacting recruiting@crowdstrike.com
2. **Official Channels Only:** Navigate directly to CrowdStrike's official Careers page for job applications
3. **Avoid Downloads:** Never download software as part of an interview process
4. **Report Suspicious Activity:** Report fraudulent recruitment communications immediately

**For Organizations:**
1. **Block IOCs:** Implement blocking for all identified domains, IPs, and file hashes
2. **Threat Hunt:** Search environments for presence of IOCs
3. **Email Filtering:** Enhance email security to detect recruitment-themed phishing
4. **User Awareness:** Conduct immediate security awareness training on recruitment scams

### Security Controls

**Email Security:**
- Implement advanced email filtering to detect brand impersonation
- Enable SPF, DKIM, and DMARC validation
- Block or quarantine emails containing recruitment themes from unauthorized domains
- Deploy email security gateways with URL rewriting and sandboxing

**Endpoint Protection:**
- Deploy endpoint detection and response (EDR) solutions
- Enable real-time monitoring for cryptominer signatures
- Block execution from temporary directories
- Implement application whitelisting where feasible

**Network Security:**
- Block communications to known mining pools
- Monitor for unusual outbound connections on non-standard ports
- Implement DNS filtering to block malicious domains
- Deploy network traffic analysis for cryptomining indicators

**User Education:**
- Conduct regular phishing simulation exercises
- Train employees on recruitment scam indicators
- Establish clear policies for legitimate recruitment processes
- Create reporting mechanisms for suspicious communications

### Long-Term Strategic Actions

1. **Brand Protection Program:** Implement domain monitoring for typosquatting and impersonation
2. **Threat Intelligence Integration:** Subscribe to threat feeds containing cryptomining IOCs
3. **Incident Response Planning:** Develop playbooks for recruitment phishing incidents
4. **Security Culture:** Foster organizational awareness of social engineering tactics

---

## 9. Detection Techniques

### Behavioral Detection

**Process Monitoring:**
- Monitor for execution of processes from %TEMP% and %LOCALAPPDATA% directories
- Detect suspicious parent-child process relationships (e.g., browser spawning executables from temp folders)
- Alert on processes making debugger detection API calls (IsDebuggerPresent)
- Identify processes scanning for virtualization/analysis tools

**Network Monitoring:**
- Detect connections to known mining pools and suspicious ports (e.g., 1300, 3333, 14444)
- Monitor for downloads from newly registered domains
- Alert on HTTP/HTTPS traffic to IP addresses rather than domains
- Identify base64-encoded configuration downloads

**File System Monitoring:**
- Monitor creation of files in Startup directories
- Detect modifications to Windows Registry Run keys
- Alert on ZIP file extractions to unusual paths
- Track creation of batch scripts in system directories

### Signature-Based Detection

**Email Signatures:**
- Scan for emails containing "CrowdStrike recruitment" or "CRM application" keywords
- Detect URLs matching pattern: *crm-hiring[.]com or variations
- Identify emails with download links to executable files

**File Signatures:**
- XMRig binary signatures and variants
- Rust-compiled executable indicators
- Specific file names: config.exe, process.exe, startup.bat

**Registry Monitoring:**
- Monitor HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run for new entries
- Alert on suspicious autorun entries containing "config" or non-standard paths

### Threat Hunting Queries

**Search for Cryptomining Activity:**
```
process_name:"*xmrig*" OR 
command_line:"*mining*" OR 
network_connection:(*:1300 OR *:3333 OR *:14444)
```

**Identify Suspicious Startup Persistence:**
```
file_path:("*\\Startup\\*.bat" OR "*\\Run\\config") AND
file_created_time:[NOW-7DAYS TO NOW]
```

**Detect Evasion Techniques:**
```
api_call:"IsDebuggerPresent" AND
process_path:"*\\Temp\\*" OR "*\\LocalAppData\\*"
```

---

## 10. Prevention Techniques

### Technical Controls

**Email Security:**
- Implement DMARC policy to prevent domain spoofing
- Configure email gateways to sandbox attachments and links
- Block executable attachments in recruitment-themed emails
- Deploy anti-phishing solutions with machine learning capabilities

**Endpoint Security:**
- Enable Windows Defender Application Control (WDAC) or AppLocker
- Configure attack surface reduction (ASR) rules to block execution from temp directories
- Implement endpoint DLP to prevent unauthorized downloads
- Deploy behavioral analytics to detect cryptomining activity

**Network Security:**
- Block access to cryptocurrency mining pools at firewall level
- Implement egress filtering for suspicious ports
- Deploy DNS security solutions to block malicious domains
- Enable SSL/TLS inspection for encrypted traffic analysis

**User Access Controls:**
- Implement principle of least privilege
- Restrict execution permissions in temporary directories
- Disable PowerShell and command-line interpreters for standard users
- Enforce multi-factor authentication for all accounts

### Process and Policy Controls

**Security Awareness:**
- Mandatory phishing awareness training for all employees
- Regular simulated phishing exercises focusing on recruitment scenarios
- Clear communication of legitimate recruitment processes
- Establishment of verification procedures for unsolicited contacts

**Vendor Risk Management:**
- Maintain list of approved recruitment platforms and channels
- Document official recruitment communication methods
- Establish out-of-band verification protocols
- Regular audits of recruitment-related communications

**Incident Response:**
- Develop specific playbooks for recruitment phishing incidents
- Establish clear escalation paths for suspicious recruitment contacts
- Implement rapid IOC distribution mechanisms
- Conduct post-incident reviews and lessons learned sessions

### Configuration Hardening

**Windows Hardening:**
- Disable Windows Script Host for standard users
- Configure folder permissions to prevent execution from temp directories
- Enable Windows Defender Exploit Guard
- Implement code integrity policies

**Browser Security:**
- Deploy browser isolation or remote browser solutions
- Configure browsers to prompt before downloading executables
- Implement content filtering and URL reputation services
- Enable safe browsing features in all enterprise browsers

---

## 11. YARA Rules

```yara
rule CrowdStrike_Recruitment_Phishing_Downloader {
    meta:
        description = "Detects fake CrowdStrike CRM application downloader"
        author = "Security Analysis"
        date = "2025-01-08"
        reference = "CrowdStrike Recruitment Phishing Campaign"
        hash1 = "62f3a21db99bcd45371ca4845c7296af81ce3ff6f0adcaee3f1698317dd4898b"
        
    strings:
        $api1 = "IsDebuggerPresent" ascii wide
        $string1 = "System\\temp.zip" ascii wide
        $string2 = "System\\process.exe" ascii wide
        $string3 = "System32\\config.exe" ascii wide
        $url1 = "93.115.172.41" ascii wide
        $url2 = "cscrm-hiring.com" ascii wide
        $xmrig1 = "xmrig" ascii wide nocase
        $path1 = "\\Startup\\startup.bat" ascii wide
        $registry1 = "CurrentVersion\\Run\\config" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (3 of ($string*)) or
            ($api1 and 2 of ($string*)) or
            (2 of ($url*) and 2 of ($string*)) or
            ($xmrig1 and 2 of ($string*))
        )
}

rule XMRig_Cryptominer_Generic {
    meta:
        description = "Detects XMRig cryptocurrency miner"
        author = "Security Analysis"
        date = "2025-01-08"
        
    strings:
        $xmrig1 = "xmrig" ascii wide nocase
        $xmrig2 = "XMRig" ascii wide
        $pool1 = "pool" ascii wide
        $donate1 = "donate-level" ascii wide
        $algo1 = "cryptonight" ascii wide
        $wallet1 = "wallet" ascii wide
        $mining1 = "mining" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($xmrig*)) or
            ($xmrig1 and 3 of them)
        )
}

rule Recruitment_Phishing_BatchScript {
    meta:
        description = "Detects batch scripts used for persistence in recruitment phishing campaign"
        author = "Security Analysis"
        date = "2025-01-08"
        
    strings:
        $batch1 = "@echo off" ascii nocase
        $batch2 = "start /b" ascii nocase
        $path1 = "\\System32\\process.exe" ascii wide
        $path2 = "\\LocalAppData\\System32\\" ascii wide
        $reg1 = "reg add" ascii nocase
        $reg2 = "CurrentVersion\\Run" ascii wide
        
    condition:
        filesize < 10KB and
        (
            (2 of ($batch*) and 1 of ($path*)) or
            (1 of ($batch*) and 2 of ($reg*))
        )
}

rule Rust_Based_Malware_Downloader {
    meta:
        description = "Detects Rust-compiled malware with anti-analysis features"
        author = "Security Analysis"
        date = "2025-01-08"
        
    strings:
        $rust1 = "rust" ascii wide nocase
        $rust2 = ".rdata" ascii
        $api1 = "IsDebuggerPresent" ascii wide
        $api2 = "GetSystemInfo" ascii wide
        $api3 = "CreateProcessA" ascii wide
        $check1 = "VirtualBox" ascii wide nocase
        $check2 = "VMware" ascii wide nocase
        $check3 = "sandboxie" ascii wide nocase
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (1 of ($rust*) and 2 of ($api*) and 1 of ($check*)) or
            (3 of ($api*) and 2 of ($check*))
        )
}
```

---

## 12. Sigma Rules

```yaml
title: CrowdStrike Recruitment Phishing - Suspicious Process Execution from Temp
id: a8f3c9d2-7e1b-4a5c-9f2d-3b4e5a6c7d8e
status: experimental
description: Detects execution of processes from temporary directories associated with recruitment phishing campaign
author: Security Analysis
date: 2025/01/08
references:
    - https://www.crowdstrike.com/en-us/blog/recruitment-phishing-scam-imitates-crowdstrike-hiring-process/
logsource:
    category: process_creation
    product: windows
detection:
    selection_path:
        Image|contains:
            - '\AppData\Local\Temp\System\'
            - '\AppData\Local\System32\'
    selection_name:
        Image|endswith:
            - '\config.exe'
            - '\process.exe'
    condition: selection_path or selection_name
falsepositives:
    - Legitimate software installations
    - Administrative activities
level: high
tags:
    - attack.execution
    - attack.t1204.002
    - attack.defense_evasion
    - attack.t1036.005

---

title: XMRig Cryptominer Execution
id: b9e4d8f1-2a3c-4d5e-8f7g-1h2i3j4k5l6m
status: experimental
description: Detects execution of XMRig cryptocurrency miner
author: Security Analysis
date: 2025/01/08
references:
    - https://www.crowdstrike.com/en-us/blog/recruitment-phishing-scam-imitates-crowdstrike-hiring-process/
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith: '\process.exe'
    selection_cmdline:
        CommandLine|contains:
            - '--donate-level'
            - 'pool'
            - 'xmrig'
    selection_parent:
        ParentImage|contains:
            - '\config.exe'
            - '\Temp\System\'
    condition: selection_image or (selection_cmdline and selection_parent)
falsepositives:
    - Legitimate cryptocurrency mining
level: critical
tags:
    - attack.impact
    - attack.t1496

---

title: Recruitment Phishing - Suspicious Startup Persistence
id: c1d2e3f4-5a6b-7c8d-9e0f-1a2b3c4d5e6f
status: experimental
description: Detects creation of batch files in Windows Startup folder for persistence
author: Security Analysis
date: 2025/01/08
references:
    - https://www.crowdstrike.com/en-us/blog/recruitment-phishing-scam-imitates-crowdstrike-hiring-process/
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Start Menu\Programs\Startup\'
        TargetFilename|endswith: '.bat'
    filter:
        Image|startswith: 'C:\Windows\System32\'
    condition: selection and not filter
falsepositives:
    - Administrative scripts
    - Legitimate startup configurations
level: high
tags:
    - attack.persistence
    - attack.t1547.009

---

title: Recruitment Phishing - Registry Run Key Persistence
id: d2e3f4g5-6h7i-8j9k-0l1m-2n3o4p5q6r7s
status: experimental
description: Detects suspicious registry Run key creation for persistence
author: Security Analysis
date: 2025/01/08
references:
    - https://www.crowdstrike.com/en-us/blog/recruitment-phishing-scam-imitates-crowdstrike-hiring-process/
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run\'
        TargetObject|endswith: '\config'
        Details|contains:
            - '\AppData\Local\System32\config.exe'
    condition: selection
falsepositives:
    - Legitimate software installations
level: high
tags:
    - attack.persistence
    - attack.t1547.001

---

title: Network Connection to Cryptomining Pool
id: e3f4g5h6-7i8j-9k0l-1m2n-3o4p5q6r7s8t
status: experimental
description: Detects network connections to cryptocurrency mining pools
author: Security Analysis
date: 2025/01/08
references:
    - https://www.crowdstrike.com/en-us/blog/recruitment-phishing-scam-imitates-crowdstrike-hiring-process/
logsource:
    category: network_connection
    product: windows
detection:
    selection_ip:
        DestinationIp: '93.115.172.41'
    selection_port:
        DestinationPort:
            - 1300
            - 3333
            - 14444
    selection_process:
        Image|endswith: '\process.exe'
    condition: selection_ip or (selection_port and selection_process)
falsepositives:
    - Legitimate connections to same IP range
level: critical
tags:
    - attack.command_and_control
    - attack.impact
    - attack.t1496

---

title: Recruitment Phishing - Debugger Detection API Call
id: f4g5h6i7-8j9k-0l1m-2n3o-4p5q6r7s8t9u
status: experimental
description: Detects usage of IsDebuggerPresent API for anti-analysis
author: Security Analysis
date: 2025/01/08
references:
    - https://www.crowdstrike.com/en-us/blog/recruitment-phishing-scam-imitates-crowdstrike-hiring-process/
logsource:
    category: api_call
    product: windows
detection:
    selection:
        ApiName: 'IsDebuggerPresent'
        CallingSoftware|contains:
            - '\AppData\Local\Temp\'
            - '\AppData\Local\System32\'
    condition: selection
falsepositives:
    - Legitimate software with copy protection
    - Development and debugging tools
level: medium
tags:
    - attack.defense_evasion
    - attack.t1497.001

---

title: Recruitment Phishing - Domain Access Indicator
id: g5h6i7j8-9k0l-1m2n-3o4p-5q6r7s8t9u0v
status: experimental
description: Detects access to recruitment phishing domain
author: Security Analysis
date: 2025/01/08
references:
    - https://www.crowdstrike.com/en-us/blog/recruitment-phishing-scam-imitates-crowdstrike-hiring-process/
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|contains: 'cscrm-hiring.com'
    condition: selection
falsepositives:
    - None expected
level: critical
tags:
    - attack.initial_access
    - attack.t1566.002
```

---

## Conclusion

The CrowdStrike recruitment phishing campaign represents a sophisticated social engineering attack leveraging brand impersonation to deploy cryptomining malware. While the financial impact is primarily limited to resource hijacking, the campaign demonstrates advanced anti-analysis techniques and multiple persistence mechanisms.

Organizations should prioritize security awareness training focused on recruitment scams, implement robust email filtering, and deploy comprehensive endpoint protection solutions. The IOCs provided in this report should be immediately integrated into security monitoring platforms.

**Report Classification:** TLP:WHITE - Unlimited distribution  
**Next Review Date:** February 7, 2025
