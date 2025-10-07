
# Fortinet Report 
# Analysis of Fortinet Global Threat Landscape Report 2025
Report Link: https://www.fortinet.com/content/dam/fortinet/assets/threat-reports/threat-landscape-report-2025.pdf

## 1. Attacker Name/Group Name

**Ransomware Groups:**
- RansomHub (13% of attacks)
- LockBit 3.0 (12% of attacks)
- Play (8% of attacks)
- Medusa (4% of attacks)
- HellCat, Argonauts Ransomware, InterLock, Bashe (APT73, Eraleig), Termite, Sarcoma, Nitrogen, Lynx, Ransomcortex, Valencia

**Initial Access Brokers (IABs):**
- sandocan (26%)
- F13 (16%)
- JefryG (12%)

**Credential Trading Groups:**
- BestCombo (20%)
- BloddyMery (12%)
- ValidMail (12%)

**Hacktivist Groups:**
- RipperSec (20%)
- Z-BL4CX-H4T (14%)
- DATABASE LEAKS CYBER TEAM INDONESIA (11%)
- CyberVolk
- Handala
- KillSec
- Ikaruz Red Team (IRT)

## 2. APT Name

**State-Sponsored APT Groups:**
- **Lazarus** (21% - North Korea)
- **KIMSUKY** (18% - North Korea)
- **APT28** (13% - Russia/Fancy Bear)
- **Volt Typhoon** (12% - China)
- **APT29** (10% - Russia/Cozy Bear)
- **APT73** (also known as Bashe/Eraleig)

## 3. Exploited Vulnerabilities and Short Descriptions

| CVE | Description | CVSS Score | Impact |
|-----|-------------|------------|--------|
| **CVE-2017-0147** | Windows SMB Information Disclosure - 26.7% of exploitation attempts. Allows attackers to infiltrate enterprise networks via Server Message Block protocol | High | Remote access, lateral movement |
| **CVE-2021-44228** | Apache Log4j Remote Code Execution - 11.6% of activity. Critical vulnerability in Java logging library | 10.0 | Remote code execution |
| **CVE-2019-18935** | Netcore Netis Devices Hardcoded Password - 8% of attempts. Default credentials in IoT devices | 9.8 | Remote control, botnet recruitment |
| **CVE-2024-21887** | Ivanti Command Injection - Exploited 6 days after disclosure | Critical | Remote access |
| **CVE-2022-30525** | Zyxel Firewalls and Routers vulnerability | 9.8 | Remote access, configuration tampering |
| **CVE-2023-1389** | TP-Link Archer AX21 Router vulnerability | 9.0 | Traffic hijacking, credential theft |
| **CVE-2018-10561** | GPON Router vulnerability | 9.4 | Persistent access, botnet, DDoS |
| **CVE-2017-18377** | WiFi P2P GoAhead Cameras vulnerability | 8.3 | Unauthorized access, espionage |

**Key Statistics:**
- 331 zero-day vulnerabilities identified in darknet forums in 2024
- 182 (55%) had publicly available PoC exploit code
- 106 (32%) had fully functional exploit code
- 98 (30%) were actively exploited in ransomware/APT campaigns

## 4. Target Country, Organization, Sector

**Geographic Distribution:**
- **United States**: 61% of ransomware victims
- **United Kingdom**: 6%
- **Canada**: 5%
- **Asia-Pacific (APAC)**: 42% of exploitation attempts
- **EMEA**: 26% of exploitation attempts
- **North America**: 20% of exploitation attempts
- **Latin America**: 11% of exploitation attempts

**Targeted Sectors:**
1. **Manufacturing** (17%) - Primary ransomware target
2. **Business Services** (11%)
3. **Construction** (9%)
4. **Retail** (9%)
5. **Government Institutions** - Primary APT target
6. **Technology Sector**
7. **Education Sector**
8. **Financial Services**
9. **Telecommunications**
10. **OT/ICS/SCADA Systems**

## 5. Indicators of Compromise (IOCs)

**Malware Families:**

**Remote Access Trojans (RATs):**
- Xeno RAT
- SparkRAT
- Async RAT
- Trickbot

**Infostealers:**
- Redline (60% of infostealer activity)
- Vidar (27%)
- Racoon (12%)

**Network Indicators:**
- 36,000 scans per second detected globally
- 1.16 trillion detections in 2024 (16.7% increase YoY)
- Over 97 billion exploitation attempts recorded

**Behavioral Indicators:**
- **Logins from unusual geographies** (70% of cloud compromise cases)
- **New API activity for existing users** (20% of cloud compromise cases)
- **Malicious SMB traffic with executable downloads**
- **Anomalous SMB protocol implementation** (incorrect PID fields in Impacket package)
- **DGA (Domain Generation Algorithm) domains** for C2
- **SSL C2 beacons**
- **Cobalt Strike DNS requests**
- **DNS tunneling and long DNS queries**

**Scanning Tools Used by Attackers:**
- SIPVicious (50% of scanning events)
- Qualys (2.5%)
- Nmap (<1%)
- Nessus and OpenVAS

## 6. Attack Tactics, Techniques, and Procedures (TTPs)

### MITRE ATT&CK Mapping:

**Reconnaissance (TA0043):**
- Active Scanning (49% focused on SIP/VoIP protocols)
- Hardware Additions
- 1.6% Modbus TCP scanning for ICS/SCADA

**Resource Development (TA0042):**
- AI-powered tools (FraudGPT, WormGPT, BlackmailerV3)
- Deepfake tools (DeepFaceLab, Faceswap, ElevenLabs)
- Exploit kits from darknet forums

**Initial Access (TA0001):**
- Exploit Public-Facing Application (T1190)
- Phishing: Spearphishing Link
- Valid Accounts (credentials/VPNs - 42% increase)
- External Remote Services
- User Execution

**Execution (TA0002):**
- Command and Scripting Interpreter: PowerShell (T1059)
- Windows Management Instrumentation (WMI)
- System Binary Proxy Execution: Regsvr32
- Command and Scripting Interpreters (47 cloud incidents)

**Persistence (TA0003):**
- External Remote Services
- Server Software Component: Web Shell
- Create or Modify System Process: Windows Service
- Boot or Logon Autostart Execution
- Scheduled Task/Job (12.3% of cloud attacks)

**Privilege Escalation (TA0004):**
- Valid Accounts: Domain Accounts
- Scheduled Task/Job: Scheduled Task
- Exploitation for Privilege Escalation
- Rogue Domain Controller (DCShadow attacks - 10.6% cloud attacks)

**Defense Evasion (TA0005):**
- Obfuscated Files or Information: Stripped Payloads
- Indicator Removal: Clear Windows Event Logs
- Deobfuscate/Decode Files or Information
- Subvert Trust Controls
- "Living off the land" techniques using trusted tools

**Credential Access (TA0006):**
- Brute Force
- Forced Authentication
- OS Credential Dumping: DCSync
- Steal or Forge Kerberos Tickets: AS-REP Roasting/Kerberoasting
- 500% increase in infostealer logs (1.7 billion credentials)

**Discovery (TA0007):**
- Network Service Discovery
- Account Discovery: Domain Account
- File and Directory Discovery
- Active Directory Enumeration
- Network scanning
- 25.3% of cloud attacks used Discovery tactics

**Lateral Movement (TA0008):**
- Remote Services: SMB/Windows Admin Shares
- Remote Services: Windows Remote Management
- RDP-based movement (88% of incidents)
- WMI ExecMethod lateral movement
- Exploitation of Remote Services
- Lateral Tool Transfer (6.8% cloud attacks)

**Command and Control (TA0011):**
- Application Layer Protocol (DNS, Web Protocols)
- Proxy: External Proxy, Multi-hop Proxy
- Remote Access Software
- Ingress Tool Transfer
- SSL C2 beacons
- Cobalt Strike usage
- Web Services (T1102 - 23 cloud incidents)

**Exfiltration (TA0010):**
- Exfiltration Over Alternative Protocol
- Exfiltration Over C2 Channel
- Exfiltration Over Web Service
- 3.3% of cloud attacks

**Impact (TA0040):**
- Network Denial of Service
- Resource Hijacking (T1496 - 24 cloud cryptojacking incidents)
- Double and triple extortion ransomware models

## 7. Short Summary of Entire Content

The 2025 Fortinet Global Threat Landscape Report reveals a **dramatic acceleration in cyber adversary capabilities**, with attackers leveraging automation, AI, and industrialized cybercrime services to operate with unprecedented speed and scale.

**Key Findings:**
- **Reconnaissance surge**: 16.7% increase in scanning activity globally, reaching 1.16 trillion detections and 36,000 scans per second
- **AI-enabled cybercrime**: Threat actors using tools like FraudGPT, deepfake generators, and voice synthesis for sophisticated attacks
- **Cybercrime-as-a-Service explosion**: 42% increase in compromised credentials, 500% surge in infostealer logs
- **Rapid exploitation**: 97 billion exploitation attempts with average 5.4-day exploitation timeline
- **IoT targeting**: 20% of exploitation attempts focused on routers, cameras, and network devices
- **Post-exploitation sophistication**: "Living off the land" techniques, AD manipulation, encrypted C2 channels
- **Cloud vulnerabilities**: 70% of breaches involved logins from unfamiliar geographies; misconfigurations remain primary attack vector
- **Ransomware evolution**: 13 new groups emerged; top 4 groups account for 37% of attacks
- **State-sponsored activity**: China and Russia-linked APTs targeting government, tech, and education sectors

The report emphasizes that defenders must shift from reactive approaches to **Continuous Threat Exposure Management (CTEM)** to counter the accelerating adversary advantage.

## 8. Recommendations/Recommended Actions

### Strategic Framework: Continuous Threat Exposure Management (CTEM)

**1. Shift Left - Proactive Defense:**
- Implement continuous attack surface monitoring
- Conduct real-world adversary behavior emulation
- Adopt risk-based prioritization for remediation
- Automate detection and defense responses

**2. Simulate Real-World Attacks:**
- Conduct red and purple teaming exercises mimicking LockBit, APT29, and other threat actors
- Utilize MITRE ATT&CK framework for behavior-based attack simulations
- Regular Breach and Attack Simulation (BAS) testing

**3. Reduce Attack Surface Exposure:**
- Deploy Attack Surface Management (ASM) tools
- Monitor darknet forums for leaked credentials and emerging threats
- Identify and remediate exposed services (SIP, RDP, Modbus TCP)
- Eliminate default credentials and hardcoded passwords in IoT devices

**4. Prioritize Vulnerability Management:**
- Focus on vulnerabilities actively discussed in darknet/hacktivist forums
- Use EPSS (Exploit Prediction Scoring System) and CVSS for prioritization
- Accelerate patch cycles for high-risk vulnerabilities
- Monitor zero-day discussions (331 identified in 2024)

**5. Identity and Access Management:**
- Implement zero-trust architecture
- Monitor logins from unfamiliar geographies
- Enforce MFA with phishing-resistant methods
- Regular credential rotation and privileged access reviews
- Monitor for new API activity patterns

**6. Cloud Security Hardening:**
- Fix misconfigurations (open storage buckets, over-permissioned identities)
- Implement cloud workload protection platforms (CWPP)
- Secure APIs with proper authentication and rate limiting
- Monitor Cloud Instance Metadata API access
- Deploy FortiCNAPP or equivalent for cloud threat detection

**7. Network Segmentation and Monitoring:**
- Segment OT/IoT networks from corporate IT
- Deploy behavioral analytics for anomaly detection
- Monitor RDP and SMB traffic for lateral movement
- Implement encrypted traffic inspection for C2 detection

**8. Dark Web Intelligence:**
- Monitor darknet marketplaces for organizational credentials
- Track RaaS services (PlayBoy, Rape, Medusa, Wing, BEAST, Cicada 3301)
- Monitor hacktivist Telegram channels for targeting information
- Subscribe to threat intelligence feeds

**9. Post-Exploitation Detection:**
- Deploy Network Detection and Response (NDR) solutions
- Monitor for DCShadow and DCSync attacks on Active Directory
- Detect WMI and PowerShell abuse
- Implement behavioral analytics for "living off the land" techniques

**10. Incident Response Readiness:**
- Develop playbooks for ransomware, APT, and cloud compromise scenarios
- Conduct tabletop exercises quarterly
- Establish communication protocols for multi-stage attacks
- Maintain offline backups with regular testing

## 9. Detection Techniques

### Network-Based Detection:

**1. Scanning Activity Detection:**
- Monitor for high-volume connection attempts
- Detect SIPVicious signatures (49% of scanning)
- Identify Modbus TCP reconnaissance (1.6% of scans)
- Alert on Nmap, Qualys, Nessus scanning patterns

**2. Exploitation Attempt Detection:**
- IPS signatures for CVE-2017-0147 (SMB), CVE-2021-44228 (Log4j), CVE-2019-18935
- Monitor for IoT device exploitation patterns
- Detect unusual traffic to routers, cameras, firewalls

**3. Lateral Movement Detection:**
- Anomalous SMB traffic with executable downloads
- Incorrect PID fields in SMB protocol (Impacket IOC)
- WMI ExecMethod remote execution
- RDP connections from unusual sources (88% of incidents)
- Unusual network session enumeration

**4. Command & Control Detection:**
- SSL C2 beacon identification
- Cobalt Strike DNS request patterns
- DNS tunneling detection (long query strings)
- DGA domain detection using ML models
- Non-standard port usage for known protocols
- Proxy chain detection (multi-hop proxies)

### Host-Based Detection:

**5. Malware Detection:**
- Xeno RAT, SparkRAT, Async RAT, Trickbot signatures
- Redline, Vidar, Racoon infostealer behaviors
- Portable executable (PE) downloads across networks
- Trojan downloader patterns

**6. Execution Detection:**
- Encoded PowerShell command execution
- WMI-based fileless attacks
- Regsvr32 proxy execution
- Suspicious scheduled task creation
- Windows service modifications

**7. Privilege Escalation Detection:**
- DCShadow attacks (rogue domain controller)
- DCSync attacks (unauthorized DC replication)
- Active Directory enumeration queries
- Kerberoasting and AS-REP Roasting attempts
- Unusual domain trust queries

**8. Persistence Detection:**
- Web shell deployment on servers
- Unauthorized Windows service creation
- Boot/logon autostart execution modifications
- External remote service establishment

### Cloud-Specific Detection:

**9. Identity Compromise Detection:**
- Logins from unfamiliar geographies (70% of cases)
- New API activity for existing users (20% of cases)
- Credential leaks in code repositories (GitHub, GitGuardian monitoring)
- Impossible travel scenarios
- Multiple failed authentication attempts followed by success

**10. Cloud Workload Compromise:**
- Command execution via Bash, PowerShell, Python in cloud environments
- Legitimate cloud service abuse for C2
- Resource hijacking for cryptomining (24 incidents)
- Cloud Instance Metadata API exploitation (T1556.004)

**11. Behavioral Analytics:**
- Deviation from normal user/entity behavior
- Unusual data access patterns
- Abnormal API call sequences
- Time-of-day anomalies for sensitive operations

### Darknet Intelligence:

**12. Proactive Threat Intelligence:**
- Monitor for organizational credentials in combo lists
- Track IAB offerings for corporate access
- Identify exploit discussions for organizational technology stack
- Monitor RaaS and infostealer malware developments

## 10. Prevention Techniques

### Architecture & Infrastructure:

**1. Network Segmentation:**
- Separate OT/ICS from IT networks
- Implement DMZs for internet-facing services
- Micro-segmentation for critical assets
- VLAN isolation for IoT devices

**2. Zero Trust Architecture:**
- Never trust, always verify principle
- Least privilege access model
- Continuous authentication and authorization
- Software-defined perimeters

**3. Secure Configuration Management:**
- Eliminate default credentials (addresses 18.4% of IoT exploits)
- Harden operating systems and applications
- Disable unnecessary services and protocols
- Regular configuration audits

### Access Control:

**4. Identity & Access Management:**
- Multi-factor authentication (MFA) for all accounts
- Phishing-resistant MFA (FIDO2, hardware tokens)
- Privileged Access Management (PAM) solutions
- Regular access reviews and de-provisioning
- Strong password policies with credential monitoring

**5. Cloud Identity Security:**
- Principle of least privilege for cloud permissions
- Disable public access to storage buckets
- Implement Cloud Identity and Access Management (CIAM)
- Monitor for over-permissioned identities
- Secure service accounts and API keys

### Vulnerability Management:

**6. Patch Management:**
- Risk-based patching prioritization (EPSS + CVSS)
- Accelerated patching for internet-facing assets
- Virtual patching where immediate patching isn't possible
- Regular vulnerability scanning
- Asset inventory maintenance

**7. IoT Security:**
- Firmware update management (addresses 20% of exploitation attempts)
- Network isolation for IoT devices
- Disable remote management interfaces when not needed
- Regular security assessments of IoT devices

### Endpoint Protection:

**8. Endpoint Security:**
- Next-generation antivirus (NGAV)
- Endpoint Detection and Response (EDR)
- Application whitelisting
- Disable PowerShell/WMI where not needed
- USB device control

**9. Anti-Malware Measures:**
- Deploy anti-infostealer solutions (counter 500% increase)
- Browser isolation for high-risk users
- Email security gateways with AI-based detection
- Web filtering to block known malicious domains

### Data Protection:

**10. Data Security:**
- Data Loss Prevention (DLP) solutions
- Encryption at rest and in transit
- Secure backup strategy (3-2-1 rule)
- Offline/immutable backups (ransomware resilience)
- Regular backup testing and restoration drills

**11. Cloud Data Protection:**
- Cloud Access Security Broker (CASB)
- Cloud Storage encryption
- Data classification and labeling
- API security gateways
- Monitor for data exfiltration patterns

### Network Security:

**12. Perimeter Defense:**
- Next-Generation Firewalls (NGFW)
- Intrusion Prevention Systems (IPS) - detected 1.16 trillion threats
- Web Application Firewalls (WAF)
- DDoS protection
- Secure DNS services

**13. Traffic Analysis:**
- Network Traffic Analysis (NTA)
- Encrypted traffic inspection
- DNS filtering and monitoring
- Protocol anomaly detection

### Email & Communication:

**14. Email Security:**
- Advanced email filtering (counter AI-generated phishing)
- DMARC, DKIM, SPF implementation
- Link sandboxing and rewriting
- Attachment sandboxing
- User reporting mechanisms

**15. Collaboration Platform Security:**
- Monitor Telegram channels for threat intelligence
- Secure configuration of collaboration tools
- DLP for messaging platforms
- Access controls for external sharing

### Training & Awareness:

**16. Security Awareness:**
- Regular phishing simulation training (counter AI-enhanced phishing)
- Deepfake and voice phishing awareness
- Secure coding practices
- Incident reporting procedures
- Role-specific security training

### Vendor & Supply Chain:

**17. Third-Party Risk Management:**
- Vendor security assessments
- Supply chain security requirements
- Monitoring of vendor access
- Contractual security obligations
- Regular vendor security reviews

### Monitoring & Intelligence:

**18. Threat Intelligence:**
- Dark web monitoring services (FortiRecon)
- ISAC/ISAO participation
- Automated threat intelligence feeds
- IOC sharing with industry peers
- Adversary emulation programs

**19. Continuous Monitoring:**
- 24/7 Security Operations Center (SOC)
- Security Information and Event Management (SIEM)
- User and Entity Behavior Analytics (UEBA)
- File Integrity Monitoring (FIM)
- Log aggregation and retention

### Specialized Controls:

**20. Active Directory Hardening:**
- Tiered administrative model
- Protected Users group
- Disable NTLM where possible
- Monitor for DCSync and DCShadow
- Regular AD security assessments

**21. Cloud-Specific Prevention:**
- Cloud Security Posture Management (CSPM)
- Cloud Workload Protection Platform (CWPP)
- Container security
- Kubernetes security policies
- Infrastructure-as-Code (IaC) security scanning

**22. API Security:**
- API gateways with authentication
- Rate limiting and throttling
- API security testing
- OAuth/JWT token management
- API versioning and deprecation policies

## 11. YARA Rules (not in the report)

**Note:** The report does not provide specific YARA rules. However, based on the threats identified, here are recommended YARA rule categories to develop:

```yara
// Example YARA rule structure for Redline Infostealer (60% of activity)
rule Redline_Infostealer_Generic {
    meta:
        description = "Detects Redline infostealer malware"
        threat_level = "high"
        reference = "Fortinet 2025 Threat Report"
        
    strings:
        $s1 = "RedLine" ascii wide
        $s2 = "C:\\Users\\Admin\\source" ascii
        $s3 = "SELECT * FROM logins" ascii
        $s4 = "wallet.dat" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        2 of ($s*)
}

// Example for Vidar Infostealer (27% of activity)
rule Vidar_Infostealer_Generic {
    meta:
        description = "Detects Vidar infostealer"
        threat_level = "high"
        reference = "Fortinet 2025 Threat Report"
        
    strings:
        $s1 = "vidar" ascii nocase
        $s2 = /profile\d+\.zip/ ascii
        $s3 = "autofill" ascii
        $s4 = "\\Local State" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        3 of them
}

// Example for Xeno RAT detection
rule XenoRAT_Generic {
    meta:
        description = "Detects Xeno RAT malware"
        threat_level = "critical"
        reference = "Fortinet 2025 Threat Report"
        
    strings:
        $s1 = "XenoRAT" ascii wide
        $s2 = "Socks5" ascii
        $s3 = "screenshot" ascii
        $s4 = "keylogger" ascii
        $mutex = "XenoMutex" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        2 of ($s*) or $mutex
}

// Example for SparkRAT detection
rule SparkRAT_Generic {
    meta:
        description = "Detects SparkRAT malware"
        threat_level = "critical"
        reference = "Fortinet 2025 Threat Report"
        
    strings:
        $s1 = "SparkRAT" ascii
        $s2 = "cmd_shutdown" ascii
        $s3 = "cmd_restart" ascii
        $s4 = "file_manager" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        3 of them
}

// Example for Cobalt Strike beacon detection
rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon"
        threat_level = "critical"
        reference = "Fortinet 2025 Threat Report"
        
    strings:
        $s1 = "%c%c%c%c%c%c%c%c%cMSSE" ascii
        $s2 = "IEX (New-Object Net.Webclient)" ascii
        $s3 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $s4 = "beacon.dll" ascii nocase
        
    condition:
        2 of them
}

// Detection for SIPVicious scanning tool (49% of scanning activity)
rule SIPVicious_Scanner {
    meta:
        description = "Detects SIPVicious VoIP scanner"
        threat_level = "medium"
        reference = "Fortinet 2025 Threat Report"
        
    strings:
        $s1 = "sipvicious" ascii nocase
        $s2 = "svwar" ascii
        $s3 = "svcrack" ascii
        $s4 = "friendly-scanner" ascii
        
    condition:
        any of them
}

// Generic ransomware detection patterns
rule Ransomware_Generic_Indicators {
    meta:
        description = "Generic ransomware behavior indicators"
        threat_level = "critical"
        reference = "Fortinet 2025 Threat Report"
        
    strings:
        $ext1 = ".locked" ascii
        $ext2 = ".encrypted" ascii
        $ext3 = ".ransom" ascii
        $note1 = "README" ascii nocase
        $note2 = "DECRYPT" ascii nocase
        $note3 = "bitcoin" ascii nocase
        $cmd1 = "vssadmin delete shadows" ascii
        $cmd2 = "bcdedit /set {default} recoveryenabled no" ascii
        
    condition:
        (any of ($ext*) and any of ($note*)) or
        any of ($cmd*)
}
```

**Recommended YARA Rule Categories to Develop:**
1. Redline infostealer variants
2. Vidar infostealer variants
3. Racoon infostealer variants
4. Xeno RAT detection
5. SparkRAT detection
6. Async RAT detection
7. Trickbot detection
8. LockBit 3.0 ransomware
9. RansomHub ransomware
10. Play ransomware
11. Medusa ransomware
12. Cobalt Strike beacons
13. Web shells (12% of IAB activity)
14. Impacket tool usage
15. AI-generated phishing pages
16. Deepfake-related files

## 12. Sigma Rules (not in the report)

**Note:** The report does not provide specific Sigma rules. Based on the TTPs identified, here are recommended Sigma rule examples:

```yaml
# Detection for DCSync Attack (OS Credential Dumping)
title: DCSync Attack Detection
id: 611eab06-a145-4dfa-a295-3ccc5c20f59a
status: experimental
description: Detects DCSync attacks used to dump Active Directory credentials
references:
    - Fortinet 2025 Threat Landscape Report
    - https://attack.mitre.org/techniques/T1003/006/
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: security
detection:
    selection_event:
        EventID: 4662
    selection_properties:
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
            - '89e95b76-444d-4c62-991a-0facbeda640c'  # DS-Replication-Get-Changes-In-Filtered-Set
    filter_dc:
        SubjectUserName|endswith: '$'
        SubjectUserName|startswith: 'DC'
    condition: selection_event and selection_properties and not filter_dc
falsepositives:
    - Legitimate domain controller replication
    - Authorized AD synchronization tools
level: high
tags:
    - attack.credential_access
    - attack.t1003.006

---

# Detection for DCShadow Attack
title: DCShadow Attack - Rogue Domain Controller
id: a0f8b9c3-8f3e-4c8e-9b2a-1c5d7e8f9a0b
status: experimental
description: Detects DCShadow attacks where attackers create rogue domain controllers
references:
    - Fortinet 2025 Threat Landscape Report
    - https://attack.mitre.org/techniques/T1207/
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: security
detection:
    selection_event:
        EventID:
            - 4742  # Computer account changed
            - 5137  # Directory Service object created
            - 5141  # Directory Service object deleted
    selection_attributes:
        AttributeLDAPDisplayName|contains:
            - 'ServerReference'
            - 'msDS-NcType'
            - 'nTDSDSA'
    filter_dc:
        SubjectUserName|endswith: '$'
    condition: selection_event and selection_attributes and not filter_dc
falsepositives:
    - Legitimate domain controller deployment
level: critical
tags:
    - attack.privilege_escalation
    - attack.t1207

---

# Detection for RDP Lateral Movement (88% of incidents)
title: Suspicious RDP Lateral Movement
id: c3b0f3d4-9a5e-4b7c-8d2e-1f4a5b6c7d8e
status: stable
description: Detects suspicious RDP connections indicating lateral movement
references:
    - Fortinet 2025 Threat Landscape Report
    - https://attack.mitre.org/techniques/T1021/001/
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10  # RemoteInteractive
    filter_normal:
        IpAddress|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
        SubjectUserName|endswith: '-admin'
    timeframe: 10m
    condition: selection and not filter_normal | count(SourceIP) by TargetUserName > 3
falsepositives:
    - System administrators performing legitimate tasks
    - Help desk remote support
level: medium
tags:
    - attack.lateral_movement
    - attack.t1021.001

---

# Detection for PowerShell Encoded Command Execution
title: Encoded PowerShell Command Execution
id: 1f4e5d3a-2b6c-4d8e-9f1a-3c5e7b9d0f2a
status: stable
description: Detects suspicious encoded PowerShell command execution
references:
    - Fortinet 2025 Threat Landscape Report
    - https://attack.mitre.org/techniques/T1059/001/
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: powershell
detection:
    selection_cli:
        EventID:
            - 4103
            - 4104
    selection_encoded:
        - CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
            - ' -e '
        - ScriptBlockText|contains:
            - 'FromBase64String'
            - '[Convert]::FromBase64'
    selection_suspicious:
        - CommandLine|contains:
            - 'hidden'
            - 'bypass'
```yaml
            - 'noprofile'
    condition: selection_cli and (selection_encoded or selection_suspicious)
falsepositives:
    - Legitimate administrative scripts
    - Software deployment tools
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027

---

# Detection for WMI Lateral Movement
title: WMI Remote Command Execution for Lateral Movement
id: 2e6f8b4a-3d7c-4e9b-8f1a-5c6d9e0f2b3a
status: stable
description: Detects WMI being used for remote command execution and lateral movement
references:
    - Fortinet 2025 Threat Landscape Report
    - https://attack.mitre.org/techniques/T1047/
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: sysmon
detection:
    selection_event:
        EventID: 1
    selection_wmic:
        - Image|endswith: '\wmic.exe'
          CommandLine|contains:
            - 'process call create'
            - '/node:'
            - 'path win32_process'
        - Image|endswith: '\wmiprvse.exe'
          ParentImage|endswith: '\svchost.exe'
    selection_network:
        - EventID: 3
          Image|endswith: '\wmiprvse.exe'
          DestinationPort: 135
    condition: (selection_event and selection_wmic) or selection_network
falsepositives:
    - Legitimate system administration
    - Monitoring tools
level: medium
tags:
    - attack.execution
    - attack.t1047
    - attack.lateral_movement
    - attack.t1021

---

# Detection for Impacket Tool Usage (SMB PID Anomaly)
title: Impacket Tool Usage via SMB PID Anomaly
id: 3f7e9c5b-4d8a-4e9f-8b2a-6c7d9e0f1a2b
status: experimental
description: Detects Impacket tool usage through anomalous SMB PID fields
references:
    - Fortinet 2025 Threat Landscape Report
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145  # Network share object accessed
    selection_impacket:
        - RelativeTargetName|contains:
            - 'ADMIN$'
            - 'C$'
            - 'IPC$'
        - ProcessID: '0'
        - ProcessName: ''
    condition: selection and selection_impacket
falsepositives:
    - Very rare legitimate scenarios
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.execution

---

# Detection for Cobalt Strike DNS Beaconing
title: Cobalt Strike DNS Beacon Activity
id: 4g8f0d6c-5e9b-4f0a-9c3b-7d8e9f0a1b2c
status: stable
description: Detects DNS beaconing patterns associated with Cobalt Strike
references:
    - Fortinet 2025 Threat Landscape Report
    - https://attack.mitre.org/software/S0154/
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: dns-server
detection:
    selection_pattern:
        - QueryName|re: '^[a-z0-9]{30,}\..*'
        - QueryType: 'TXT'
    selection_frequency:
        QueryName: '*'
    timeframe: 5m
    condition: selection_pattern or (selection_frequency | count(QueryName) by SourceIP > 50)
falsepositives:
    - Legitimate DNS-based applications
    - CDN services
level: high
tags:
    - attack.command_and_control
    - attack.t1071.004
    - attack.t1568.002

---

# Detection for DNS Tunneling
title: DNS Tunneling Detection
id: 5h9g1e7d-6f0c-5g1b-0d4c-8e9f0a1b2c3d
status: stable
description: Detects DNS tunneling used for C2 communication
references:
    - Fortinet 2025 Threat Landscape Report
    - https://attack.mitre.org/techniques/T1071/004/
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: dns-server
detection:
    selection_long_query:
        QueryLength: '>100'
    selection_suspicious_tld:
        QueryName|endswith:
            - '.tk'
            - '.ml'
            - '.ga'
            - '.cf'
            - '.gq'
    selection_high_entropy:
        QueryName|re: '[a-z0-9]{40,}'
    timeframe: 1m
    condition: selection_long_query or (selection_suspicious_tld and selection_high_entropy) or (count() by SourceIP > 100)
falsepositives:
    - Legitimate long domain names
    - Some CDN services
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.004
    - attack.exfiltration
    - attack.t1048.003

---

# Detection for Redline Infostealer Activity
title: Redline Infostealer Browser Credential Theft
id: 6i0h2f8e-7g1d-6h2c-1e5d-9f0a1b2c3d4e
status: experimental
description: Detects Redline infostealer accessing browser credential stores
references:
    - Fortinet 2025 Threat Landscape Report (60% of infostealer activity)
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: sysmon
detection:
    selection_file_access:
        EventID: 11  # File created
    selection_paths:
        TargetFilename|contains:
            - '\Login Data'
            - '\Cookies'
            - '\Web Data'
            - '\Local State'
            - '\wallet.dat'
    selection_process:
        Image|endswith:
            - '.exe'
        Image|contains:
            - '\Temp\'
            - '\AppData\Local\'
    filter_browsers:
        Image|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\brave.exe'
    condition: selection_file_access and selection_paths and selection_process and not filter_browsers
falsepositives:
    - Password manager applications
    - Backup software
level: high
tags:
    - attack.credential_access
    - attack.t1555.003
    - attack.collection
    - attack.t1005

---

# Detection for Web Shell Activity
title: Web Shell Deployment and Execution
id: 7j1i3g9f-8h2e-7i3d-2f6e-0a1b2c3d4e5f
status: stable
description: Detects web shell deployment and execution (12% of IAB activity)
references:
    - Fortinet 2025 Threat Landscape Report
    - https://attack.mitre.org/techniques/T1505/003/
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: sysmon
detection:
    selection_webserver:
        ParentImage|endswith:
            - '\w3wp.exe'
            - '\httpd.exe'
            - '\nginx.exe'
            - '\tomcat*.exe'
    selection_suspicious_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\net.exe'
            - '\whoami.exe'
            - '\ipconfig.exe'
    selection_file_creation:
        EventID: 11
        TargetFilename|endswith:
            - '.jsp'
            - '.jspx'
            - '.asp'
            - '.aspx'
            - '.php'
        TargetFilename|contains: '\wwwroot\'
    condition: (selection_webserver and selection_suspicious_child) or selection_file_creation
falsepositives:
    - Legitimate web application functionality
    - Management scripts
level: high
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.initial_access

---

# Detection for Kerberoasting Attack
title: Kerberoasting Attack Detection
id: 8k2j4h0g-9i3f-8j4e-3g7f-1b2c3d4e5f6g
status: stable
description: Detects Kerberoasting attacks for credential theft
references:
    - Fortinet 2025 Threat Landscape Report
    - https://attack.mitre.org/techniques/T1558/003/
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769  # Kerberos service ticket requested
        ServiceName: 'not *$'
        TicketEncryptionType: '0x17'  # RC4
        TicketOptions: '0x40810000'
    filter_machine:
        ServiceName|endswith: '$'
    timeframe: 10m
    condition: selection and not filter_machine | count(ServiceName) by TargetUserName > 5
falsepositives:
    - Legitimate service account usage
    - Legacy applications using RC4
level: high
tags:
    - attack.credential_access
    - attack.t1558.003

---

# Detection for Cloud Login from Unusual Geography (70% of cloud breaches)
title: Cloud Login from Unusual Geography
id: 9l3k5i1h-0j4g-9k5f-4h8g-2c3d4e5f6g7h
status: stable
description: Detects cloud logins from unfamiliar geographic locations
references:
    - Fortinet 2025 Threat Landscape Report (70% of cloud incidents)
author: Security Operations
date: 2025/01/01
logsource:
    product: azure
    service: signin
detection:
    selection:
        Status: 'Success'
    filter_known_locations:
        Location:
            - 'US'
            - 'IN'  # Adjust to your organization's locations
    filter_vpn:
        IPAddress|cidr:
            - '10.0.0.0/8'  # Internal VPN ranges
    timeframe: 24h
    condition: selection and not filter_known_locations and not filter_vpn
falsepositives:
    - Legitimate business travel
    - Remote workers
    - VPN services
level: medium
tags:
    - attack.initial_access
    - attack.t1078

---

# Detection for New API Activity Pattern (20% of cloud compromises)
title: New API Activity for Existing Cloud User
id: 0m4l6j2i-1k5h-0l6g-5i9h-3d4e5f6g7h8i
status: experimental
description: Detects new API calls by existing users indicating compromise
references:
    - Fortinet 2025 Threat Landscape Report (20% of cloud incidents)
author: Security Operations
date: 2025/01/01
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_sensitive_apis:
        EventName:
            - 'CreateAccessKey'
            - 'CreateUser'
            - 'PutUserPolicy'
            - 'AttachUserPolicy'
            - 'CreateRole'
            - 'UpdateAssumeRolePolicy'
            - 'GetSecretValue'
    baseline_check:
        EventName: '*'
    timeframe: 30d
    condition: selection_sensitive_apis and not baseline_check
falsepositives:
    - New legitimate administrative tasks
    - Role changes for users
level: medium
tags:
    - attack.privilege_escalation
    - attack.t1078.004
    - attack.persistence
    - attack.t1136.003

---

# Detection for Cryptojacking in Cloud (24 incidents)
title: Cloud Resource Hijacking for Cryptomining
id: 1n5m7k3j-2l6i-1m7h-6j0i-4e5f6g7h8i9j
status: stable
description: Detects cryptomining activity in cloud environments
references:
    - Fortinet 2025 Threat Landscape Report (T1496)
author: Security Operations
date: 2025/01/01
logsource:
    product: linux
    service: sysmon
detection:
    selection_process:
        EventID: 1
    selection_miners:
        - CommandLine|contains:
            - 'xmrig'
            - 'minerd'
            - 'cpuminer'
            - 'stratum+tcp'
            - 'pool.minexmr'
            - 'cryptonight'
        - Image|endswith:
            - 'xmrig'
            - 'minerd'
    selection_network:
        EventID: 3
        DestinationPort:
            - 3333
            - 4444
            - 5555
            - 7777
            - 8888
    condition: (selection_process and selection_miners) or selection_network
falsepositives:
    - Legitimate cryptocurrency research
    - Authorized mining operations
level: high
tags:
    - attack.impact
    - attack.t1496

---

# Detection for Active Directory Enumeration
title: Active Directory Reconnaissance and Enumeration
id: 2o6n8l4k-3m7j-2n8i-7k1j-5f6g7h8i9j0k
status: stable
description: Detects AD enumeration activities
references:
    - Fortinet 2025 Threat Landscape Report
    - https://attack.mitre.org/techniques/T1087/002/
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: security
detection:
    selection_ldap:
        EventID: 4662
        AccessMask: '0x100'
    selection_queries:
        - ObjectType|contains:
            - 'domainDNS'
            - 'groupPolicyContainer'
            - 'user'
            - 'group'
            - 'computer'
    selection_tools:
        - ProcessName|endswith:
            - '\net.exe'
            - '\net1.exe'
            - '\dsquery.exe'
            - '\ldapsearch.exe'
            - '\adfind.exe'
        - CommandLine|contains:
            - 'net group'
            - 'net user'
            - 'dsquery'
            - 'ldapsearch'
    timeframe: 5m
    condition: (selection_ldap and selection_queries) or (selection_tools | count() > 10)
falsepositives:
    - Legitimate administrative queries
    - Management tools
level: medium
tags:
    - attack.discovery
    - attack.t1087.002
    - attack.t1069.002

---

# Detection for IoT Device Exploitation (20% of exploitation attempts)
title: IoT Device Exploitation Attempt
id: 3p7o9m5l-4n8k-3o9j-8l2k-6g7h8i9j0k1l
status: experimental
description: Detects exploitation attempts against IoT devices
references:
    - Fortinet 2025 Threat Landscape Report (CVE-2019-18935, CVE-2017-18377)
author: Security Operations
date: 2025/01/01
logsource:
    product: network
    service: firewall
detection:
    selection_targets:
        DestinationPort:
            - 80
            - 443
            - 8080
            - 81
            - 8888
    selection_paths:
        URL|contains:
            - '/apply_sec.cgi'
            - '/goform/set_LimitClient_cfg'
            - '/cgi-bin/webproc'
            - '/command.php'
            - '/setup.cgi'
    selection_user_agents:
        UserAgent|contains:
            - 'sipvicious'
            - 'masscan'
            - 'zgrab'
    condition: selection_targets and (selection_paths or selection_user_agents)
falsepositives:
    - Security scanning tools
    - Vulnerability assessments
level: high
tags:
    - attack.initial_access
    - attack.t1190

---

# Detection for Scheduled Task Persistence
title: Suspicious Scheduled Task Creation for Persistence
id: 4q8p0n6m-5o9l-4p0k-9m3l-7h8i9j0k1l2m
status: stable
description: Detects suspicious scheduled task creation for persistence
references:
    - Fortinet 2025 Threat Landscape Report
    - https://attack.mitre.org/techniques/T1053/005/
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: security
detection:
    selection_event:
        EventID: 4698  # Scheduled task created
    selection_suspicious:
        - TaskContent|contains:
            - '\Temp\'
            - '\AppData\'
            - 'powershell'
            - 'cmd.exe'
            - 'wscript'
            - 'cscript'
        - TaskName|startswith:
            - 'WindowsUpdate'
            - 'MicrosoftUpdate'
            - 'GoogleUpdate'
        - RunLevel: 'HighestAvailable'
    filter_legitimate:
        TaskName|startswith:
            - '\Microsoft\'
            - '\Google\'
        SubjectUserName|endswith: '$'
    condition: selection_event and selection_suspicious and not filter_legitimate
falsepositives:
    - Software installation
    - Legitimate administrative tasks
level: medium
tags:
    - attack.persistence
    - attack.t1053.005
    - attack.execution

---

# Detection for Cloud Metadata API Exploitation
title: Cloud Instance Metadata API Exploitation
id: 5r9q1o7n-6p0m-5q1l-0n4m-8i9j0k1l2m3n
status: experimental
description: Detects attempts to exploit cloud metadata APIs (T1556.004)
references:
    - Fortinet 2025 Threat Landscape Report
    - https://attack.mitre.org/techniques/T1552/005/
author: Security Operations
date: 2025/01/01
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_metadata:
        UserAgent|contains:
            - 'aws-cli'
            - 'boto'
            - 'curl'
            - 'wget'
        RequestParameters|contains:
            - '169.254.169.254'
            - 'metadata.google.internal'
            - '169.254.169.254/latest/meta-data'
    selection_ssrf:
        EventName:
            - 'GetObject'
            - 'PutObject'
        RequestParameters|contains: 'http://169.254.169.254'
    condition: selection_metadata or selection_ssrf
falsepositives:
    - Legitimate instance initialization scripts
    - Management tools
level: high
tags:
    - attack.credential_access
    - attack.t1552.005

---

# Detection for Mass Credential Validation (Credential Stuffing)
title: Credential Stuffing Attack Detection
id: 6s0r2p8o-7q1n-6r2m-1o5n-9j0k1l2m3n4o
status: stable
description: Detects credential stuffing attacks from combo lists (42% increase)
references:
    - Fortinet 2025 Threat Landscape Report
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625  # Failed logon
        LogonType:
            - 3  # Network
            - 10  # RemoteInteractive
    timeframe: 5m
    condition: selection | count(TargetUserName) by SourceIP > 10
falsepositives:
    - User password reset attempts
    - Account lockout scenarios
level: high
tags:
    - attack.credential_access
    - attack.t1110.004

---

# Detection for Living Off the Land Binaries (LOLBins)
title: Living Off The Land Binary Abuse
id: 7t1s3q9p-8r2o-7s3n-2p6o-0k1l2m3n4o5p
status: stable
description: Detects abuse of legitimate Windows binaries for malicious purposes
references:
    - Fortinet 2025 Threat Landscape Report
    - https://lolbas-project.github.io/
author: Security Operations
date: 2025/01/01
logsource:
    product: windows
    service: sysmon
detection:
    selection_event:
        EventID: 1
    selection_lolbins:
        Image|endswith:
            - '\certutil.exe'
            - '\bitsadmin.exe'
            - '\mshta.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\msiexec.exe'
    selection_suspicious_args:
        CommandLine|contains:
            - '-decode'
            - 'urlcache'
            - '/transfer'
            - 'javascript:'
            - 'vbscript:'
            - 'scrobj.dll'
            - '/i:http'
    condition: selection_event and selection_lolbins and selection_suspicious_args
falsepositives:
    - Software installation
    - System administration
level: medium
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.execution
```

## Additional Sigma Rule Recommendations

Based on the Fortinet 2025 Threat Landscape Report, organizations should also develop Sigma rules for:

1. **SIPVicious VoIP Scanner Detection** (49% of scanning activity)
2. **Modbus TCP Reconnaissance** (1.6% targeting ICS/SCADA)
3. **Log4Shell Exploitation Attempts** (CVE-2021-44228 - 11.6% activity)
4. **SMB EternalBlue Exploitation** (CVE-2017-0147 - 26.7% activity)
5. **Ransomware Group Specific TTPs** (LockBit, RansomHub, Play, Medusa)
6. **APT28 Tactics** (13% of APT activity)
7. **Lazarus Group Tactics** (21% of APT activity)
8. **Volt Typhoon Infrastructure Targeting**
9. **AI-Generated Phishing Detection** (FraudGPT, WormGPT indicators)
10. **Deepfake Tool Usage** (DeepFaceLab, Faceswap, ElevenLabs)
11. **Telegram C2 Channel Detection**
12. **Initial Access Broker (IAB) Activity** (VPN/RDP access abuse)
13. **Cloud Storage Bucket Misconfiguration Exploitation**
14. **Container Escape Attempts in Cloud Environments**
15. **Kubernetes API Abuse Detection**

---

## Summary

This comprehensive analysis of the Fortinet 2025 Global Threat Landscape Report provides security teams with actionable intelligence across all aspects of cyber defense:

- **Threat Actors**: 40+ groups identified including ransomware gangs, APTs, hacktivists, and cybercrime syndicates
- **Vulnerabilities**: Focus on high-impact CVEs being actively exploited
- **Attack Patterns**: Detailed TTPs mapped to MITRE ATT&CK framework
- **Geographic/Sector Targeting**: Clear identification of most impacted regions and industries
- **Detection Strategies**: Comprehensive behavioral and signature-based detection techniques
- **Prevention Controls**: Multi-layered security controls across infrastructure, identity, and data
- **Threat Hunting**: YARA and Sigma rules for proactive threat detection

The report emphasizes that **adversaries are accelerating faster than defenders**, requiring organizations to adopt **Continuous Threat Exposure Management (CTEM)** and shift from reactive to proactive security postures.

Other links: https://nvd.nist.gov/general/nvd-dashboard
