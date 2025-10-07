# PWC Cyber Threat 2024
Report Link: https://www.pwc.com/gx/en/cyber/cyber-threats-2024.pdf
### 1. Attacker name/ Group name
*   **White Rabbit ransomware actor:** An unnamed threat actor leveraged a FortiGate vulnerability in an attack.
*   **China-based threat actors:** The report mentions these actors in the context of targeting Taiwan-based entities through FortiGate devices. The specific group "PingPong" is mentioned in a footnote.

### 2. APT Name
The report does not explicitly label the attackers exploiting Fortinet vulnerabilities as specific Advanced Persistent Threat (APT) groups.

### 3. Exploited vulnerability and it's short description
*   **Fortinet FortiPortal Vulnerability (CVE-2024-23105):** This vulnerability in Fortinet's FortiPortal management platform allowed an unauthenticated attacker to bypass IP protection.
*   **Fortinet FortiOS RCE (CVE-2024-21762):** A Remote Code Execution vulnerability in the FortiOS operating system was actively exploited by threat actors just a day after its public disclosure.
*   **Unspecified FortiGate SSL vulnerability:** Older, patched vulnerabilities in FortiGate SSL are noted as being exploited in ransomware and data breach cases.
*   **Unspecified FortiGate vulnerability (White Rabbit case):** The report states there is a "realistic probability" that the White Rabbit ransomware actor exploited one of two recently disclosed critical vulnerabilities in a FortiGate network security appliance to gain initial access.

### 4. Target country, organization, sector name etc.
*   **Taiwan:** The report mentions that China-based threat actors are likely to continue targeting Taiwan-based entities, specifically focusing on defense and government institutions, through attacks on FortiGate devices.

### 5. IOCs
The provided report does not contain any specific Indicators of Compromise (IOCs) such as file hashes, IP addresses, or domains related to the Fortinet attacks.

### 6. Attack Tactics, Techniques and Procedures
*   **Exploitation of Public-Facing Application:** Threat actors exploited vulnerabilities in Fortinet's internet-facing devices.
*   **Initial Access:** Gaining an initial foothold into networks was achieved by exploiting vulnerabilities in FortiGate appliances. In the White Rabbit ransomware case, the actor logged into the FortiGate appliance using a user account, with the vulnerability being the plausible entry point.
*   **Use of Previously Obtained Credentials:** In some instances, attackers may have used credentials obtained from initial access brokers to log into FortiGate devices.
*   **Exploitation of both zero-day and n-day vulnerabilities:** The report highlights that both newly disclosed (zero-day) and older, patched (n-day) vulnerabilities in Fortinet products were exploited.

### 7. Short summary of entire content
The PwC report indicates that in 2024, Fortinet vulnerabilities were a significant target for a range of threat actors. Both sophisticated espionage-motivated groups, particularly those based in China targeting Taiwan, and cybercriminals deploying ransomware like White Rabbit, exploited these vulnerabilities. The attacks leveraged both newly disclosed zero-day flaws and older, unpatched vulnerabilities in edge devices like FortiGate appliances to gain initial access to networks. The report underscores a trend of exploiting such perimeter devices, which are often not included in regular patch rollouts, making them attractive targets.

### 8. Recommendation/ recommended actions
The report does not provide specific recommendations for Fortinet products. However, it gives general advice for network defense, which is applicable:
*   Secure the internal environment by mapping the organization's entire architecture.
*   Ensure all devices, especially those on the "edge" of the perimeter, are patched to the latest version of their technology.
*   Consistently analyze logs of edge devices in line with guidance from trusted sources to better determine compromise in the event of a zero-day exploitation.

### 9. Detection Techniques
The report does not offer specific detection techniques for Fortinet-related threats.

### 10. Prevention techniques
The report does not offer specific prevention techniques for Fortinet-related threats beyond the general recommendation to keep systems patched.

### 11. Yara rules
The provided report does not contain any YARA rules.

### 12. Sigma rules
The provided report does not contain any Sigma rules.
