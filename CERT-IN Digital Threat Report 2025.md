# CERT-IN Digital Threat Report 2025
Report Link: https://www.cert-in.org.in/PDF/Digital_Threat_Report_2024.pdf
### 1. Attacker name/ Group name
The report mentions the following specific threat actor groups:
*   **CLOP:** A ransomware group known for launching attacks on managed file transfer (MFT) services.
*   **RansomEXX:** A ransomware group that targeted a third-party service provider in the BFSI sector through a supply chain attack.
*   The report also references malicious Large Language Models (LLMs) used by attackers, such as **WormGPT** and **FraudGPT**.

### 2. APT Name
The report does not explicitly label the mentioned groups with specific Advanced Persistent Threat (APT) designations.

### 3. Exploited vulnerability and it's short description
The report highlights several key vulnerabilities and weaknesses being actively exploited:
*   **Third-Party Software Vulnerabilities:** Exploits in managed file transfer (MFT) services like Fortra's GoAnywhere and Progress Software's MOVEit.
*   **Open-Source Library Vulnerabilities:** The compromise of the XZ Utils data compression library, which introduced a backdoor.
*   **API Vulnerabilities:** Weaknesses in API authentication, such as hardcoded keys, credential reuse, and predictable patterns. A specific technique mentioned is OTP Bypass via BOLA (Broken Object Level Authentication).
*   **Cloud Misconfigurations:** Publicly accessible storage buckets (like AWS S3), default credentials, and weak Identity and Access Management (IAM) settings leading to unauthorized access.
*   **Web Application Vulnerabilities:** Exploitation of Cross-Site Scripting (XSS) to deploy webshells and infiltrate cloud infrastructure, as well as SQL injection.
*   **Lack of Multi-Factor Authentication (MFA):** The absence or improper implementation of MFA allows attackers to use stolen credentials and session cookies to gain access to critical systems.
*   **Hardware Vulnerabilities:** Using fault injection techniques like "voltage glitching" to disrupt a device's boot process and bypass security mechanisms like Readout Protection (RDP) to extract sensitive data (e.g., from a cryptocurrency wallet).

### 4. Target country, organization, sector name etc.
*   **Target Sector:** The report's primary focus is the **Banking, Financial Services, and Insurance (BFSI) Sector**.
*   **Target Country:** The analysis covers both **India** and **global** financial institutions. Several case studies are explicitly noted as occurring "outside India."
*   **Target Organization Type:** The attacks target a wide range of entities within the BFSI ecosystem, including small financial entities, third-party service providers, fintech companies, payment service providers, and organizations using digital wallets and reward points systems.

### 5. IOCs
The report is a strategic overview and does not provide specific, tactical Indicators of Compromise (IOCs) like file hashes, IP addresses, or malicious domains.

### 6. Attack Tactics, Techniques and Procedures
The report details a shift towards more sophisticated and blended TTPs:
*   **Social Engineering:** This is a dominant trend, featuring Business Email Compromise (BEC) with pretexting, and highly convincing phishing campaigns enhanced by AI to mimic tone and style.
*   **Supply Chain Attacks:** A primary vector where attackers compromise a trusted third-party vendor or open-source library to inject malicious code, which is then distributed to the vendor's clients.
*   **Credential Theft and Abuse:** Attackers acquire credentials via phishing or dark web purchases and use them to access VPNs, email accounts, and SaaS platforms. They also use session hijacking to bypass MFA.
*   **Ransomware with Double Extortion:** Attackers first encrypt critical files and databases and then threaten to leak the stolen sensitive client data if the ransom is not paid.
*   **Man-in-the-Middle (MITM) Attacks:** Intercepting and altering transaction data in real-time to manipulate outcomes, such as inflating cashback reward values.
*   **Insider Threats:** Malicious insiders abusing administrative privileges to manipulate dormant accounts, create fraudulent transactions, and erase logs to cover their tracks.
*   **API Replay Attacks:** Replicating legitimate API calls to execute unauthorized transfers or actions, bypassing security checks.
*   **Hardware Hacking:** Physically manipulating devices using fault injection to force the system into an insecure state and extract cryptographic keys or other secrets from RAM.

### 7. Short summary of entire content
The Digital Threat Report 2024 provides a comprehensive analysis of the evolving cyber threats facing the BFSI sector in India and globally. It highlights a significant shift towards social engineering, credential theft, and sophisticated supply chain attacks. A key theme is the impact of Artificial Intelligence (AI), which lowers the barrier for less-skilled actors to create convincing deepfakes, phishing lures, and polymorphic malware using malicious LLMs like WormGPT.

The report uses eight detailed case studies—from ransomware attacks via the supply chain to hardware hacks on crypto wallets—to illustrate how attackers exploit vulnerabilities across core banking, payment processing, cloud infrastructure, and third-party integrations. It identifies persistent gaps in fundamental security controls, including inadequate MFA, poor cloud configurations, and slow vulnerability patching. Looking ahead to 2025, the report anticipates a rise in AI-driven attacks, LLM prompt hacking, and threats from quantum computing. The document concludes with actionable recommendations structured around People, Process, and Technology to help organizations build a resilient, forward-thinking cybersecurity posture.

### 8. Recommendation/ recommended actions
The report provides extensive recommendations to strengthen cybersecurity posture, categorized as follows:
*   **People (Awareness, Training, and Culture):**
    *   Increase the frequency of security training to quarterly instead of annually.
    *   Strengthen risk management and governance with direct CISO reporting to the CEO/CRO.
    *   Focus on securing remote and hybrid work environments.
*   **Process (Policies, Procedures, and Governance):**
    *   Accelerate vulnerability assessment timeframes from quarterly to weekly or daily.
    *   Develop comprehensive incident response playbooks for various scenarios.
    *   Integrate threat intelligence feeds (e.g., from CERT-In) into monitoring.
    *   Implement a defense-in-depth strategy and adopt a Zero Trust Architecture (ZTA).
*   **Technology (Tools, Systems, and Solutions):**
    *   Accelerate patching of network devices (firewalls, VPNs).
    *   Implement AI-powered anomaly detection and dark web monitoring.
    *   Strengthen Application and API Security with strong authentication (OAuth, JWT) and security testing (DAST).
    *   Enforce MFA across all sensitive financial operations and remote access.
    *   Deploy robust Endpoint and Email Security, including application whitelisting.

### 9. Detection Techniques
*   **Log Monitoring and Anomaly Detection:** Implement centralized logging for all critical systems and retain logs for at least 180 days. Use AI-powered systems to detect unusual patterns in user behavior and system events.
*   **Network and Endpoint Detection:** Deploy advanced security systems like Intrusion Detection/Prevention Systems (IDS/IPS), Network Detection and Response (NDR), and Endpoint Detection and Response (EDR) for enhanced threat detection.
*   **Dark Web Monitoring:** Proactively monitor the dark web for compromised credentials to enable rapid password resets.

### 10. Prevention techniques
*   **Multi-Factor Authentication (MFA):** Enforce MFA for all VPNs, webmail, cloud services, and accounts accessing critical systems.
*   **Network Segmentation:** Segment networks into security zones using VLANs to separate administrative networks from business processes, limiting lateral movement.
*   **Application Whitelisting:** Enforce whitelisting on endpoints to block the execution of unauthorized software.
*   **Data Protection and Encryption:** Encrypt sensitive data at rest and in transit. Use tokenization or Transparent Data Encryption (TDE) for sensitive database fields.
*   **Virtual Patching:** Use virtual patching to protect legacy systems and applications that cannot be immediately updated.
*   **Least Privilege Access Control:** Enforce strict role-based access controls (RBAC) and the principle of least privilege to minimize risk from compromised accounts and insider threats.
*   **API Security:** Secure APIs with strong authentication, encrypt keys, and properly configure Cross-Origin Resource Sharing (CORS) to restrict access to specific domains.

### 11. Yara rules
The provided report does not contain any YARA rules.

### 12. Sigma rules
The provided report does not contain any Sigma rules.

References:

https://www.auditboard.com/blog/security-vs-compliance/

https://www.tripwire.com/state-of-security/compliance-vs-security-striking-right-balance-cybersecurity

https://www.scrut.io/post/how-to-prevent-cyberattacks-by-balancing-security-and-compliance

https://www.securitymagazine.com/articles/99259-compliance-and-security-are-two-sides-of-the-same-coin

https://www.tripwire.com/resources/guides/mind-the-cybersecurity-compliance-gap

https://www.csoonline.com/article/1309993/grc-impact-and-challenges-to-cybersecurity.html

https://www.mckinsey.com/industries/financial-services/our-insights/global-payments-in-2024-simpler-interfaces-complex-reality

https://cxotoday.com/interviews/turning-data-breaches-into-opportunities-strategies-for-indian-businesses-to-strengthen-cybersecurity-and-reduce-risks/

https://www.scworld.com/resource/building-cybersecurity-resilience-strategies-technologies-and-best-practices-from-industry-leaders

https://www.techtarget.com/searchsecurity/tip/5-tips-for-building-a-cybersecurity-culture-at-your-company

https://www.weforum.org/stories/2024/04/cybersecurity-key-strategies-cyber-resilience-2024/

https://www.techtarget.com/searchsecurity/feature/Security-posture-management-a-huge-challenge-for-IT-pros

https://www.techtarget.com/healthtechsecurity/feature/Navigating-cyber-insurance-coverage-as-threats-evolve

https://www.helpnetsecurity.com/2024/07/05/iot-security-privacy-challenges/

https://www.paloaltonetworks.com/cybersecurity-perspectives/how-to-secure-iot-in-financial-services

https://securityintelligence.com/articles/what-are-the-risks-of-the-iot-in-financial-services/

https://www.statista.com/statistics/1183457/iot-connected-devices-worldwide/
