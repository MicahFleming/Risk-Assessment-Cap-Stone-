# Risk-Assessment-Cap-Stone-
An in-depth explanation of how I would conduct a risk assessment from the perspective of a Cyber security analyst.
CapStone Project (Artemis Gas Incorporated)
Micah Razelle Fleming
Cyber Security Career Track
7/17/2023

Overview:
Me and my cyber security team of penetration testers will be responsible for gathering reliable information for our client, Artemis Gas Incorporated. The direction we’re going to take will be conducted in 5 phases: Performing Reconnaissance, Identifying Targets to Run Scans, Identifying Vulnerabilities, Doing a Threat Assessment, and lastly, Reporting everything back to the client. Before moving forward, we’ll first identify the company’s concerns.

Concerns:
Older network hardware is being phased out, is unsupported, and may have unpatched vulnerabilities.
Newer network hardware may not have been configured properly.
Some business units do not always follow company policy regarding storing data in the cloud, creating websites, or conducting file transfers. 
Some IT admin are unwilling to keep up with updated technologies and this could be exposing the network to unknown risks. 

Phase 1: Reconnaissance
My team and I will use a series of tools and methods in order to obtain as much publicly available information on Artemis Gas Inc.  as possible. I’ll list the tools and methods below.For a quick breakdown, we will first  use online resources such as the internet to find out the information we’re looking for in order to build a robust portfolio and we’ll finish the process by sitting down with Artemis’s Stakeholders, CEO’s, and Management to get the full scope of the company. As soon as we understand what it is that the company does, the technologies they use (softwares, etc), and their concerns, our cyber security team will be able to begin moving forward.
Tools/Methods:
Internet Access (Google)
Social Media-employees have profiles and information about the company’s they work at. 
News Articles
Company Website-this will provide us with a lot of information of what services they provide.
LinkedIn-this will help understand employees and work culture
Crunchbase-database of information about companies
SEC Filings- provides annual report information
Threat Intelligence Feeds
OSINT Tools-open source tools to gather information
Penetration Testing- simulated attacks to identify vulnerabilities
Social Engineering- tricking people into revealing sensitive information 
Physical Security Assessment
Incident Response Plan
Security Awareness Training
Security Policies & Procedures
Talking to company stakeholders, CEO’s, and Management
  
Artemis Gas Incorporated uses a firewall landscape which consists of Cisco, Fortinet, and Palo Alto. They use F5 (Big IP) for load balancing. For secure remote application access they use Zscaler. Half of their servers and applications are in the cloud Amazon Web Services (AWS). The large company is based in Paris France with its headquarters in Houston Texas. They’re present in 40 countries with 30,000 employees who serve more than 1.7 million customers.Their on premise assets are among the 4 major data centers (Houston, Paris, Cairo, and Singapore). The network is currently transitioning to SD-WAN so there are several MPLS links. The company is considering eliminating their Cisco gear to cut costs. For Artemis’s internal infrastructure, they use Single Sign On (SSO) solutions that leverage Microsoft Active Directory to authenticate users to the applications. SAP, the company’s primary ERP system, runs on servers running Linux & Oracle 12c. Messaging is through Office 365 & the only other applications are the PARS system and Apollo system. 

Artemis Gas Inc. contact information:
Artemis@gmail.com
(832) 582-3692
CapStone Project (Identify Targets & Run Scans)
Micah Razelle Fleming
Cyber Security Career Track
7/17/2023

Overview:
I’ll be providing a list of 5 tools that my team and I will be using to perform host discovery network scans and enumeration. There will be a follow up explaining what the tools are, their purpose, my reason for choosing them, and their limitations.

Tools(5):

Nessus is a vulnerability scanner developed by Tenable Network Security. Its purpose is to identify vulnerabilities within an organization's network system. Our Cyber Security team will use Nessus to identify things like software flaws, missing patches, and malware.
Benefits include: It can help organizations identify issues they may not be aware of. Secondly, it prioritizes vulnerabilities based on their severity.
Limitations: It can be expensive and also complex to use.

OpenVAS is also a free open source vulnerability scanner. Its purpose is used to identify and assess security vulnerabilities in computer systems and networks. We would use this tool to identify security risks. Some limitations of OpenVAS include, it can be difficult to set up, it can be slow with scanning large networks, and it’s not 100% accurate.

Metasploit is an open source framework used for penetration testing. The purpose of this tool is to exploit known vulnerabilities and mitigate security risks. Our team would implement this during our pen testing to figure out where the weak points are in the systems infrastructure. Some limitations of Metasploit include, it can be used for malicious purposes, it can be complex to use, and it can generate a lot of network traffic.

Nikto is a free open source scanner that can be used to identify security vulnerabilities on web servers. Its purpose is to scan a wide range of vulnerabilities. We’d use this to identify where patches need to happen on web servers. Some limitations of Nikto include, it cannot exploit vulnerabilities, just scan them. It’s also slow and not a replacement for security auditing. 

Lynis is a security auditing tool for Linux systems. Its purpose is to scan vulnerabilities like outdated software, misconfigurations, and dangerous files. We would use it to find weak points in the Linux operating system. Limitations in Lynis include, it can be slow, inaccurate, and it doesn’t have a graphical user interface (GUI).

CapStone (Identify Vulnerabilities)
Micah Razelle Fleming
Cyber Security Career Track
7/18/2023

Below I’ll provide a list of 5 tools that our cyber security team will use to perform vulnerability scanning. I’ll also explain what they are, their purpose, and how we’ll use them.

Nessus is a vulnerability scanner developed by Tenable Network Security. Its purpose is to identify vulnerabilities within an organization's network system. Our Cyber Security team will use Nessus to identify things like software flaws, missing patches, and malware.
Screenshot of Nessus with configuration options & settings:


Benefits include: It can help organizations identify issues they may not be aware of. Secondly, it prioritizes vulnerabilities based on their severity.
Limitations: It can be expensive and also complex to use.

Burp Suite is a collection of tools for web application security testing. Its purpose is to exploit vulnerabilities. Our team will use the Burp Suite tools to improve the organization's security. 
Screenshot of Burp Suite with configuration options & setting:

Benefits: It’s easy to use for beginners and it can be used to find the most obscure or uncertain vulnerabilities.
Limitations: It can be expensive.

OpenVAS is also a free open source vulnerability scanner. Its purpose is used to identify and assess security vulnerabilities in computer systems and networks. We would use this tool to identify security risks. Some limitations of OpenVAS include, it can be difficult to set up, it can be slow with scanning large networks, and it’s not 100% accurate.
Screenshot of OpenVAS configuration options & setting:

Metasploit is an open source framework used for penetration testing. The purpose of this tool is to exploit known vulnerabilities and mitigate security risks. Our team would implement this during our pen testing segment to figure out where the weak points are in the systems infrastructure. Some limitations of Metasploit include, it can be used for malicious purposes, it can be complex to use, and it can generate a lot of network traffic.
Screenshot of Metasploit configuration options with setting:

Nikto is a free open source scanner that can be used to identify security vulnerabilities on web servers. Its purpose is to scan a wide range of vulnerabilities. We’d use this to identify where patches need to happen on web servers. Some limitations of Nikto include, it cannot exploit vulnerabilities, just scan them. It’s also slow and not a replacement for security auditing. 
Screenshot of Nikto with configuration options & setting:



CapStone (Threat Assessment)
Micah Razelle Fleming
Cyber Security Career Track
7/21/2023

Vulnerability: A vulnerability in IT is a weak point within an organization's network, software, and systems infrastructure that can be exploited/breached by hackers, causing loss to individuals and the organization. 

Common Vulnerability Scoring System (CVSS) Score: Is the standard way within the tech field to measure the severity of a threat and the risk it poses. 
(Low, Medium, High, Severe)

Scenario 1: Unpatched RDP is exposed to the Internet.
An unpatched remote desktop protocol (RDP) is a connection that hasn’t been updated. Our Cyber Security Team has come to the conclusion that this is a high risk threat because of how detrimental it could be if attackers gained access to the exposed unpatched RDP. Also,, whatever operating system that is being used will be affected. Attackers would be able to control the remote computer, steal data, and install malware.Our penetration testers will use a vulnerability scanner to identify known RDP vulnerabilities. This will consist of finding out the IP address of the RDP server, the operating systems, and the applications installed on the server. Next we’ll develop and implement mitigation strategies with the intent of preventing this issue from happening again.
-Threat: An unpatched RDP is exposed to the internet
-CVSS Score:High
-Impact: Hackers can steal data and install malware.
-Mitigation: Use Vulnerability scanners to identify the IP addresses of the RDP servers and implement prevention strategies. 

Scenario 2: Web Application is vulnerable to SQL (Structured Query Language) Injection.
An SQL injection is an attack where code unlocks data driven applications. Malicious activity follows such as a hacker stealing finances from the owner's bank account. Our Cyber Security team has identified this as a high risk issue because it can lead to hackers having full access to people's assets, like their finances. Our team will use Nessus to scan & locate where the vulnerability is. We’ll also work with coders to ensure that the website application users login credentials are strong enough to prevent unauthorized logging or SQL injections from occurring.
-Threat: An SQL Injected a Web Application.
-CVSS Score: High
-Impact: Hackers have full access to valuable data.
-Mitigation: Install Nessus to scan and locate the vulnerability and create stronger passwords. 

Scenario 3: Default password on Cisco Admin Portal.
A default password is a pre-configured or pre-made password. Those are easy to hack so a default password on a Cisco admin portal is a high risk threat because it can be easily guessed during a loggin.This can lead to sensitive information being stolen. The likelihood of this threat occuring is high so we could assess an immediate password installation; something that is strong and advanced enough to not be easily breached. Also changing a user's password on a monthly basis will limit hacks from happening.
-Threat: An attacker uses a default password to gain access to a Cisco admin portal.
-CVSS Score: High
-Impact: The attacker could modify or delete configuration settings/steal sensitive data, and take control of the network.
-Mitigation: Change passwords regularly to something strong and difficult to guess. Also implement multi-factor authentication.

Scenario 4: Apache Web Server Vulnerable to CVE-2019-0211
CVE-2019-0211 is a local privilege escalation bug. This bug is considered to be high risk because it allows attackers to release code that accesses files shared by users. This code can also negatively affect the server's system and install malware. Our team recommends updating the Apache server to the newest version; this will fix the vulnerability. Also installing a firewall will protect the servers against the bug.
-Threat: An attacker exploits the CVE-2019-0211 vulnerability bug on an Apache Web server.
-CVSS: High
-Impact: The attacker could steal data and install malware.
-Mitigation: Upgrade the Apache web server to the newest version and install a firewall. 

Scenario 5: Web Server is exposing sensitive data
-Threat: Sensitive data, such as credit card numbers, is being exposed on a web server.
-CVSS: High
-Impact: The data could be accessed by unauthorized individuals which can lead to financial loss.
-Mitigation: Encrypt the data, limit access to the data, and monitor the web server for suspicious activity.

Scenario 6: Web Application has broken access control.
-Threat: Unauthorized individuals have access to user accounts and financial information.
-CVSS: High
-Impact: The data could be used to commit fraud or identity theft.
-Mitigation: Implement RBAC, use strong passwords, & check web applications for unusual activity.

Scenario 7: Oracle Weblogic Server vulnerable to CVE-2020-14882
CVE-2020-14882 is a remote code flaw that installs code with malicious malware.
-Threat: The CVE-2020-14882 code flaw easily exploits an Oracle Weblogic server and installs malware.
-CVSS: High
-Impact: The bug could take over the server, expose important information, like passwords, and install malware. Oracle’s operating system will be at risk as well.
Mitigation: Update the oracle weblogic server, implement security patches, and use an application firewall.

Scenario 8: Misconfigured cloud storage (AWS security group misconfiguration, lack of access restrictions)
-Threat: An attacker gains unauthorized access to cloud storage due to misconfigured AWS security groups and lack of access restrictions.
-CVSS: High
-Impact: The attacker could steal data, install malware, and take control of the system.
-Mitigation: Configure AWS security groups to allow access from authorized sources, implement access restrictions to cloud storage (stronger passwords), and monitor cloud storage for unusual activity.

Scenario 9: Microsoft Exchange Server Vulnerable to CVE-2021-26855
CVE-2021-26855 is a bug that was established to authenticate user access. This can then lead to stealing sensitive data.
-Threat: An attacker exploits the CVE-2021-26855 vulnerability to gain unauthorized access to the Microsoft Exchange Server.
-CVSS: High
-Impact: The attacker could steal data, install malware, and control the system.
-Mitigation: Apply the appropriate patches, install a web application firewall, and monitor microsoft exchange server for suspicious activity. 

Risks of Exploitation: The risk of successfully exploiting a website, server, or any IT infrastructure can be detrimental to the victim, causing sensitive information to be lost like finances, medical data, etc. Hackers gaining unauthorized access to environments they have no business being in can ruin a businesses reputation, lose them customers, and even put them out of business. 

Blocking Mechanisms: Blocking mechanisms are tools that can be implemented to prevent hackers or unauthorized access from reaching systems, data, or sensitive information. Some of these mechanisms/tools include:
Access control lists (ACL’s), Firewalls, Anti-virus (AV), Intrusion detection systems (IDS’s), Intrusion prevention systems (IPS’s), Data loss prevention (DLP), Web application firewalls (WAFs), & Application security testing (AST).

My cyber security team and I may attempt to bypass these blocking mechanisms via using:
Proxies, tunneling, obfuscation, polymorphism, and zero day attacks. Tools I can use to plan on cracking passwords include: Hashcat, John the ripper, Aircracking, and THC-Hydra.


Cap Stone: Executive Summary
Micah Razelle Fleming
Cyber Security Career Track
7/23/2023
Confidential 									Artemis Inc.
										Threat Assessment

	Executive Summary

Artemis Gas Inc. hired Cybersolvers to perform a vulnerability threat assessment to determine the risk of compromise their systems and network infrastructure is under due to internal & external issues. The assessment was conducted in July of 2023. Cybersolvers evaluated Artemis Inc. network layers using vulnerability scanning tools from their work laptops connected inside of Artemis Inc. internal corporate networks. This report provides a summary of the overall discoveries for all of the identified vulnerabilities as well as cybersolvers recommendations for critical and high risk vulnerabilities. 

Key Summary Findings & Recommendations:
Three outdated servers were identified within the network along with an unpatched (RDP) Remote Desktop Protocol exposed to the internet. Leaving the servers & RDP how they are puts Artemis Inc. network exposed due to the high risk vulnerabilities. This can lead to the company losing sensitive data as well as having their full system being compromised.

Cybersolvers Recommendations:
Update the software in the servers and patch the vulnerabilities. Implementing a consistent up to date patch management program will ensure that these vulnerabilities aren’t apparent. Keeping the program maintained will lower the risk level.

Default passwords were identified within the internal infrastructure resulting in weak login credentials & an (SQL) Structured Query Language Injection. This finding puts web applications & cloud storage at risk of being compromised. Malware can also penetrate the systems, completely erasing the database.

Cybersolvers Recommendations:
Artemis Inc. should have Nessus, the vulnerability scanner installed, while configuring a strong authenticated password process for proper protection. This will keep unauthorized users from accessing internal systems and applications.

Conclusion:
The Threat Assessment has shown that Artemis Gas Inc. has layers of protection within their networks but could use extra support to effectively mitigate risks. If the vulnerabilities are exploited by an attacker, the company’s full network can potentially be compromised. 

Artemis Gas Inc. should consider opportunities to further strengthen their applications, systems, and networks like implementing vulnerability scanning, configuration tools, and patch management, to ensure that critical/high risk vulnerabilities are professionally addressed within 30 days or less. 
Cap Stone: Technical Report
Micah Razelle Fleming
Cyber Security Career Track
7/23/2023
Table of Contents:
Phases 1-5

Phase 1: Perform Reconnaissance
-Description of all the tools and methods used to perform reconnaissance.

 Phase 2: Identify Targets & Run Scans
-Description of the tools planned on being used for network scans, the reason for selecting them, & how they’ll be used.

Phase 3: Identify Vulnerabilities
-Description of the tools planned on being used for vulnerability scans, how they’ll be used, screenshots of the tools with configuration options/settings, and the pros & cons of each tool.
Phase 4: Threat Assessment
- Documentation showing the work that was completed on the threat assessment.
Phase 5: Reporting
-Two mock reports for the client: An Executive Summary for the client’s senior management, & a Detailed Technical Report for the client’s IT staff.
Scope of Work:
Detailed Technical Report of Artemis Gas Inc.
Project Number:01234
Date:7/23/2023

Task:
The first step our Cyber security team will do is sit down with Artemis’s managers and stakeholders. We would like to discuss the errors that the company is facing within their IT infrastructure. Once we have an understanding on the issues, we’ll discuss various aspects of our IT security teams services and work products. Lastly, we’ll create a strategic plan so our penetration testers can get started on improving the quality of the company’s IT infrastructure. 
Responsibilities (Point of Contacts):
Our cyber security team, Cybersolvers, consists of 9 pen-testers:
Red team (3)
Blue team (3)
Purple team (3)

Deliverables: 
-Reconnaissance of Artemis Gas Inc.
-Target the identification of scans against the external work
-Identification of vulnerabilities
-Assessment of the threats & recommendations of Mitigations
-Execute Summary
-Detailed Technical Report
Project Objectives
	The objective of this project is to perform an external penetration test for the client, Artemis Gas Inc. As the team leader of the pen-testers within our cybersecurity firm, my responsibilities are to:
-Make sure everyone on the team knows what to do
-Ensure the amount of time allotted for the actual test is utilized as efficiently as possible.
-Guarantee the clients expectations are met or exceeded.

Assumptions
-We can assume that the networks and systems are not fully secured
-We can assume that security breaches will be attempted
-The attacker has full knowledge of the organization’s IT infrastructure and systems
-The attacker has access to publicly available information about the organization
-The hackers have the resources and skills necessary to exploit any vulnerabilities they find
-The attacker has a motive to be attacking the organization.


Schedule: (30 days)
Week 1 (1st-7th)
Week 2 (8th-15th)
Week 3 (16th-23rd)
Week 4 (24th-31st)

Change Request:
Any change request must be submitted within the third week of the project July 16th-23rd.

Approvals:
If satisfied with the services,signatures will be needed by:
-Project Manager
-Artemis Gas Inc. Stakeholders

Summary of Findings
During our Threat Assessment for Artemis Gas Inc. we discovered (9) vulnerabilities in total. Three servers in the network were outdated and there was an unpatched RDP. The other four vulnerabilities had to do with default passwords, bugs potentially breaching the network, and cloud storage data being compromised. Although we were able to identify (9) vulnerabilities, more insecurities can arise amongst the network if those aren’t effectively dealt with. The (9) vulnerabilities identified include:
Unpatched RDP
Web Application vulnerability to SQL injection
Default password on Cisco Admin Portal
Apache web server vulnerable to CVE-2019-0211
Web server is exposing sensitive data
Web application has broken access control
Oracle weblogic server vulnerable to CVE-2020-14882
Misconfigured cloud storage
Microsoft server vulnerable to CVE-2021-26855

		Recommendations
We recommend that the organization gets professional help to install vulnerability scanning tools to mitigate the insecurities. The (5) specific tools we recommend include:
(Nessus, Burp Suite, OpenVAS, Metasploit, & Nikto.) We also encourage action to be taken sooner than later; preferably in the next 30 days or less to limit more vulnerabilities from worsening.

References
https://www.sans.org/white-papers/33343/
https://www.springboard.com/workshops/cyber-security-career-track/learn/#/curriculum/27756/27762
https://www.springboard.com/workshops/cyber-security-career-track/learn/#/curriculum/27864/27867
https://www.springboard.com/archeio/download/ccdcf0619d71421ba66a4bac8e5efc18/









 



