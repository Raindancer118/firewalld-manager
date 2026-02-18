"""Port risk assessment database for firewalld-manager.

Risk scores range from 0 (no risk) to 100 (critical/root-level risk).

Risk factors considered:
- History of remote code execution (RCE) vulnerabilities
- Unauthenticated access or default credentials risk
- Privilege escalation to root
- Exposure of sensitive data or credentials
- Protocol-level attack surface (cleartext, weak auth)
- Common attack target in the wild
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class RiskAssessment:
    port: str
    proto: str
    score: int          # 0–100
    label: str          # e.g. "CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"
    summary: str        # One-line summary
    explanation: str    # Detailed explanation
    cves: list[str]     # Notable CVEs (not exhaustive)


def _label(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 45:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "MINIMAL"


# ---------------------------------------------------------------------------
# Risk database: keyed by "port/proto" (e.g. "22/tcp")
# Ports not in this database get a default assessment based on port range.
# ---------------------------------------------------------------------------

_RISK_DB: dict[str, dict] = {
    # -----------------------------------------------------------------------
    # CRITICAL (90–100): direct root/system access or trivially exploitable
    # -----------------------------------------------------------------------
    "23/tcp": {
        "score": 98,
        "summary": "Telnet – cleartext, no encryption, trivially sniffable",
        "explanation": (
            "Telnet transmits all data, including passwords, in cleartext. "
            "Any network observer can capture credentials and gain full shell access. "
            "There are no modern use cases that justify exposing Telnet publicly. "
            "Replace with SSH (port 22) immediately. "
            "Historically used for initial router/switch access; frequently exploited by Mirai and similar botnets."
        ),
        "cves": ["CVE-2020-10188", "CVE-2011-4862"],
    },
    "512/tcp": {
        "score": 97,
        "summary": "rexec – remote execution with cleartext credentials",
        "explanation": (
            "The rexec service allows remote command execution using username/password "
            "transmitted in cleartext over the network. Any attacker who can sniff the "
            "traffic gains full credentials. Even on trusted networks, this protocol is "
            "considered obsolete and dangerous. No modern system should expose this."
        ),
        "cves": [],
    },
    "513/tcp": {
        "score": 96,
        "summary": "rlogin – unauthenticated remote login via trust relationships",
        "explanation": (
            "rlogin uses .rhosts trust relationships to allow passwordless remote login. "
            "An attacker who can spoof an IP address of a trusted host gains immediate "
            "shell access without any credentials. IP spoofing combined with rlogin has "
            "been a classic attack vector since the Morris Worm era (1988)."
        ),
        "cves": [],
    },
    "514/tcp": {
        "score": 95,
        "summary": "rsh – remote shell with no authentication",
        "explanation": (
            "Like rlogin, rsh relies on .rhosts trust rather than passwords. "
            "An attacker who spoofs a trusted host's IP can execute arbitrary commands "
            "as the target user. Combined with root .rhosts entries (which were common "
            "historically), this grants immediate root access."
        ),
        "cves": [],
    },
    "3389/tcp": {
        "score": 93,
        "summary": "RDP – frequent ransomware/brute-force target with RCE history",
        "explanation": (
            "Remote Desktop Protocol (RDP) is one of the most commonly exploited services "
            "on the internet. Vulnerabilities like BlueKeep (CVE-2019-0708) allow "
            "pre-authentication remote code execution as SYSTEM (root equivalent on Windows). "
            "Even patched systems face constant brute-force attacks. "
            "If exposure is necessary, use a VPN or restrict to specific source IPs. "
            "Shodan consistently shows millions of exposed RDP endpoints."
        ),
        "cves": ["CVE-2019-0708", "CVE-2019-1181", "CVE-2019-1182", "CVE-2012-0002"],
    },
    "445/tcp": {
        "score": 92,
        "summary": "SMB – EternalBlue/WannaCry, direct root equivalent access",
        "explanation": (
            "SMB (Server Message Block) was exploited by EternalBlue (NSA exploit leaked "
            "by Shadow Brokers) to create WannaCry and NotPetya ransomware outbreaks. "
            "CVE-2017-0144 allows unauthenticated remote code execution as SYSTEM. "
            "Even on patched systems, SMB exposes credential hashes to relay attacks (NTLM relay). "
            "Never expose SMB to the internet. On Linux (Samba), similar critical vulnerabilities "
            "have allowed remote root access (CVE-2017-7494 'SambaCry')."
        ),
        "cves": ["CVE-2017-0144", "CVE-2017-7494", "CVE-2020-0796"],
    },
    "6000/tcp": {
        "score": 91,
        "summary": "X11 – display server, trivial remote desktop takeover",
        "explanation": (
            "An exposed X11 server allows any connecting client to capture keystrokes, "
            "take screenshots, inject mouse/keyboard events, and potentially execute "
            "commands via xterm or similar. No authentication is required by default. "
            "This effectively grants full graphical session control to anyone who can connect."
        ),
        "cves": [],
    },

    # -----------------------------------------------------------------------
    # HIGH (70–89): significant risk, well-known attack vectors
    # -----------------------------------------------------------------------
    "21/tcp": {
        "score": 82,
        "summary": "FTP – cleartext credentials, frequent RCE vulnerabilities",
        "explanation": (
            "FTP transmits username and password in cleartext. "
            "Anonymous FTP is a common misconfiguration that allows anyone to upload files. "
            "FTP has a long history of vulnerabilities including buffer overflows granting root access "
            "(e.g. ProFTPd, wu-ftpd). Even authenticated FTP exposes credentials to network sniffing. "
            "Replace with SFTP (SSH file transfer, port 22) or FTPS (FTP over TLS)."
        ),
        "cves": ["CVE-2010-4221", "CVE-2015-3306", "CVE-2011-4130"],
    },
    "22/tcp": {
        "score": 35,
        "summary": "SSH – encrypted, but constant brute-force target",
        "explanation": (
            "SSH itself is well-designed and encrypted. The main risks are:\n"
            "1. Brute-force attacks on weak/default passwords (bots scan constantly)\n"
            "2. Older OpenSSH versions with known vulnerabilities\n"
            "3. Misconfigured PermitRootLogin=yes\n"
            "Mitigations: disable password auth (use keys only), use fail2ban, "
            "restrict source IPs if possible, keep OpenSSH updated. "
            "Risk is relatively low if properly configured."
        ),
        "cves": ["CVE-2023-38408", "CVE-2016-0777"],
    },
    "25/tcp": {
        "score": 72,
        "summary": "SMTP – open relay risk, spam, credential exposure",
        "explanation": (
            "An exposed SMTP server that allows unauthenticated relay becomes a spam relay, "
            "consuming bandwidth and getting your IP blacklisted. "
            "SMTP authentication sends credentials that may be intercepted if TLS is not enforced. "
            "Sendmail and older MTAs have had critical remote RCE vulnerabilities. "
            "If running mail, use submission port 587 with STARTTLS instead."
        ),
        "cves": ["CVE-2014-3566", "CVE-2011-1720"],
    },
    "53/tcp": {
        "score": 65,
        "summary": "DNS (TCP) – amplification, zone transfer, cache poisoning",
        "explanation": (
            "TCP port 53 is used for DNS zone transfers and large DNS responses. "
            "Allowing unrestricted zone transfers (AXFR) leaks your entire DNS infrastructure. "
            "DNS servers have had remote code execution vulnerabilities (BIND has a long history). "
            "DNS is also used in amplification DDoS attacks. "
            "Restrict zone transfers to authorized secondaries only."
        ),
        "cves": ["CVE-2020-8625", "CVE-2021-25216", "CVE-2016-2776"],
    },
    "53/udp": {
        "score": 60,
        "summary": "DNS (UDP) – amplification attacks, cache poisoning",
        "explanation": (
            "UDP/53 is the standard DNS query port. While necessary for DNS resolution, "
            "exposing it publicly without rate limiting enables DNS amplification DDoS attacks "
            "(small query → large response, traffic directed at victim). "
            "Cache poisoning attacks (Kaminsky attack, CVE-2008-1447) can redirect traffic. "
            "Only expose if running a public recursive resolver or authoritative DNS server."
        ),
        "cves": ["CVE-2008-1447", "CVE-2020-8617"],
    },
    "110/tcp": {
        "score": 70,
        "summary": "POP3 – cleartext email credentials",
        "explanation": (
            "POP3 without TLS sends email credentials in cleartext. "
            "An attacker on the same network segment can trivially capture email passwords. "
            "Use POP3S (port 995) instead. "
            "Some POP3 daemons have had buffer overflow vulnerabilities allowing remote access."
        ),
        "cves": [],
    },
    "111/tcp": {
        "score": 80,
        "summary": "RPC portmapper – exposes all RPC services, NFS attack gateway",
        "explanation": (
            "The RPC portmapper/rpcbind service maps RPC program numbers to port numbers. "
            "It acts as a directory service for all other RPC services (NFS, NIS, etc.). "
            "Exposing this allows attackers to enumerate all available RPC services. "
            "Combined with NFS misconfigurations, this historically allowed complete filesystem access. "
            "Many severe vulnerabilities have been found in rpcbind itself."
        ),
        "cves": ["CVE-2017-8779"],
    },
    "111/udp": {
        "score": 78,
        "summary": "RPC portmapper (UDP) – service enumeration, DoS amplification",
        "explanation": (
            "Same risks as TCP/111 (RPC portmapper), with additional UDP amplification risk. "
            "The portmapper can be abused for UDP amplification DDoS attacks due to response size. "
            "Restrict access to trusted networks only."
        ),
        "cves": [],
    },
    "135/tcp": {
        "score": 85,
        "summary": "MS-RPC endpoint mapper – direct exploitation vector on Windows",
        "explanation": (
            "The Windows RPC endpoint mapper has been a primary attack vector for worms "
            "like Blaster (CVE-2003-0352) which exploited it for remote code execution as SYSTEM. "
            "It also enables DCOM exploitation and is used in lateral movement. "
            "Never expose port 135 to the internet."
        ),
        "cves": ["CVE-2003-0352"],
    },
    "137/udp": {
        "score": 75,
        "summary": "NetBIOS Name Service – Windows credential/information leakage",
        "explanation": (
            "NetBIOS Name Service allows enumeration of Windows hostnames and workgroups. "
            "Attackers can use it to identify Windows systems and gather information for targeted attacks. "
            "Combined with SMB, enables NTLM relay attacks to capture and relay credentials."
        ),
        "cves": [],
    },
    "139/tcp": {
        "score": 85,
        "summary": "NetBIOS Session Service – SMB predecessor, credential attacks",
        "explanation": (
            "Port 139 provides SMB over NetBIOS, an older form of the Windows file sharing protocol. "
            "It has many of the same risks as port 445 (SMB): credential relay, enumeration, "
            "and historical RCE vulnerabilities. Should not be exposed to the internet."
        ),
        "cves": [],
    },
    "143/tcp": {
        "score": 65,
        "summary": "IMAP – cleartext email access without TLS",
        "explanation": (
            "IMAP without TLS sends credentials and email content in cleartext. "
            "Use IMAPS (port 993) instead. "
            "Some IMAP servers (Cyrus, Dovecot) have had remote vulnerabilities. "
            "If exposed, ensure TLS is enforced and passwords are strong."
        ),
        "cves": ["CVE-2019-19722"],
    },
    "161/udp": {
        "score": 75,
        "summary": "SNMP – default community strings expose full device control",
        "explanation": (
            "SNMP v1 and v2c use 'community strings' (effectively passwords) that are often left "
            "at defaults ('public' for read, 'private' for write). With write access, an attacker "
            "can reconfigure network devices. Even read access reveals network topology, "
            "routing tables, and configuration details useful for further attacks. "
            "Use SNMPv3 with authentication and encryption."
        ),
        "cves": ["CVE-2017-6736", "CVE-2002-0013"],
    },
    "389/tcp": {
        "score": 70,
        "summary": "LDAP – directory enumeration, credential exposure without TLS",
        "explanation": (
            "An exposed LDAP server allows attackers to enumerate users, groups, and organizational "
            "structure. Without TLS, credentials are transmitted in cleartext (LDAP simple bind). "
            "Attackers use anonymous LDAP access to harvest email addresses and usernames for "
            "password spraying attacks. Use LDAPS (port 636) and restrict access."
        ),
        "cves": ["CVE-2021-44228"],  # log4shell via LDAP
    },
    "443/tcp": {
        "score": 15,
        "summary": "HTTPS – encrypted web traffic, low risk if properly configured",
        "explanation": (
            "HTTPS (HTTP over TLS) is the standard for secure web communication. "
            "Risks depend entirely on the web application served:\n"
            "- Outdated TLS (SSLv3, TLS 1.0) is vulnerable to POODLE, BEAST attacks\n"
            "- Weak cipher suites can be downgraded\n"
            "- Web application vulnerabilities (SQLi, XSS, RCE) are independent of TLS\n"
            "Keep TLS configuration up to date, use TLS 1.2+ with strong ciphers. "
            "Use Mozilla SSL Config Generator for recommended settings."
        ),
        "cves": ["CVE-2014-3566"],  # POODLE
    },
    "465/tcp": {
        "score": 30,
        "summary": "SMTPS – SMTP over TLS, submission port",
        "explanation": (
            "Port 465 (SMTPS) provides SMTP with implicit TLS for email submission. "
            "This is the preferred secure alternative to port 25 for email clients. "
            "Risks are moderate: brute-force on credentials, spam relay if authentication is weak. "
            "Ensure strong authentication and rate limiting."
        ),
        "cves": [],
    },
    "514/udp": {
        "score": 55,
        "summary": "Syslog – log injection, information disclosure",
        "explanation": (
            "The syslog protocol (UDP) has no authentication. "
            "Anyone can send arbitrary log messages, enabling log injection attacks. "
            "Receiving logs over UDP also means an attacker can flood the log server (DoS). "
            "Use encrypted, authenticated syslog (e.g. over TLS/TCP, port 6514)."
        ),
        "cves": [],
    },
    "1433/tcp": {
        "score": 85,
        "summary": "MS SQL Server – frequent RCE target, credential brute-force",
        "explanation": (
            "Microsoft SQL Server exposed to the internet is a high-value target. "
            "SQL Server has had numerous remote code execution vulnerabilities. "
            "The 'sa' (system administrator) account with a blank or weak password "
            "grants xp_cmdshell access for arbitrary OS command execution. "
            "SQL injection in connected applications often pivots to the database. "
            "Never expose SQL Server directly to the internet."
        ),
        "cves": ["CVE-2020-0618", "CVE-2019-1068"],
    },
    "1521/tcp": {
        "score": 82,
        "summary": "Oracle DB – TNS listener poisoning, credential attacks",
        "explanation": (
            "Oracle Database listener (TNS) has had vulnerabilities including listener "
            "poisoning attacks that redirect connections. Default credentials (scott/tiger, "
            "system/manager) are commonly found. With DBA access, attackers can execute OS "
            "commands. Never expose Oracle listener to the internet."
        ),
        "cves": ["CVE-2012-1675"],
    },
    "2049/tcp": {
        "score": 80,
        "summary": "NFS – filesystem access with weak authentication",
        "explanation": (
            "NFS (Network File System) relies on IP-based access control and UID mapping. "
            "An attacker who can connect from a trusted IP (or spoof it) gains full filesystem "
            "access to exported shares. Root squashing helps but is often misconfigured. "
            "NFS v3 has no encryption or strong authentication. "
            "Never expose NFS to the internet; restrict to trusted VLANs."
        ),
        "cves": [],
    },
    "2049/udp": {
        "score": 78,
        "summary": "NFS (UDP) – same risks as TCP, plus amplification attacks",
        "explanation": (
            "Same risks as TCP/2049 (NFS) with additional UDP amplification risk. "
            "NFS over UDP is even less reliable and should be avoided on modern systems."
        ),
        "cves": [],
    },
    "3306/tcp": {
        "score": 78,
        "summary": "MySQL/MariaDB – credential attacks, data exfiltration",
        "explanation": (
            "MySQL/MariaDB exposed to the internet faces constant brute-force attacks. "
            "The 'root' account without a password is a common misconfiguration. "
            "With database access, attackers can exfiltrate all data, write files via "
            "SELECT INTO OUTFILE (potential code execution if writable webroot), "
            "and use UDFs (User Defined Functions) for OS command execution. "
            "Bind MySQL to localhost (127.0.0.1) only."
        ),
        "cves": ["CVE-2012-2122", "CVE-2016-6662"],
    },
    "4444/tcp": {
        "score": 90,
        "summary": "Metasploit default shell port – strongly associated with malware/backdoors",
        "explanation": (
            "Port 4444 is the default listener port for Metasploit Framework reverse shells "
            "and many malware families (including older variants of the Blaster worm). "
            "An open port 4444 is a strong indicator of compromise or an active backdoor. "
            "There are no legitimate services that use this port by convention. "
            "Investigate immediately if this port is open on any production system."
        ),
        "cves": [],
    },
    "4899/tcp": {
        "score": 88,
        "summary": "Radmin – remote admin, historically exploited without auth",
        "explanation": (
            "Radmin (Remote Administrator) provides full remote desktop control. "
            "Older versions had authentication bypass vulnerabilities allowing complete "
            "system control without credentials. Used by attackers as a backdoor. "
            "Exposed Radmin endpoints are common in ransomware intrusions."
        ),
        "cves": [],
    },
    "5432/tcp": {
        "score": 72,
        "summary": "PostgreSQL – credential attacks, COPY TO/FROM for file access",
        "explanation": (
            "PostgreSQL exposed to the internet faces brute-force attacks. "
            "With superuser access, the COPY command can read/write arbitrary files, "
            "and the lo_import/lo_export functions provide filesystem access. "
            "pg_read_file() can read PostgreSQL data directory files. "
            "Bind to localhost only; never expose to the internet."
        ),
        "cves": ["CVE-2019-9193", "CVE-2016-5423"],
    },
    "5900/tcp": {
        "score": 85,
        "summary": "VNC – often unencrypted, weak auth, frequent attack target",
        "explanation": (
            "VNC (Virtual Network Computing) provides graphical desktop access. "
            "Many VNC servers use weak or no authentication by default. "
            "The protocol is often unencrypted, exposing the session to sniffing. "
            "VNC has had numerous authentication bypass vulnerabilities. "
            "Shodan shows millions of open VNC endpoints, many with no authentication. "
            "Use SSH tunneling for VNC access instead of direct exposure."
        ),
        "cves": ["CVE-2019-15681", "CVE-2006-2369"],
    },
    "6379/tcp": {
        "score": 88,
        "summary": "Redis – no auth by default, arbitrary command execution",
        "explanation": (
            "Redis has no authentication by default and listens on all interfaces. "
            "An unauthenticated attacker can:\n"
            "1. Read/write/delete all data in memory\n"
            "2. Write arbitrary files via CONFIG SET dir / CONFIG SET dbfilename\n"
            "3. Write SSH authorized_keys to gain SSH access\n"
            "4. Write cron jobs for command execution\n"
            "5. Use module loading for direct code execution\n"
            "Redis has been trivially exploited to root thousands of servers. "
            "Bind to localhost only. Enable requirepass in redis.conf."
        ),
        "cves": ["CVE-2022-0543", "CVE-2016-10517"],
    },
    "8080/tcp": {
        "score": 45,
        "summary": "HTTP alternate – often dev/proxy servers with weak auth",
        "explanation": (
            "Port 8080 is commonly used for HTTP proxy servers, development web servers, "
            "and alternative web interfaces (Tomcat, Jenkins, proxy). "
            "Dev servers often lack authentication. Jenkins, if exposed, has had "
            "script console access allowing arbitrary command execution. "
            "Risk depends entirely on what service is running on this port."
        ),
        "cves": ["CVE-2019-1003000"],
    },
    "8443/tcp": {
        "score": 35,
        "summary": "HTTPS alternate – similar to 443, depends on application",
        "explanation": (
            "Port 8443 is commonly used as an alternate HTTPS port for admin interfaces, "
            "Tomcat SSL, and similar services. Risk depends on the specific application. "
            "Admin interfaces on this port may have weaker authentication."
        ),
        "cves": [],
    },
    "9200/tcp": {
        "score": 87,
        "summary": "Elasticsearch – no auth by default, complete data exposure",
        "explanation": (
            "Elasticsearch has no authentication or TLS by default. "
            "An attacker can read, modify, or delete all indexed data without credentials. "
            "Elasticsearch also exposes a scripting interface (Groovy/Painless) that has "
            "been exploited for remote code execution (CVE-2014-3120, CVE-2015-1427). "
            "Billions of records have been exposed due to misconfigured Elasticsearch. "
            "Enable X-Pack security and bind to localhost only."
        ),
        "cves": ["CVE-2015-1427", "CVE-2014-3120"],
    },
    "27017/tcp": {
        "score": 86,
        "summary": "MongoDB – no auth by default, complete data exposure",
        "explanation": (
            "MongoDB has no authentication by default and historically listened on all interfaces. "
            "Attackers have automated mass-scanning and data wiping campaigns against exposed MongoDB. "
            "Ransomware-style attacks have deleted entire databases from unprotected MongoDB instances. "
            "Enable authentication (--auth flag) and bind to localhost. "
            "Hundreds of millions of records have been exposed via misconfigured MongoDB."
        ),
        "cves": ["CVE-2019-2392"],
    },
    "11211/tcp": {
        "score": 80,
        "summary": "Memcached – no auth, UDP amplification, data exposure",
        "explanation": (
            "Memcached has no authentication and caches potentially sensitive application data. "
            "Attackers can read cached data (session tokens, user data) and inject malicious content. "
            "UDP/11211 is used for massive DDoS amplification attacks (factor 51,000x). "
            "The 2018 GitHub DDoS attack used Memcached amplification. "
            "Bind to localhost only; disable UDP if not needed."
        ),
        "cves": ["CVE-2018-1000115"],
    },
    "11211/udp": {
        "score": 90,
        "summary": "Memcached UDP – 51,000x amplification factor DDoS weapon",
        "explanation": (
            "Memcached UDP port is one of the most dangerous amplification vectors known. "
            "A 15-byte UDP request can generate a 750KB+ response, providing a 51,000x "
            "amplification factor. The 2018 GitHub DDoS attack peaked at 1.35 Tbps using "
            "Memcached reflection/amplification. Disable UDP on Memcached immediately."
        ),
        "cves": ["CVE-2018-1000115"],
    },
    "8888/tcp": {
        "score": 60,
        "summary": "Jupyter Notebook – often runs without auth, full code execution",
        "explanation": (
            "Jupyter Notebook/Lab provides an interactive Python execution environment. "
            "Default installations before recent versions had no authentication. "
            "An exposed Jupyter instance allows arbitrary Python code execution under "
            "the web server's user account. This grants full filesystem access, "
            "network access, and potential privilege escalation. "
            "Always use token/password authentication and never expose publicly."
        ),
        "cves": ["CVE-2022-24758"],
    },
    # -----------------------------------------------------------------------
    # MEDIUM (45–69): notable risks, context-dependent
    # -----------------------------------------------------------------------
    "80/tcp": {
        "score": 25,
        "summary": "HTTP – cleartext web traffic, app vulnerabilities",
        "explanation": (
            "HTTP transmits data in cleartext (no encryption). "
            "The main risks are:\n"
            "1. Web application vulnerabilities (SQLi, XSS, RCE) – depends on the app\n"
            "2. Credential sniffing if login forms use HTTP\n"
            "3. Man-in-the-middle attacks\n"
            "HTTP itself is not inherently dangerous for serving public content, "
            "but should redirect to HTTPS for any authenticated functionality. "
            "Risk is primarily from the web application, not the port itself."
        ),
        "cves": [],
    },
    "8000/tcp": {
        "score": 40,
        "summary": "HTTP dev server – common for development, often unauthenticated",
        "explanation": (
            "Port 8000 is commonly used for development HTTP servers (Django dev server, "
            "Python http.server, etc.). These typically have no authentication and may expose "
            "sensitive development resources. Django dev server was never intended for production "
            "and has known security weaknesses."
        ),
        "cves": [],
    },
    "631/tcp": {
        "score": 48,
        "summary": "CUPS printing – RCE vulnerabilities in 2024, admin interface exposure",
        "explanation": (
            "CUPS (Common UNIX Printing System) has had critical remote code execution "
            "vulnerabilities. In September 2024, a chain of vulnerabilities (CVE-2024-47176, "
            "CVE-2024-47076, CVE-2024-47175, CVE-2024-47177) allowed unauthenticated RCE "
            "by sending a malicious UDP packet to port 631 (browsed), and then having a user "
            "print to the malicious printer. The web admin interface (TCP/631) can be exposed "
            "without authentication by default."
        ),
        "cves": ["CVE-2024-47176", "CVE-2024-47076", "CVE-2024-47175", "CVE-2024-47177"],
    },
    "631/udp": {
        "score": 62,
        "summary": "CUPS browsed – UDP 631 triggers RCE chain (CVE-2024-47176)",
        "explanation": (
            "CVE-2024-47176: cups-browsed binds to UDP 0.0.0.0:631 by default. "
            "An unauthenticated attacker can send a specially crafted UDP packet to trigger "
            "the system to connect to an attacker-controlled IPP server, which then causes "
            "arbitrary command execution when a print job is initiated. "
            "This is the entry point for the 2024 CUPS RCE chain. "
            "Disable cups-browsed if not needed."
        ),
        "cves": ["CVE-2024-47176"],
    },
    "5353/udp": {
        "score": 30,
        "summary": "mDNS – local network discovery, information leakage",
        "explanation": (
            "mDNS (Multicast DNS) is used for local network service discovery (Bonjour/Avahi). "
            "It leaks information about services running on the host (hostnames, service types). "
            "On a local network this is usually acceptable; exposed to the internet it provides "
            "reconnaissance information. mDNS responders have had vulnerabilities (CVE-2017-14315)."
        ),
        "cves": ["CVE-2017-14315"],
    },
    "9090/tcp": {
        "score": 55,
        "summary": "Cockpit/Prometheus – admin interfaces with auth requirements",
        "explanation": (
            "Port 9090 is used by Cockpit (Linux web admin panel) and Prometheus. "
            "Cockpit requires authentication but has had vulnerabilities. "
            "Prometheus has no built-in authentication and exposes metrics about the system. "
            "An attacker with Prometheus access gets detailed system telemetry."
        ),
        "cves": ["CVE-2021-3698"],
    },
    "2375/tcp": {
        "score": 98,
        "summary": "Docker API (unencrypted) – immediate container escape to root",
        "explanation": (
            "The Docker daemon API on port 2375 has NO authentication by default. "
            "An attacker with access can:\n"
            "1. Create containers with host filesystem mounted\n"
            "2. Escape to root on the host in seconds\n"
            "3. Install persistent backdoors\n"
            "4. Exfiltrate all data\n"
            "This is equivalent to giving root access to the host. "
            "Thousands of servers have been compromised via exposed Docker APIs "
            "(cryptocurrency miners, botnets). Never expose port 2375."
        ),
        "cves": [],
    },
    "2376/tcp": {
        "score": 55,
        "summary": "Docker API (TLS) – container management, requires valid client cert",
        "explanation": (
            "Port 2376 is Docker API over TLS with mutual certificate authentication. "
            "If TLS is properly configured with client certificate verification, risk is lower. "
            "However, if the CA key is compromised or certificates are poorly managed, "
            "the same container escape risks as 2375 apply."
        ),
        "cves": [],
    },
    "8500/tcp": {
        "score": 65,
        "summary": "Consul – service mesh control plane, no auth by default",
        "explanation": (
            "HashiCorp Consul provides service discovery and configuration. "
            "Without ACLs (Access Control Lists) enabled, any client can read and modify "
            "service registrations, health checks, and KV store data. "
            "Sensitive configuration values in the KV store are exposed. "
            "Consul has had RCE vulnerabilities via template injection."
        ),
        "cves": ["CVE-2019-15076"],
    },
    "2181/tcp": {
        "score": 75,
        "summary": "Zookeeper – no auth, coordination service control",
        "explanation": (
            "Apache ZooKeeper has no authentication by default. "
            "An attacker can read and write all ZooKeeper znodes (configuration data), "
            "which may include Kafka broker lists, cluster configuration, and credentials. "
            "ZooKeeper controls many distributed systems (Kafka, HBase, Solr) – "
            "unauthorized access can disrupt entire clusters."
        ),
        "cves": [],
    },
    "9092/tcp": {
        "score": 68,
        "summary": "Kafka – no auth by default, message interception",
        "explanation": (
            "Apache Kafka has no authentication or encryption by default. "
            "An attacker can produce/consume all messages on all topics, "
            "potentially intercepting sensitive event data or injecting malicious events. "
            "Enable SASL authentication and TLS encryption."
        ),
        "cves": [],
    },
    "4369/tcp": {
        "score": 70,
        "summary": "Erlang Port Mapper Daemon (epmd) – cookie theft → RCE",
        "explanation": (
            "epmd is the Erlang port mapper daemon, used by RabbitMQ, CouchDB, and other "
            "Erlang-based systems. It exposes information about running Erlang nodes. "
            "If an attacker can obtain the Erlang cookie (used for node authentication), "
            "they can execute arbitrary code on all nodes in the cluster. "
            "RabbitMQ with default credentials (guest/guest) is trivially exploitable."
        ),
        "cves": [],
    },
    "15672/tcp": {
        "score": 78,
        "summary": "RabbitMQ Management – default guest/guest credentials",
        "explanation": (
            "RabbitMQ management interface defaults to guest/guest credentials "
            "accessible from localhost, but if exposed externally with default credentials, "
            "an attacker gets full access to message queues. "
            "From the management API, attackers can consume all messages, inject malicious "
            "messages, and potentially pivot to connected services."
        ),
        "cves": [],
    },
    "7474/tcp": {
        "score": 65,
        "summary": "Neo4j Browser – database access, older versions no auth",
        "explanation": (
            "Neo4j Browser (port 7474) provides web-based database access. "
            "Older versions had no authentication, allowing full database access. "
            "With ROLE ADMIN, attackers can execute arbitrary Java procedures. "
            "Ensure authentication is enabled and restrict access."
        ),
        "cves": [],
    },
    "50070/tcp": {
        "score": 72,
        "summary": "Hadoop NameNode HTTP – data access, code execution via YARN",
        "explanation": (
            "Hadoop NameNode web UI exposes HDFS metadata and file listings. "
            "Combined with YARN ResourceManager (port 8088), attackers can submit "
            "MapReduce jobs for arbitrary code execution under the hadoop user. "
            "Thousands of Hadoop clusters have been compromised for cryptocurrency mining."
        ),
        "cves": [],
    },
    "8088/tcp": {
        "score": 85,
        "summary": "YARN ResourceManager – arbitrary code execution via job submission",
        "explanation": (
            "Hadoop YARN ResourceManager allows submitting distributed computing jobs. "
            "Without authentication, any attacker can submit a job that executes arbitrary "
            "shell commands under the YARN user. Widely exploited for cryptocurrency mining. "
            "The API endpoint /ws/v1/cluster/apps allows job submission without credentials."
        ),
        "cves": [],
    },
    "6443/tcp": {
        "score": 60,
        "summary": "Kubernetes API server – cluster control plane",
        "explanation": (
            "The Kubernetes API server controls the entire cluster. "
            "With proper RBAC and authentication, risk is moderate. "
            "Misconfigurations (anonymous auth enabled, insecure port) allow "
            "unauthenticated cluster control, container deployment, and lateral movement. "
            "The --insecure-port (8080) is even more dangerous."
        ),
        "cves": ["CVE-2019-11253", "CVE-2018-1002105"],
    },
    "10250/tcp": {
        "score": 85,
        "summary": "Kubernetes Kubelet – node agent, arbitrary pod/command execution",
        "explanation": (
            "The Kubernetes Kubelet API allows listing pods and executing commands in containers. "
            "If authentication is disabled (anonymous auth), attackers can execute arbitrary "
            "commands in any pod on the node. From a privileged pod, host escape is trivial. "
            "Historically the primary Kubernetes attack vector for cryptomining."
        ),
        "cves": ["CVE-2019-11245"],
    },
    # -----------------------------------------------------------------------
    # LOW (20–44): minor risks in most contexts
    # -----------------------------------------------------------------------
    "587/tcp": {
        "score": 28,
        "summary": "SMTP Submission (STARTTLS) – authenticated email sending",
        "explanation": (
            "Port 587 is the standard port for email client submission with STARTTLS. "
            "Properly configured, it requires authentication and upgrades to TLS. "
            "Risk is relatively low: brute-force on accounts, spam relay if auth is weak. "
            "Use fail2ban and strong passwords."
        ),
        "cves": [],
    },
    "993/tcp": {
        "score": 15,
        "summary": "IMAPS – IMAP over TLS, encrypted email access",
        "explanation": (
            "IMAPS provides encrypted IMAP access. Risk is mainly from credential brute-force. "
            "The protocol itself is secure when using modern TLS."
        ),
        "cves": [],
    },
    "995/tcp": {
        "score": 15,
        "summary": "POP3S – POP3 over TLS, encrypted email retrieval",
        "explanation": (
            "POP3S provides encrypted POP3 access. Secure when using modern TLS. "
            "Main risk is brute-force attacks on credentials."
        ),
        "cves": [],
    },
    "8009/tcp": {
        "score": 75,
        "summary": "Apache AJP – Ghostcat vulnerability, file read and RCE",
        "explanation": (
            "Apache Tomcat AJP connector (Ghostcat, CVE-2020-1938) allows unauthenticated "
            "file inclusion and code execution. Even with no file upload functionality, "
            "any file in the Tomcat webapp can be read including WEB-INF/web.xml. "
            "If file upload exists, arbitrary JSP execution is possible. "
            "Never expose AJP port publicly; use requiredSecret attribute if needed."
        ),
        "cves": ["CVE-2020-1938"],
    },
    "2222/tcp": {
        "score": 38,
        "summary": "SSH alternate port – same as SSH but slightly less scanned",
        "explanation": (
            "Same risks as port 22 (SSH) but with slightly reduced automated scanning. "
            "Security through obscurity provides minimal protection. "
            "Properly hardened SSH (key-only auth, fail2ban) is more effective than port hiding."
        ),
        "cves": [],
    },
    "3000/tcp": {
        "score": 42,
        "summary": "Node.js/Grafana dev – often dev servers or monitoring with weak auth",
        "explanation": (
            "Port 3000 is used by many development servers (Node.js, React, Grafana). "
            "Grafana (before 8.3.5) had a critical path traversal/SSRF (CVE-2021-43798) "
            "that leaked arbitrary files including grafana.ini with passwords. "
            "Dev servers have no authentication; Grafana uses default admin/admin."
        ),
        "cves": ["CVE-2021-43798"],
    },
    "9000/tcp": {
        "score": 55,
        "summary": "PHP-FPM/SonarQube – RCE if FPM exposed, data in SonarQube",
        "explanation": (
            "Port 9000 is used by PHP-FPM and SonarQube. "
            "PHP-FPM should never be exposed directly (no authentication, arbitrary PHP execution). "
            "SonarQube in older versions had no authentication, exposing source code analysis results. "
            "Risk depends heavily on which service is running."
        ),
        "cves": ["CVE-2019-11043"],
    },
    "5984/tcp": {
        "score": 78,
        "summary": "CouchDB – admin party mode, arbitrary code execution via design docs",
        "explanation": (
            "CouchDB's 'admin party' mode (default) allows anyone to become admin. "
            "Design documents allow server-side JavaScript execution for map/reduce functions. "
            "An attacker with admin access can execute arbitrary OS commands via _exec or "
            "through configuration changes. CVE-2017-12636 allowed RCE via config API."
        ),
        "cves": ["CVE-2017-12636"],
    },
    "1194/udp": {
        "score": 20,
        "summary": "OpenVPN – VPN service, low risk if properly configured",
        "explanation": (
            "OpenVPN is a well-audited VPN protocol. "
            "Main risks: weak credentials (if using password auth instead of certificates), "
            "outdated versions with known vulnerabilities. "
            "Keep OpenVPN updated and use certificate-based authentication."
        ),
        "cves": [],
    },
    "500/udp": {
        "score": 22,
        "summary": "IKE/IPSec – VPN key exchange, standard protocol",
        "explanation": (
            "IKE (Internet Key Exchange) is used for IPSec VPN negotiation. "
            "Risk depends on configuration: weak pre-shared keys are vulnerable to offline attacks. "
            "Use IKEv2 with certificate authentication for best security."
        ),
        "cves": [],
    },
    "4500/udp": {
        "score": 20,
        "summary": "IPSec NAT-T – VPN protocol, low risk if properly configured",
        "explanation": (
            "IPSec NAT traversal port. Same risks as port 500/udp (IKE). "
            "Standard VPN protocol with good security record when properly configured."
        ),
        "cves": [],
    },
    "51820/udp": {
        "score": 12,
        "summary": "WireGuard – modern VPN, excellent security design",
        "explanation": (
            "WireGuard is a modern VPN protocol with excellent security design. "
            "Uses state-of-the-art cryptography (Noise protocol framework, Curve25519, ChaCha20). "
            "Does not respond to unauthenticated packets (stealth by default). "
            "Very low attack surface by design. Main risk: key management."
        ),
        "cves": [],
    },
    "179/tcp": {
        "score": 55,
        "summary": "BGP – routing protocol, session hijacking critical for infrastructure",
        "explanation": (
            "BGP (Border Gateway Protocol) is used for internet routing. "
            "Without MD5 authentication (RFC 2385) or RPKI, BGP sessions can be hijacked. "
            "BGP route hijacking can redirect internet traffic at scale. "
            "Should only be accessible to authorized BGP peers."
        ),
        "cves": [],
    },
    "546/udp": {
        "score": 18,
        "summary": "DHCPv6 client – standard IPv6 address configuration",
        "explanation": (
            "DHCPv6 client port for receiving IPv6 address assignments. "
            "Rogue DHCPv6 servers can assign malicious configurations (DNS servers, routes). "
            "In most environments this is a necessary protocol with acceptable risk."
        ),
        "cves": [],
    },
    "67/udp": {
        "score": 40,
        "summary": "DHCP server – rogue DHCP can redirect all network traffic",
        "explanation": (
            "A DHCP server distributes IP configuration to clients. "
            "A rogue DHCP server on the network can assign malicious DNS servers and "
            "default gateways, routing all client traffic through an attacker-controlled host. "
            "Only run DHCP servers on trusted network segments."
        ),
        "cves": [],
    },
    "68/udp": {
        "score": 20,
        "summary": "DHCP client – receives network configuration from DHCP server",
        "explanation": (
            "DHCP client port. Receives configuration from DHCP servers. "
            "Vulnerable to rogue DHCP server attacks on the local network. "
            "Standard network protocol; risk is primarily from network-level attacks."
        ),
        "cves": [],
    },
    "1714/tcp": {
        "score": 25,
        "summary": "KDE Connect – device pairing over local network",
        "explanation": (
            "KDE Connect links devices for notification sharing, file transfer, and remote control. "
            "Uses TLS with certificate pinning after initial pairing. "
            "Should only be accessible on trusted local networks. "
            "An unpaired device cannot access data without explicit user approval."
        ),
        "cves": [],
    },
    "1764/tcp": {
        "score": 25,
        "summary": "KDE Connect (upper range) – same as 1714/tcp",
        "explanation": (
            "KDE Connect uses ports 1714-1764 for device communication. "
            "See port 1714 for full explanation."
        ),
        "cves": [],
    },
}


def get_risk(port: str, proto: str) -> RiskAssessment:
    """Get risk assessment for a port/proto combination."""
    key = f"{port}/{proto}"
    data = _RISK_DB.get(key)

    if data:
        score = data["score"]
        return RiskAssessment(
            port=port,
            proto=proto,
            score=score,
            label=_label(score),
            summary=data["summary"],
            explanation=data["explanation"],
            cves=data.get("cves", []),
        )

    # Default assessment based on port range
    return _default_assessment(port, proto)


def _default_assessment(port: str, proto: str) -> RiskAssessment:
    """Generate a default risk assessment for unknown ports."""
    try:
        port_num = int(port.split("-")[0])  # handle ranges like "1714-1764"
    except ValueError:
        port_num = 0

    if port_num == 0:
        score = 30
        summary = "Unknown port"
        explanation = "Unknown port number. Risk cannot be assessed."
    elif port_num < 1024:
        score = 40
        summary = f"Well-known port (privileged, <1024)"
        explanation = (
            f"Port {port} is in the privileged port range (0-1023), meaning it requires "
            f"root/administrator privileges to bind. This does not directly indicate risk, "
            f"but well-known ports are more likely to be running standard services with "
            f"known vulnerability histories. The specific risk depends entirely on the "
            f"service running on this port."
        )
    elif port_num < 49152:
        score = 25
        summary = f"Registered port (1024-49151)"
        explanation = (
            f"Port {port} is a registered port. These are assigned to specific protocols "
            f"by IANA. Without knowing the exact service, risk is moderate. "
            f"Open ports in this range may be services with unknown vulnerability profiles."
        )
    else:
        score = 15
        summary = f"Ephemeral/dynamic port (>49151)"
        explanation = (
            f"Port {port} is in the ephemeral/dynamic port range. "
            f"These ports are normally used for temporary client connections. "
            f"A permanently open port in this range is unusual and may indicate a "
            f"non-standard service or misconfiguration."
        )

    return RiskAssessment(
        port=port,
        proto=proto,
        score=score,
        label=_label(score),
        summary=summary,
        explanation=explanation,
        cves=[],
    )


def get_risk_for_service(service_name: str, ports: list[tuple[str, str]]) -> RiskAssessment:
    """Get the highest risk assessment across all ports of a service."""
    if not ports:
        return RiskAssessment(
            port="N/A",
            proto="N/A",
            score=0,
            label=_label(0),
            summary="No ports defined",
            explanation="This service has no port definitions.",
            cves=[],
        )

    assessments = [get_risk(p, pr) for p, pr in ports]
    return max(assessments, key=lambda a: a.score)


def score_color(score: int) -> str:
    """Return a rich color string for a given score."""
    if score >= 90:
        return "bold red"
    if score >= 70:
        return "red"
    if score >= 45:
        return "yellow"
    if score >= 20:
        return "cyan"
    return "green"


def score_bar(score: int, width: int = 10) -> str:
    """Return a visual bar for the score."""
    filled = round(score / 100 * width)
    return "█" * filled + "░" * (width - filled)
