import * as fs from 'fs/promises';
import * as path from 'path';
import { spawn } from 'child_process';
import { GitHubInstaller } from './github-installer';

/**
 * Tool category enumeration
 */
export enum ToolCategory {
  RECON = 'recon',
  SCANNER = 'scanner',
  EXPLOIT = 'exploit',
  WIRELESS = 'wireless',
  WEB = 'web',
  PASSWORD = 'password',
  FORENSICS = 'forensics',
  SNIFFING = 'sniffing',
  REVERSE_ENGINEERING = 'reverse-engineering',
  CLOUD = 'cloud',
  MOBILE = 'mobile',
  API = 'api',
  POST_EXPLOITATION = 'post-exploitation',
  SOCIAL_ENGINEERING = 'social-engineering',
  REPORTING = 'reporting',
  VOIP = 'voip',
  HARDWARE = 'hardware',
  CUSTOM = 'custom'
}

/**
 * Tool information interface
 */
export interface ToolInfo {
  name: string;
  displayName: string;
  version: string;
  description: string;
  category: ToolCategory;
  capabilities: string[];
  installed: boolean;
  path?: string;
  requiresRoot: boolean;
  defaultArgs?: string[];
}

/**
 * Custom tool definition
 */
export interface CustomTool {
  name: string;
  script: string;
  description: string;
  category: ToolCategory;
  requiresRoot: boolean;
  createdAt: Date;
}

/**
 * Tool command generation options
 */
export interface CommandOptions {
  target: string;
  port?: number;
  protocol?: string;
  output?: string;
  verbose?: boolean;
  additionalArgs?: string[];
}

/**
 * ToolManager - Manages available tools and custom tool creation
 */
export class ToolManager {
  private toolsPath: string;
  private customToolsPath: string;
  private installedTools: Map<string, ToolInfo>;
  private toolDatabase: Map<string, ToolInfo>;
  public githubInstaller: GitHubInstaller;

  constructor(toolsPath: string = '/usr/share/ryha/tools') {
    this.toolsPath = toolsPath;
    this.customToolsPath = path.join(toolsPath, 'custom');
    this.installedTools = new Map();
    this.toolDatabase = new Map();
    this.githubInstaller = new GitHubInstaller();
    this.initializeToolDatabase();
  }

  /**
   * Initialize the built-in tool database
   */
  private initializeToolDatabase(): void {
    // Helper to add tool quickly
    const t = (name: string, displayName: string, desc: string, cat: ToolCategory, caps: string[], root = false, defArgs?: string[]) => {
      this.toolDatabase.set(name, { name, displayName, version: '', description: desc, category: cat, capabilities: caps, installed: false, requiresRoot: root, defaultArgs: defArgs });
    };

    // ======================
    // RECON & OSINT (50+ tools)
    // ======================
    t('nmap', 'Nmap', 'Network exploration and security auditing', ToolCategory.RECON, ['port-scanning','service-detection','os-detection','vulnerability-scanning'], false, ['-sV','-sC']);
    t('masscan', 'Masscan', 'Fast TCP port scanner', ToolCategory.RECON, ['port-scanning','fast-scanning'], true);
    t('unicornscan', 'Unicornscan', 'Asynchronous stateless TCP/UDP scanner', ToolCategory.RECON, ['port-scanning','asynchronous'], true);
    t('zmap', 'ZMap', 'Internet-wide network scanner', ToolCategory.RECON, ['port-scanning','internet-wide'], true);
    t('rustscan', 'RustScan', 'Fast port scanner with nmap integration', ToolCategory.RECON, ['port-scanning','fast-scanning'], false);
    t('dnsenum', 'DNSEnum', 'DNS enumeration tool', ToolCategory.RECON, ['dns-enumeration','subdomain-discovery'], false);
    t('dnsrecon', 'DNSRecon', 'DNS enumeration and zone transfer', ToolCategory.RECON, ['dns-enumeration','zone-transfer','srv-record-discovery'], false);
    t('fierce', 'Fierce', 'DNS reconnaissance tool', ToolCategory.RECON, ['dns-enumeration','zone-transfer'], false);
    t('dnsx', 'DNSX', 'Fast DNS toolkit', ToolCategory.RECON, ['dns-resolution','wildcard-detection'], false);
    t('dig', 'Dig', 'DNS lookup utility', ToolCategory.RECON, ['dns-lookup','record-query'], false);
    t('host', 'Host', 'DNS lookup utility', ToolCategory.RECON, ['dns-lookup'], false);
    t('nslookup', 'Nslookup', 'DNS query tool', ToolCategory.RECON, ['dns-lookup'], false);
    t('whois', 'Whois', 'Domain registration lookup', ToolCategory.RECON, ['domain-info','registration-data'], false);
    t('recon-ng', 'Recon-ng', 'Reconnaissance framework', ToolCategory.RECON, ['osint','reconnaissance','information-gathering'], false);
    t('amass', 'OWASP Amass', 'Attack surface mapping and asset discovery', ToolCategory.RECON, ['subdomain-enumeration','asset-discovery','osint'], false);
    t('subfinder', 'Subfinder', 'Fast passive subdomain enumeration', ToolCategory.RECON, ['subdomain-discovery','passive-recon'], false);
    t('sublist3r', 'Sublist3r', 'Fast subdomain enumeration', ToolCategory.RECON, ['subdomain-discovery'], false);
    t('assetfinder', 'Assetfinder', 'Find domains and subdomains', ToolCategory.RECON, ['subdomain-discovery','asset-discovery'], false);
    t('theharvester', 'theHarvester', 'OSINT for emails, subdomains, IPs', ToolCategory.RECON, ['osint','email-harvesting','subdomain-discovery'], false);
    t('maltego', 'Maltego', 'OSINT and graphical link analysis', ToolCategory.RECON, ['osint','link-analysis','visualization'], false);
    t('spiderfoot', 'SpiderFoot', 'Automated OSINT collection', ToolCategory.RECON, ['osint','automated-recon','threat-intelligence'], false);
    t('shodan', 'Shodan CLI', 'Shodan search engine CLI', ToolCategory.RECON, ['internet-scanning','device-discovery'], false);
    t('censys', 'Censys', 'Internet-wide scanning', ToolCategory.RECON, ['internet-scanning','certificate-discovery'], false);
    t('traceroute', 'Traceroute', 'Network path tracing', ToolCategory.RECON, ['network-tracing','routing'], false);
    t('ping', 'Ping', 'ICMP echo request', ToolCategory.RECON, ['host-discovery','connectivity-test'], false);
    t('fping', 'FPing', 'Fast ping sweep', ToolCategory.RECON, ['host-discovery','fast-sweep'], false);
    t('netdiscover', 'Netdiscover', 'Active/passive ARP reconnaissance', ToolCategory.RECON, ['host-discovery','arp-scanning'], true);
    t('arp-scan', 'ARP-Scan', 'ARP scanner', ToolCategory.RECON, ['host-discovery','arp-scanning'], true);
    t('nbtscan', 'NBTScan', 'NetBIOS scanner', ToolCategory.RECON, ['netbios-scanning','host-discovery'], false);
    t('naabu', 'Naabu', 'Fast port scanner', ToolCategory.RECON, ['port-scanning','fast-scanning'], false);
    t('httprobe', 'HTTProbe', 'Probe HTTP/HTTPS servers', ToolCategory.RECON, ['http-probing','host-discovery'], false);
    t('uncover', 'Uncover', 'API-based host discovery', ToolCategory.RECON, ['api-discovery','host-discovery'], false);
    t('sherlock', 'Sherlock', 'Social media username finder', ToolCategory.RECON, ['osint','social-media','username-enumeration'], false);
    t('whatweb', 'WhatWeb', 'Web technology fingerprinting', ToolCategory.RECON, ['technology-detection','fingerprinting'], false);

    // ======================
    // WEB APPLICATION (60+ tools)
    // ======================
    t('nikto', 'Nikto', 'Web server vulnerability scanner', ToolCategory.WEB, ['web-scanning','vulnerability-detection'], false);
    t('sqlmap', 'SQLMap', 'SQL injection detection and exploitation', ToolCategory.WEB, ['sql-injection','database-exploitation'], false);
    t('burpsuite', 'Burp Suite', 'Web application security testing platform', ToolCategory.WEB, ['web-proxy','vulnerability-scanning','manual-testing'], false);
    t('zaproxy', 'OWASP ZAP', 'Web application security scanner', ToolCategory.WEB, ['web-scanning','proxy','api-testing'], false);
    t('wpscan', 'WPScan', 'WordPress vulnerability scanner', ToolCategory.WEB, ['wordpress-scanning','plugin-enumeration'], false);
    t('joomscan', 'JoomScan', 'Joomla vulnerability scanner', ToolCategory.WEB, ['joomla-scanning','cms-enumeration'], false);
    t('droopescan', 'Droopescan', 'CMS vulnerability scanner', ToolCategory.WEB, ['cms-scanning','drupal','silverstripe'], false);
    t('nuclei', 'Nuclei', 'Template-based vulnerability scanner', ToolCategory.WEB, ['vulnerability-scanning','template-based','cve-detection'], false);
    t('gobuster', 'Gobuster', 'Directory/DNS brute-forcing', ToolCategory.WEB, ['directory-brute-force','dns-enumeration'], false);
    t('dirb', 'DIRB', 'Web content scanner', ToolCategory.WEB, ['directory-brute-force','file-discovery'], false);
    t('dirbuster', 'DirBuster', 'Web content brute-forcer', ToolCategory.WEB, ['directory-brute-force','file-discovery'], false);
    t('ffuf', 'FFUF', 'Fast web fuzzer', ToolCategory.WEB, ['fuzzing','directory-brute-force','parameter-discovery'], false);
    t('wfuzz', 'WFuzz', 'Web application fuzzer', ToolCategory.WEB, ['fuzzing','brute-force','parameter-fuzzing'], false);
    t('feroxbuster', 'Feroxbuster', 'Fast recursive content discovery', ToolCategory.WEB, ['directory-brute-force','recursive-scanning'], false);
    t('dalfox', 'DalFox', 'XSS scanning and parameter analysis', ToolCategory.WEB, ['xss-detection','parameter-analysis'], false);
    t('xsser', 'XSSer', 'Cross-site scripting detection', ToolCategory.WEB, ['xss-detection','xss-exploitation'], false);
    t('commix', 'Commix', 'Command injection exploitation', ToolCategory.WEB, ['command-injection','exploitation'], false);
    t('nosqlmap', 'NoSQLMap', 'NoSQL injection detection', ToolCategory.WEB, ['nosql-injection','mongodb-exploitation'], false);
    t('sslyze', 'SSLyze', 'SSL/TLS configuration analyzer', ToolCategory.WEB, ['ssl-analysis','certificate-validation','cipher-testing'], false);
    t('sslscan', 'SSLScan', 'SSL/TLS scanner', ToolCategory.WEB, ['ssl-scanning','cipher-analysis'], false);
    t('testssl.sh', 'TestSSL', 'SSL/TLS testing tool', ToolCategory.WEB, ['ssl-testing','vulnerability-detection'], false);
    t('wafw00f', 'WAFW00F', 'WAF detection tool', ToolCategory.WEB, ['waf-detection','fingerprinting'], false);
    t('httpx', 'httpx', 'Fast HTTP probing tool', ToolCategory.WEB, ['http-probing','technology-detection','status-detection'], false);
    t('katana', 'Katana', 'Web crawling framework', ToolCategory.WEB, ['web-crawling','endpoint-discovery'], false);
    t('gospider', 'GoSpider', 'Fast web spider', ToolCategory.WEB, ['web-crawling','link-extraction'], false);
    t('hakrawler', 'Hakrawler', 'Web crawler for URL gathering', ToolCategory.WEB, ['web-crawling','url-discovery'], false);
    t('gau', 'GAU', 'Fetch known URLs from sources', ToolCategory.WEB, ['url-discovery','wayback-machine'], false);
    t('waybackurls', 'Waybackurls', 'Wayback Machine URL fetcher', ToolCategory.WEB, ['url-discovery','historical-data'], false);
    t('meg', 'Meg', 'Fetch many paths for many hosts', ToolCategory.WEB, ['bulk-fetching','path-scanning'], false);
    t('unfurl', 'Unfurl', 'URL component extraction', ToolCategory.WEB, ['url-analysis','parameter-extraction'], false);
    t('qsreplace', 'QSReplace', 'Query string value replacement', ToolCategory.WEB, ['parameter-manipulation','fuzzing-prep'], false);
    t('arjun', 'Arjun', 'HTTP parameter discovery', ToolCategory.WEB, ['parameter-discovery','hidden-params'], false);
    t('paramspider', 'ParamSpider', 'Parameter URL mining', ToolCategory.WEB, ['parameter-discovery','url-mining'], false);
    t('crlfuzz', 'CRLFuzz', 'CRLF vulnerability scanner', ToolCategory.WEB, ['crlf-injection','header-injection'], false);
    t('kxss', 'KXSS', 'XSS reflection checker', ToolCategory.WEB, ['xss-detection','reflection-check'], false);
    t('weevely', 'Weevely', 'PHP web shell generator', ToolCategory.WEB, ['web-shell','php-backdoor'], false);
    t('curl', 'cURL', 'HTTP client', ToolCategory.WEB, ['http-client','data-transfer'], false);
    t('wget', 'Wget', 'Network downloader', ToolCategory.WEB, ['http-client','file-download'], false);
    t('httpie', 'HTTPie', 'Modern HTTP client', ToolCategory.WEB, ['http-client','api-testing'], false);
    t('gowitness', 'GoWitness', 'Web screenshot utility', ToolCategory.WEB, ['screenshot','visual-recon'], false);

    // ======================
    // VULNERABILITY SCANNERS (15+ tools)
    // ======================
    t('openvas', 'OpenVAS', 'Open Vulnerability Assessment System', ToolCategory.SCANNER, ['vulnerability-scanning','compliance-auditing'], false);
    t('nessus', 'Nessus', 'Vulnerability scanner', ToolCategory.SCANNER, ['vulnerability-scanning','compliance'], false);
    t('lynis', 'Lynis', 'System auditing tool', ToolCategory.SCANNER, ['system-auditing','hardening','compliance'], false);
    t('legion', 'Legion', 'Network penetration testing framework', ToolCategory.SCANNER, ['automated-scanning','enumeration'], false);
    t('autorecon', 'AutoRecon', 'Automated reconnaissance tool', ToolCategory.SCANNER, ['automated-scanning','service-enumeration'], false);
    t('sparta', 'SPARTA', 'Network infrastructure pen test tool', ToolCategory.SCANNER, ['network-scanning','automated-enumeration'], false);

    // ======================
    // EXPLOITATION (25+ tools)
    // ======================
    t('metasploit', 'Metasploit', 'Penetration testing platform', ToolCategory.EXPLOIT, ['exploitation','post-exploitation','payload-generation'], false);
    t('msfconsole', 'MSFConsole', 'Metasploit console', ToolCategory.EXPLOIT, ['exploitation','interactive-shell'], false);
    t('msfvenom', 'MSFVenom', 'Payload generator', ToolCategory.EXPLOIT, ['payload-generation','encoding','shellcode'], false);
    t('searchsploit', 'SearchSploit', 'Exploit database search', ToolCategory.EXPLOIT, ['exploit-search','database-query'], false);
    t('beef-xss', 'BeEF', 'Browser Exploitation Framework', ToolCategory.EXPLOIT, ['browser-exploitation','xss-framework','social-engineering'], false);
    t('routersploit', 'RouterSploit', 'Router exploitation framework', ToolCategory.EXPLOIT, ['router-exploitation','iot-testing'], false);
    t('setoolkit', 'SET', 'Social-Engineer Toolkit', ToolCategory.EXPLOIT, ['social-engineering','phishing','credential-harvesting'], false);
    t('shellnoob', 'ShellNoob', 'Shellcode helper tool', ToolCategory.EXPLOIT, ['shellcode','exploitation'], false);
    t('exploitdb', 'ExploitDB', 'Exploit database', ToolCategory.EXPLOIT, ['exploit-search','cve-lookup'], false);
    t('pwncat', 'Pwncat', 'Post-exploitation platform', ToolCategory.EXPLOIT, ['post-exploitation','reverse-shell','persistence'], false);

    // ======================
    // PASSWORD (20+ tools)
    // ======================
    t('hydra', 'Hydra', 'Network logon cracker', ToolCategory.PASSWORD, ['password-cracking','brute-force'], false);
    t('john', 'John the Ripper', 'Password cracker', ToolCategory.PASSWORD, ['password-cracking','hash-cracking'], false);
    t('hashcat', 'Hashcat', 'Advanced password recovery', ToolCategory.PASSWORD, ['hash-cracking','gpu-acceleration'], false);
    t('medusa', 'Medusa', 'Parallel network login brute-forcer', ToolCategory.PASSWORD, ['password-cracking','parallel-processing'], false);
    t('ncrack', 'Ncrack', 'Network authentication cracker', ToolCategory.PASSWORD, ['password-cracking','network-auth'], false);
    t('patator', 'Patator', 'Multi-purpose brute-forcer', ToolCategory.PASSWORD, ['brute-force','multi-protocol'], false);
    t('cewl', 'CeWL', 'Custom word list generator', ToolCategory.PASSWORD, ['wordlist-generation','web-scraping'], false);
    t('crunch', 'Crunch', 'Wordlist generator', ToolCategory.PASSWORD, ['wordlist-generation','pattern-based'], false);
    t('cupp', 'CUPP', 'Common User Passwords Profiler', ToolCategory.PASSWORD, ['wordlist-generation','social-engineering'], false);
    t('hash-identifier', 'Hash-ID', 'Hash type identifier', ToolCategory.PASSWORD, ['hash-identification','analysis'], false);
    t('hashid', 'HashID', 'Identify hash types', ToolCategory.PASSWORD, ['hash-identification'], false);
    t('ophcrack', 'Ophcrack', 'Windows password cracker', ToolCategory.PASSWORD, ['windows-password','rainbow-table'], false);
    t('fcrackzip', 'FCrackZip', 'ZIP password cracker', ToolCategory.PASSWORD, ['archive-cracking','zip-password'], false);
    t('rarcrack', 'RARCrack', 'RAR/ZIP/7z password cracker', ToolCategory.PASSWORD, ['archive-cracking'], false);
    t('chntpw', 'CHNTPW', 'Windows password reset', ToolCategory.PASSWORD, ['windows-password','sam-editing'], false);
    t('mimikatz', 'Mimikatz', 'Windows credential extraction', ToolCategory.PASSWORD, ['credential-extraction','kerberos','pass-the-hash'], false);
    t('lazagne', 'LaZagne', 'Credential recovery tool', ToolCategory.PASSWORD, ['credential-recovery','browser-passwords'], false);
    t('kerbrute', 'Kerbrute', 'Kerberos brute-forcer', ToolCategory.PASSWORD, ['kerberos','brute-force','ad-enumeration'], false);

    // ======================
    // WIRELESS (15+ tools)
    // ======================
    t('aircrack-ng', 'Aircrack-ng', 'WiFi security auditing suite', ToolCategory.WIRELESS, ['wifi-cracking','packet-capture','wep-wpa-cracking'], true);
    t('airmon-ng', 'Airmon-ng', 'Monitor mode enabler', ToolCategory.WIRELESS, ['monitor-mode','interface-management'], true);
    t('airodump-ng', 'Airodump-ng', 'WiFi packet capture', ToolCategory.WIRELESS, ['packet-capture','wifi-scanning'], true);
    t('aireplay-ng', 'Aireplay-ng', 'WiFi packet injection', ToolCategory.WIRELESS, ['packet-injection','deauth-attack'], true);
    t('wifite', 'Wifite', 'Automated wireless attack tool', ToolCategory.WIRELESS, ['wifi-cracking','automated-attacks'], true);
    t('reaver', 'Reaver', 'WPS PIN attack tool', ToolCategory.WIRELESS, ['wps-attacks','wifi-cracking'], true);
    t('bully', 'Bully', 'WPS brute force', ToolCategory.WIRELESS, ['wps-attacks','brute-force'], true);
    t('pixiewps', 'Pixiewps', 'WPS pixie dust attack', ToolCategory.WIRELESS, ['wps-attacks','pixie-dust'], true);
    t('kismet', 'Kismet', 'Wireless network detector', ToolCategory.WIRELESS, ['wireless-detection','packet-capture','gps-mapping'], true);
    t('wifiphisher', 'WiFi-Phisher', 'WiFi phishing attacks', ToolCategory.WIRELESS, ['wifi-phishing','evil-twin'], true);
    t('fluxion', 'Fluxion', 'WiFi social engineering', ToolCategory.WIRELESS, ['evil-twin','captive-portal'], true);
    t('hostapd-wpe', 'Hostapd-WPE', 'Enterprise WiFi attacks', ToolCategory.WIRELESS, ['enterprise-wifi','credential-capture'], true);
    t('fern-wifi-cracker', 'Fern', 'GUI WiFi cracker', ToolCategory.WIRELESS, ['wifi-cracking','gui-tool'], true);
    t('macchanger', 'MACChanger', 'MAC address changer', ToolCategory.WIRELESS, ['mac-spoofing','anonymity'], true);
    t('wash', 'Wash', 'WPS-enabled AP scanner', ToolCategory.WIRELESS, ['wps-scanning','ap-discovery'], true);

    // ======================
    // SNIFFING & MITM (20+ tools)
    // ======================
    t('wireshark', 'Wireshark', 'Network protocol analyzer', ToolCategory.SNIFFING, ['packet-capture','protocol-analysis'], true);
    t('tshark', 'TShark', 'CLI Wireshark', ToolCategory.SNIFFING, ['packet-capture','cli-analysis'], true);
    t('tcpdump', 'TCPDump', 'Command-line packet analyzer', ToolCategory.SNIFFING, ['packet-capture','network-monitoring'], true);
    t('ettercap', 'Ettercap', 'MITM attack tool', ToolCategory.SNIFFING, ['mitm','packet-sniffing','network-analysis'], true);
    t('bettercap', 'Bettercap', 'Network attack and monitoring framework', ToolCategory.SNIFFING, ['mitm','network-monitoring','arp-spoofing','dns-spoofing'], true);
    t('responder', 'Responder', 'LLMNR/NBT-NS/MDNS poisoner', ToolCategory.SNIFFING, ['llmnr-poisoning','credential-capture','mitm'], true);
    t('mitmproxy', 'Mitmproxy', 'Interactive HTTPS proxy', ToolCategory.SNIFFING, ['http-proxy','ssl-interception','traffic-analysis'], false);
    t('sslstrip', 'SSLStrip', 'SSL downgrade attack', ToolCategory.SNIFFING, ['ssl-stripping','mitm'], true);
    t('hping3', 'HPing3', 'TCP/IP packet assembler/analyzer', ToolCategory.SNIFFING, ['packet-crafting','firewall-testing','port-scanning'], true);
    t('scapy', 'Scapy', 'Packet manipulation library', ToolCategory.SNIFFING, ['packet-crafting','protocol-fuzzing','network-analysis'], false);
    t('yersinia', 'Yersinia', 'Layer 2 attack tool', ToolCategory.SNIFFING, ['layer2-attacks','vlan-hopping','spanning-tree'], true);
    t('netcat', 'Netcat', 'TCP/UDP networking utility', ToolCategory.SNIFFING, ['port-listening','data-transfer','tunneling'], false);
    t('ncat', 'Ncat', 'Nmap netcat', ToolCategory.SNIFFING, ['port-listening','ssl-connections'], false);
    t('socat', 'Socat', 'Multipurpose relay', ToolCategory.SNIFFING, ['port-relay','tunneling','protocol-bridging'], false);
    t('dsniff', 'Dsniff', 'Network password sniffer', ToolCategory.SNIFFING, ['password-sniffing','network-auditing'], true);
    t('arpspoof', 'Arpspoof', 'ARP spoofing tool', ToolCategory.SNIFFING, ['arp-spoofing','mitm'], true);
    t('dnsspoof', 'DNSspoof', 'DNS spoofing tool', ToolCategory.SNIFFING, ['dns-spoofing','mitm'], true);

    // ======================
    // POST-EXPLOITATION (25+ tools)
    // ======================
    t('enum4linux', 'Enum4Linux', 'Windows/Samba enumeration', ToolCategory.POST_EXPLOITATION, ['smb-enumeration','user-enumeration','share-enumeration'], false);
    t('enum4linux-ng', 'Enum4Linux-ng', 'Next-gen SMB enumeration', ToolCategory.POST_EXPLOITATION, ['smb-enumeration','improved-output'], false);
    t('crackmapexec', 'CrackMapExec', 'Post-exploitation for AD', ToolCategory.POST_EXPLOITATION, ['ad-enumeration','credential-testing','lateral-movement'], false);
    t('evil-winrm', 'Evil-WinRM', 'Windows Remote Management shell', ToolCategory.POST_EXPLOITATION, ['remote-shell','file-transfer','persistence'], false);
    t('bloodhound', 'BloodHound', 'AD attack path mapping', ToolCategory.POST_EXPLOITATION, ['ad-analysis','attack-path-mapping','privilege-escalation'], false);
    t('sharphound', 'SharpHound', 'BloodHound data collector', ToolCategory.POST_EXPLOITATION, ['ad-data-collection','domain-enumeration'], false);
    t('empire', 'Empire', 'Post-exploitation framework', ToolCategory.POST_EXPLOITATION, ['post-exploitation','c2','powershell'], false);
    t('sliver', 'Sliver', 'C2 framework', ToolCategory.POST_EXPLOITATION, ['c2-framework','implant-generation','lateral-movement'], false);
    t('covenant', 'Covenant', '.NET C2 framework', ToolCategory.POST_EXPLOITATION, ['c2-framework','dotnet-implants'], false);
    t('merlin', 'Merlin', 'Cross-platform C2', ToolCategory.POST_EXPLOITATION, ['c2-framework','cross-platform'], false);
    t('powersploit', 'PowerSploit', 'PowerShell post-exploitation', ToolCategory.POST_EXPLOITATION, ['powershell','privilege-escalation','persistence'], false);
    t('chisel', 'Chisel', 'TCP/UDP tunnel over HTTP', ToolCategory.POST_EXPLOITATION, ['tunneling','pivot','port-forwarding'], false);
    t('ligolo-ng', 'Ligolo-ng', 'Tunneling/pivoting tool', ToolCategory.POST_EXPLOITATION, ['tunneling','pivot','internal-network'], false);
    t('smbclient', 'SMBClient', 'SMB/CIFS client', ToolCategory.POST_EXPLOITATION, ['smb-access','file-transfer'], false);
    t('smbmap', 'SMBMap', 'SMB share enumerator', ToolCategory.POST_EXPLOITATION, ['smb-enumeration','share-permissions'], false);
    t('rpcclient', 'RPCClient', 'Windows RPC client', ToolCategory.POST_EXPLOITATION, ['rpc-enumeration','user-enumeration'], false);
    t('ldapsearch', 'LDAPSearch', 'LDAP query tool', ToolCategory.POST_EXPLOITATION, ['ldap-enumeration','directory-query'], false);
    t('snmpwalk', 'SNMPWalk', 'SNMP data retrieval', ToolCategory.POST_EXPLOITATION, ['snmp-enumeration','mib-walking'], false);
    t('onesixtyone', 'Onesixtyone', 'Fast SNMP scanner', ToolCategory.POST_EXPLOITATION, ['snmp-scanning','community-brute-force'], false);
    t('smtp-user-enum', 'SMTP-User-Enum', 'SMTP user enumeration', ToolCategory.POST_EXPLOITATION, ['smtp-enumeration','user-discovery'], false);
    t('certipy', 'Certipy', 'AD Certificate Services exploitation', ToolCategory.POST_EXPLOITATION, ['ad-cs-exploitation','certificate-abuse'], false);
    t('rubeus', 'Rubeus', 'Kerberos exploitation toolset', ToolCategory.POST_EXPLOITATION, ['kerberos','ticket-manipulation','delegation-abuse'], false);
    t('impacket-psexec', 'Impacket-PsExec', 'Remote command execution', ToolCategory.POST_EXPLOITATION, ['remote-execution','smb'], false);
    t('impacket-wmiexec', 'Impacket-WMIExec', 'WMI command execution', ToolCategory.POST_EXPLOITATION, ['remote-execution','wmi'], false);
    t('impacket-smbserver', 'Impacket-SMBServer', 'SMB server', ToolCategory.POST_EXPLOITATION, ['smb-server','file-transfer'], false);
    t('impacket-secretsdump', 'Impacket-SecretsDump', 'Credential dumping', ToolCategory.POST_EXPLOITATION, ['credential-dumping','ntds-extraction'], false);
    t('impacket-getTGT', 'Impacket-GetTGT', 'Kerberos TGT request', ToolCategory.POST_EXPLOITATION, ['kerberos','tgt-request'], false);
    t('pspy', 'PSpy', 'Process monitor without root', ToolCategory.POST_EXPLOITATION, ['process-monitoring','privilege-escalation'], false);
    t('linpeas', 'LinPEAS', 'Linux privilege escalation', ToolCategory.POST_EXPLOITATION, ['privilege-escalation','enumeration','linux'], false);
    t('winpeas', 'WinPEAS', 'Windows privilege escalation', ToolCategory.POST_EXPLOITATION, ['privilege-escalation','enumeration','windows'], false);
    t('linux-exploit-suggester', 'LES', 'Linux exploit suggester', ToolCategory.POST_EXPLOITATION, ['privilege-escalation','exploit-suggestion'], false);

    // ======================
    // FORENSICS (20+ tools)
    // ======================
    t('autopsy', 'Autopsy', 'Digital forensics platform', ToolCategory.FORENSICS, ['disk-analysis','file-recovery','timeline-analysis'], false);
    t('binwalk', 'Binwalk', 'Firmware analysis tool', ToolCategory.FORENSICS, ['firmware-analysis','file-extraction'], false);
    t('volatility', 'Volatility', 'Memory forensics framework', ToolCategory.FORENSICS, ['memory-analysis','malware-detection'], false);
    t('volatility3', 'Volatility3', 'Memory forensics v3', ToolCategory.FORENSICS, ['memory-analysis','process-analysis'], false);
    t('foremost', 'Foremost', 'File carving tool', ToolCategory.FORENSICS, ['file-recovery','data-carving'], false);
    t('scalpel', 'Scalpel', 'File carver', ToolCategory.FORENSICS, ['file-recovery','data-carving'], false);
    t('bulk_extractor', 'Bulk Extractor', 'Digital evidence extraction', ToolCategory.FORENSICS, ['evidence-extraction','email-extraction'], false);
    t('strings', 'Strings', 'Extract strings from binaries', ToolCategory.FORENSICS, ['string-extraction','binary-analysis'], false);
    t('file', 'File', 'File type identifier', ToolCategory.FORENSICS, ['file-identification','magic-bytes'], false);
    t('xxd', 'XXD', 'Hex dump utility', ToolCategory.FORENSICS, ['hex-dump','binary-analysis'], false);
    t('hexdump', 'Hexdump', 'Binary file viewer', ToolCategory.FORENSICS, ['hex-dump','binary-viewing'], false);
    t('exiftool', 'ExifTool', 'Metadata extraction', ToolCategory.FORENSICS, ['metadata-extraction','image-analysis'], false);
    t('steghide', 'Steghide', 'Steganography tool', ToolCategory.FORENSICS, ['steganography','data-hiding','extraction'], false);
    t('stegsolve', 'StegSolve', 'Image steganography solver', ToolCategory.FORENSICS, ['steganography','image-analysis'], false);
    t('zsteg', 'ZSteg', 'PNG/BMP steganography detection', ToolCategory.FORENSICS, ['steganography','png-analysis'], false);
    t('photorec', 'PhotoRec', 'Photo/file recovery', ToolCategory.FORENSICS, ['file-recovery','photo-recovery'], false);
    t('testdisk', 'TestDisk', 'Partition recovery', ToolCategory.FORENSICS, ['partition-recovery','disk-repair'], false);
    t('sleuthkit', 'Sleuth Kit', 'Filesystem forensics', ToolCategory.FORENSICS, ['filesystem-analysis','timeline'], false);
    t('dc3dd', 'DC3DD', 'DOD forensic imaging', ToolCategory.FORENSICS, ['disk-imaging','forensic-copy'], false);
    t('guymager', 'Guymager', 'Forensic imaging tool', ToolCategory.FORENSICS, ['disk-imaging','evidence-acquisition'], false);

    // ======================
    // REVERSE ENGINEERING (15+ tools)
    // ======================
    t('radare2', 'Radare2', 'Reverse engineering framework', ToolCategory.REVERSE_ENGINEERING, ['disassembly','debugging','binary-analysis'], false);
    t('ghidra', 'Ghidra', 'NSA reverse engineering tool', ToolCategory.REVERSE_ENGINEERING, ['decompilation','disassembly','binary-analysis'], false);
    t('gdb', 'GDB', 'GNU Debugger', ToolCategory.REVERSE_ENGINEERING, ['debugging','breakpoints','memory-inspection'], false);
    t('objdump', 'Objdump', 'Object file dumper', ToolCategory.REVERSE_ENGINEERING, ['disassembly','elf-analysis'], false);
    t('readelf', 'Readelf', 'ELF file analyzer', ToolCategory.REVERSE_ENGINEERING, ['elf-analysis','header-inspection'], false);
    t('strace', 'Strace', 'System call tracer', ToolCategory.REVERSE_ENGINEERING, ['syscall-tracing','debugging'], false);
    t('ltrace', 'Ltrace', 'Library call tracer', ToolCategory.REVERSE_ENGINEERING, ['library-tracing','debugging'], false);
    t('rizin', 'Rizin', 'Reverse engineering framework', ToolCategory.REVERSE_ENGINEERING, ['disassembly','scripting','binary-analysis'], false);
    t('cutter', 'Cutter', 'Reverse engineering GUI', ToolCategory.REVERSE_ENGINEERING, ['gui-reversing','graph-view'], false);
    t('jadx', 'JADX', 'Android DEX decompiler', ToolCategory.REVERSE_ENGINEERING, ['android-reversing','dex-decompilation'], false);
    t('apktool', 'APKTool', 'Android APK reverse engineering', ToolCategory.REVERSE_ENGINEERING, ['android-reversing','apk-decompilation'], false);
    t('dex2jar', 'Dex2Jar', 'DEX to JAR converter', ToolCategory.REVERSE_ENGINEERING, ['android-reversing','format-conversion'], false);
    t('jd-gui', 'JD-GUI', 'Java decompiler', ToolCategory.REVERSE_ENGINEERING, ['java-decompilation','gui-tool'], false);
    t('pwntools', 'Pwntools', 'CTF/exploit development library', ToolCategory.REVERSE_ENGINEERING, ['exploit-development','ctf','binary-exploitation'], false);

    // ======================
    // CLOUD & CONTAINER (15+ tools)
    // ======================
    t('trivy', 'Trivy', 'Container and cloud security scanner', ToolCategory.CLOUD, ['container-scanning','iac-scanning','sbom'], false);
    t('prowler', 'Prowler', 'AWS/Azure/GCP security assessment', ToolCategory.CLOUD, ['cloud-audit','compliance-checking','misconfiguration-detection'], false);
    t('pacu', 'Pacu', 'AWS exploitation framework', ToolCategory.CLOUD, ['aws-exploitation','privilege-escalation'], false);
    t('cloudsploit', 'CloudSploit', 'Cloud security scanner', ToolCategory.CLOUD, ['cloud-scanning','misconfiguration'], false);
    t('scout', 'ScoutSuite', 'Multi-cloud security auditing', ToolCategory.CLOUD, ['cloud-audit','multi-cloud'], false);
    t('grype', 'Grype', 'Vulnerability scanner for images', ToolCategory.CLOUD, ['container-scanning','vulnerability-detection'], false);
    t('syft', 'Syft', 'Container SBOM generator', ToolCategory.CLOUD, ['sbom-generation','dependency-analysis'], false);
    t('dive', 'Dive', 'Docker image layer explorer', ToolCategory.CLOUD, ['docker-analysis','layer-inspection'], false);
    t('hadolint', 'Hadolint', 'Dockerfile linter', ToolCategory.CLOUD, ['dockerfile-linting','best-practices'], false);
    t('kube-hunter', 'Kube-Hunter', 'Kubernetes vulnerability scanner', ToolCategory.CLOUD, ['kubernetes-scanning','cluster-security'], false);
    t('kubescape', 'Kubescape', 'Kubernetes security platform', ToolCategory.CLOUD, ['kubernetes-scanning','compliance'], false);
    t('terraform-compliance', 'TF-Compliance', 'Terraform security checks', ToolCategory.CLOUD, ['iac-compliance','terraform-audit'], false);

    // ======================
    // MOBILE (10+ tools)
    // ======================
    t('adb', 'ADB', 'Android Debug Bridge', ToolCategory.MOBILE, ['android-debugging','app-installation'], false);
    t('frida', 'Frida', 'Dynamic instrumentation toolkit', ToolCategory.MOBILE, ['dynamic-analysis','hooking','runtime-manipulation'], false);
    t('objection', 'Objection', 'Runtime mobile exploration', ToolCategory.MOBILE, ['mobile-security','runtime-analysis'], false);
    t('mobsf', 'MobSF', 'Mobile Security Framework', ToolCategory.MOBILE, ['static-analysis','dynamic-analysis','malware-detection'], false);
    t('drozer', 'Drozer', 'Android security assessment', ToolCategory.MOBILE, ['android-security','ipc-analysis'], false);
    t('qark', 'QARK', 'Quick Android Review Kit', ToolCategory.MOBILE, ['android-scanning','vulnerability-detection'], false);

    // ======================
    // SOCIAL ENGINEERING (5+ tools)
    // ======================
    t('gophish', 'Gophish', 'Phishing framework', ToolCategory.SOCIAL_ENGINEERING, ['phishing-campaigns','email-spoofing'], false);
    t('king-phisher', 'King Phisher', 'Phishing campaign toolkit', ToolCategory.SOCIAL_ENGINEERING, ['phishing','credential-harvesting'], false);
    t('evilginx2', 'Evilginx2', 'MITM phishing framework', ToolCategory.SOCIAL_ENGINEERING, ['phishing','2fa-bypass','session-hijacking'], false);
    t('swaks', 'Swaks', 'SMTP test tool', ToolCategory.SOCIAL_ENGINEERING, ['smtp-testing','email-sending'], false);
    t('sendemail', 'SendEmail', 'CLI email sender', ToolCategory.SOCIAL_ENGINEERING, ['email-sending','smtp-client'], false);

    // ======================
    // VoIP (5+ tools)
    // ======================
    t('sipvicious', 'SIPVicious', 'SIP protocol auditing', ToolCategory.VOIP, ['sip-scanning','voip-enumeration'], false);
    t('ohrwurm', 'Ohrwurm', 'RTP fuzzer', ToolCategory.VOIP, ['rtp-fuzzing','voip-testing'], false);

    // ======================
    // REPORTING (5+ tools)
    // ======================
    t('dradis', 'Dradis', 'Collaboration and reporting platform', ToolCategory.REPORTING, ['reporting','collaboration','findings-management'], false);
    t('pipal', 'Pipal', 'Password analysis tool', ToolCategory.REPORTING, ['password-analysis','statistics'], false);
    t('cutycapt', 'CutyCapt', 'Web page screenshot capture', ToolCategory.REPORTING, ['screenshot','web-capture'], false);

    // ======================
    // TUNNELING & PROXY (10+ tools)
    // ======================
    t('proxychains', 'ProxyChains', 'Proxy chain redirector', ToolCategory.SNIFFING, ['proxy-chaining','anonymity','traffic-routing'], false);
    t('tor', 'Tor', 'Anonymity network', ToolCategory.SNIFFING, ['anonymity','onion-routing'], false);
    t('torsocks', 'Torsocks', 'Tor SOCKS wrapper', ToolCategory.SNIFFING, ['anonymity','socks-proxy'], false);
    t('openvpn', 'OpenVPN', 'VPN client', ToolCategory.SNIFFING, ['vpn','tunneling','encryption'], false);
    t('ssh', 'SSH', 'Secure shell', ToolCategory.SNIFFING, ['remote-access','tunneling','port-forwarding'], false);
    t('sshuttle', 'SSHuttle', 'Poor man VPN over SSH', ToolCategory.SNIFFING, ['vpn','ssh-tunneling'], false);
  }

  /**
   * Discover installed tools on Kali Linux
   */
  public async discoverTools(): Promise<ToolInfo[]> {
    this.installedTools.clear();

    // Check known tools from database
    for (const [name, toolInfo] of this.toolDatabase) {
      const installed = await this.checkToolInstalled(name);
      if (installed) {
        const version = await this.getToolVersion(name);
        const updatedInfo: ToolInfo = {
          ...toolInfo,
          installed: true,
          version
        };
        this.installedTools.set(name, updatedInfo);
      }
    }

    // Discover unknown tools from system
    await this.discoverUnknownTools();

    // Discover custom tools
    await this.discoverCustomTools();

    return Array.from(this.installedTools.values());
  }

  /**
   * Discover security tools not in the database by scanning system paths
   */
  private async discoverUnknownTools(): Promise<void> {
    // Additional tool names commonly found on security-oriented systems
    const additionalTools = [
      'testssl.sh', 'testssl', 'netcat', 'nc', 'ncat', 'socat',
      'cewl', 'crunch', 'hash-identifier', 'hashid',
      'impacket-smbserver', 'impacket-psexec', 'impacket-wmiexec',
      'impacket-getTGT', 'impacket-secretsdump',
      'ldapsearch', 'rpcclient', 'smbclient', 'smbmap',
      'snmpwalk', 'onesixtyone', 'smtp-user-enum',
      'exiftool', 'steghide', 'zsteg', 'stegsolve',
      'openvpn', 'proxychains', 'tor', 'torsocks',
      'netdiscover', 'arp-scan', 'nbtscan', 'fping',
      'arjun', 'paramspider', 'gospider', 'hakrawler',
      'gau', 'waybackurls', 'meg', 'unfurl', 'qsreplace',
      'assetfinder', 'httprobe', 'sublist3r',
      'pspy', 'linpeas.sh', 'winpeas.exe',
      'feroxbuster', 'rustscan', 'autorecon',
      'certipy', 'kerbrute', 'rubeus',
      'chisel', 'ligolo-ng', 'pwncat',
    ];

    for (const name of additionalTools) {
      if (this.installedTools.has(name) || this.toolDatabase.has(name)) continue;

      const installed = await this.checkToolInstalled(name);
      if (installed) {
        const version = await this.getToolVersion(name);
        const toolInfo: ToolInfo = {
          name,
          displayName: name,
          version,
          description: `Dynamically discovered tool: ${name}`,
          category: this.guessCategory(name),
          capabilities: ['dynamic'],
          installed: true,
          requiresRoot: false
        };
        this.installedTools.set(name, toolInfo);
      }
    }
  }

  /**
   * Register a dynamically discovered tool
   */
  public registerTool(name: string, info: Partial<ToolInfo>): void {
    const toolInfo: ToolInfo = {
      name,
      displayName: info.displayName || name,
      version: info.version || 'unknown',
      description: info.description || `Tool: ${name}`,
      category: info.category || ToolCategory.CUSTOM,
      capabilities: info.capabilities || ['dynamic'],
      installed: true,
      path: info.path,
      requiresRoot: info.requiresRoot || false,
      defaultArgs: info.defaultArgs
    };
    this.installedTools.set(name, toolInfo);
    this.toolDatabase.set(name, toolInfo);
  }

  /**
   * Guess tool category based on name
   */
  private guessCategory(name: string): ToolCategory {
    const lower = name.toLowerCase();
    if (/nmap|masscan|recon|amass|subfinder|harvest|shodan|whois|dig|dns|fierce/.test(lower)) return ToolCategory.RECON;
    if (/nikto|nuclei|wpscan|joom|zap|burp|scan/.test(lower)) return ToolCategory.SCANNER;
    if (/sql|xss|commix|dalfox|ffuf|wfuzz|gobust|dirb|ferox|fuzz|web|http|wafw|ssl|katana/.test(lower)) return ToolCategory.WEB;
    if (/metasploit|msf|exploit|searchsploit|beef|router/.test(lower)) return ToolCategory.EXPLOIT;
    if (/hydra|john|hashcat|medusa|ncrack|crack|cewl|crunch|hash|patator/.test(lower)) return ToolCategory.PASSWORD;
    if (/air|wifi|reaver|bully|kismet|fluxion/.test(lower)) return ToolCategory.WIRELESS;
    if (/wireshark|tshark|tcpdump|ettercap|bettercap|responder|sniff|mitm|hping|arp/.test(lower)) return ToolCategory.SNIFFING;
    if (/autopsy|binwalk|volatility|foremost|strings|exif|steg/.test(lower)) return ToolCategory.FORENSICS;
    if (/radare|ghidra|gdb|objdump|rizin|cutter/.test(lower)) return ToolCategory.REVERSE_ENGINEERING;
    if (/enum4linux|smbclient|crackmapexec|evil-winrm|bloodhound|impacket|empire|sliver/.test(lower)) return ToolCategory.POST_EXPLOITATION;
    if (/trivy|prowler|pacu|cloud|scout/.test(lower)) return ToolCategory.CLOUD;
    return ToolCategory.CUSTOM;
  }

  /**
   * Get information about a specific tool
   */
  public async getToolInfo(name: string): Promise<ToolInfo | null> {
    let toolInfo = this.installedTools.get(name) || this.toolDatabase.get(name);

    if (!toolInfo) {
      return null;
    }

    // Update installation status if not cached
    if (!this.installedTools.has(name)) {
      const installed = await this.checkToolInstalled(name);
      if (installed) {
        const version = await this.getToolVersion(name);
        toolInfo = {
          ...toolInfo,
          installed: true,
          version
        };
        this.installedTools.set(name, toolInfo);
      }
    }

    return toolInfo;
  }

  /**
   * Install a tool using apt-get
   */
  public async installTool(name: string): Promise<boolean> {
    try {
      await this.executeCommand('sudo', ['apt-get', 'update']);
      await this.executeCommand('sudo', ['apt-get', 'install', '-y', name]);

      // Verify installation
      const installed = await this.checkToolInstalled(name);
      if (installed) {
        const toolInfo = this.toolDatabase.get(name);
        if (toolInfo) {
          const version = await this.getToolVersion(name);
          this.installedTools.set(name, {
            ...toolInfo,
            installed: true,
            version
          });
        }
      }

      return installed;
    } catch (error) {
      console.error(`Failed to install ${name}:`, error);
      return false;
    }
  }

  /**
   * Create a custom security tool
   */
  public async createCustomTool(
    name: string,
    script: string,
    description: string,
    category: ToolCategory = ToolCategory.CUSTOM
  ): Promise<CustomTool> {
    // Ensure custom tools directory exists
    await fs.mkdir(this.customToolsPath, { recursive: true });

    const scriptPath = path.join(this.customToolsPath, name);

    // Write script file
    await fs.writeFile(scriptPath, script, { mode: 0o755 });

    const customTool: CustomTool = {
      name,
      script,
      description,
      category,
      requiresRoot: script.includes('sudo'),
      createdAt: new Date()
    };

    // Save metadata
    const metadataPath = path.join(this.customToolsPath, `${name}.meta.json`);
    await fs.writeFile(metadataPath, JSON.stringify(customTool, null, 2));

    // Add to installed tools
    const toolInfo: ToolInfo = {
      name,
      displayName: name,
      version: '1.0.0',
      description,
      category,
      capabilities: ['custom'],
      installed: true,
      path: scriptPath,
      requiresRoot: customTool.requiresRoot
    };
    this.installedTools.set(name, toolInfo);

    return customTool;
  }

  /**
   * List all available tools
   */
  public listAvailableTools(category?: ToolCategory): ToolInfo[] {
    const allTools = new Map([...this.toolDatabase, ...this.installedTools]);
    let tools = Array.from(allTools.values());

    if (category) {
      tools = tools.filter(tool => tool.category === category);
    }

    return tools.sort((a, b) => a.name.localeCompare(b.name));
  }

  /**
   * Generate command line for a tool
   */
  public getToolCommand(
    toolName: string,
    options: CommandOptions
  ): { command: string; args: string[] } {
    const toolInfo = this.installedTools.get(toolName) || this.toolDatabase.get(toolName);

    if (!toolInfo) {
      throw new Error(`Unknown tool: ${toolName}`);
    }

    const args: string[] = [];

    // Add default arguments
    if (toolInfo.defaultArgs) {
      args.push(...toolInfo.defaultArgs);
    }

    // Tool-specific command generation
    switch (toolName) {
      case 'nmap':
        args.push(options.target);
        if (options.port) {
          args.push('-p', options.port.toString());
        }
        if (options.output) {
          args.push('-oA', options.output);
        }
        if (options.verbose) {
          args.push('-v');
        }
        break;

      case 'nikto':
        args.push('-h', options.target);
        if (options.port) {
          args.push('-p', options.port.toString());
        }
        if (options.output) {
          args.push('-o', options.output);
        }
        break;

      case 'sqlmap':
        args.push('-u', options.target);
        if (options.verbose) {
          args.push('-v');
        }
        break;

      case 'hydra':
        if (options.protocol) {
          args.push(options.protocol);
        }
        args.push(options.target);
        break;

      case 'gobuster':
        args.push('dir');
        args.push('-u', options.target);
        if (options.additionalArgs?.includes('wordlist')) {
          const wordlistIndex = options.additionalArgs.indexOf('wordlist') + 1;
          if (wordlistIndex < options.additionalArgs.length) {
            args.push('-w', options.additionalArgs[wordlistIndex]);
          }
        }
        break;

      default:
        // Generic command construction
        args.push(options.target);
        if (options.additionalArgs) {
          args.push(...options.additionalArgs);
        }
    }

    return {
      command: toolInfo.path || toolName,
      args
    };
  }

  /**
   * Get tools by category
   */
  public getToolsByCategory(category: ToolCategory): ToolInfo[] {
    return this.listAvailableTools(category);
  }

  /**
   * Search tools by capability
   */
  public searchByCapability(capability: string): ToolInfo[] {
    return Array.from(this.installedTools.values()).filter(tool =>
      tool.capabilities.some(cap => cap.includes(capability.toLowerCase()))
    );
  }

  // Private helper methods

  private async checkToolInstalled(name: string): Promise<boolean> {
    try {
      await this.executeCommand('which', [name]);
      return true;
    } catch {
      return false;
    }
  }

  private async getToolVersion(name: string): Promise<string> {
    try {
      const result = await this.executeCommand(name, ['--version']);
      const lines = result.split('\n');
      return lines[0] || 'unknown';
    } catch {
      return 'unknown';
    }
  }

  private async discoverCustomTools(): Promise<void> {
    try {
      const files = await fs.readdir(this.customToolsPath);

      for (const file of files) {
        if (file.endsWith('.meta.json')) {
          const metadataPath = path.join(this.customToolsPath, file);
          const content = await fs.readFile(metadataPath, 'utf8');
          const customTool: CustomTool = JSON.parse(content);

          const toolInfo: ToolInfo = {
            name: customTool.name,
            displayName: customTool.name,
            version: '1.0.0',
            description: customTool.description,
            category: customTool.category,
            capabilities: ['custom'],
            installed: true,
            path: path.join(this.customToolsPath, customTool.name),
            requiresRoot: customTool.requiresRoot
          };

          this.installedTools.set(customTool.name, toolInfo);
        }
      }
    } catch (error) {
      // Custom tools directory doesn't exist yet
    }
  }

  private executeCommand(command: string, args: string[]): Promise<string> {
    return new Promise((resolve, reject) => {
      const proc = spawn(command, args);
      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('error', reject);

      proc.on('close', (exitCode) => {
        if (exitCode === 0) {
          resolve(stdout);
        } else {
          reject(new Error(stderr || `Command failed with exit code ${exitCode}`));
        }
      });
    });
  }
}
