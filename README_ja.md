# Active Directory キルチェーンへの攻撃＆防衛

<img width="650" src="https://camo.githubusercontent.com/9547d8152e3490a6e5e3da0279faab64340885be/68747470733a2f2f646f63732e6d6963726f736f66742e636f6d2f656e2d75732f616476616e6365642d7468726561742d616e616c79746963732f6d656469612f61747461636b2d6b696c6c2d636861696e2d736d616c6c2e6a7067">

## 概要
このドキュメントは、攻撃者がActive Directoryを危険にさらすために利用している特定の戦術、技術、および手順（TTP）を理解し、緩和、検出、および防止するためのガイダンスとして役立つ有益な情報資産として作成されています。 そしてActive Directoryキルチェーンへの攻撃と攻撃後の敵対者スパイ活動の最新のノウハウについて理解してください。

## 目次
* [探索](#探索)
* [権限昇格](#権限昇格)
* [防衛回避](#防衛回避)
* [認証情報ダンピング](#認証情報ダンピング)
* [横展開](#横展開)
* [永続化](#永続化)
* [防衛＆検知](#防衛＆検知)

------

## 探索
### SPN Scanning
* [SPN Scanning – Service Discovery without Network Port Scanning](https://adsecurity.org/?p=1508)
* [Active Directory: PowerShell script to list all SPNs used](https://social.technet.microsoft.com/wiki/contents/articles/18996.active-directory-powershell-script-to-list-all-spns-used.aspx)
* [Discovering Service Accounts Without Using Privileges](https://blog.stealthbits.com/discovering-service-accounts-without-using-privileges/)

### データマイニング
* [A Data Hunting Overview](https://thevivi.net/2018/05/23/a-data-hunting-overview/)
* [Push it, Push it Real Good](https://www.harmj0y.net/blog/redteaming/push-it-push-it-real-good/)
* [Finding Sensitive Data on Domain SQL Servers using PowerUpSQL](https://blog.netspi.com/finding-sensitive-data-domain-sql-servers-using-powerupsql/)
* [Sensitive Data Discovery in Email with MailSniper](https://www.youtube.com/watch?v=ZIOw_xfqkKM)
* [Remotely Searching for Sensitive Files](https://www.fortynorthsecurity.com/remotely-search/)

### ユーザハンティング
* [Hidden Administrative Accounts: BloodHound to the Rescue](https://www.crowdstrike.com/blog/hidden-administrative-accounts-bloodhound-to-the-rescue/)
* [Active Directory Recon Without Admin Rights](https://adsecurity.org/?p=2535)
* [Gathering AD Data with the Active Directory PowerShell Module](https://adsecurity.org/?p=3719)
* [Using ActiveDirectory module for Domain Enumeration from PowerShell Constrained Language Mode](http://www.labofapenetrationtester.com/2018/10/domain-enumeration-from-PowerShell-CLM.html)
* [PowerUpSQL Active Directory Recon Functions](https://github.com/NetSPI/PowerUpSQL/wiki/Active-Directory-Recon-Functions)
* [Derivative Local Admin](https://www.sixdub.net/?p=591)
* [Dumping Active Directory Domain Info – with PowerUpSQL!](https://blog.netspi.com/dumping-active-directory-domain-info-with-powerupsql/)
* [Local Group Enumeration](https://www.harmj0y.net/blog/redteaming/local-group-enumeration/)
* [Attack Mapping With Bloodhound](https://blog.stealthbits.com/local-admin-mapping-bloodhound)
* [Situational Awareness](https://pentestlab.blog/2018/05/28/situational-awareness/)
* [Commands for Domain Network Compromise](https://www.javelin-networks.com/static/5fcc6e84.pdf)
* [A Pentester’s Guide to Group Scoping](https://www.harmj0y.net/blog/activedirectory/a-pentesters-guide-to-group-scoping/)

### LAPS
* [Microsoft LAPS Security & Active Directory LAPS Configuration Recon](https://adsecurity.org/?p=3164)
* [Running LAPS with PowerView](https://www.harmj0y.net/blog/powershell/running-laps-with-powerview/)
* [RastaMouse LAPS Part 1 & 2](https://rastamouse.me/tags/laps/)

### AppLocker
* [Enumerating AppLocker Config](https://rastamouse.me/2018/09/enumerating-applocker-config/)

------

## 権限昇格
### Passwords in SYSVOL & Group Policy Preferences
* [Finding Passwords in SYSVOL & Exploiting Group Policy Preferences](https://adsecurity.org/?p=2288)
* [Pentesting in the Real World: Group Policy Pwnage](https://blog.rapid7.com/2016/07/27/pentesting-in-the-real-world-group-policy-pwnage/)

### MS14-068 Kerberos脆弱性
* [MS14-068: Vulnerability in (Active Directory) Kerberos Could Allow Elevation of Privilege](https://adsecurity.org/?p=525)
* [Digging into MS14-068, Exploitation and Defence](https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/)
* [From MS14-068 to Full Compromise – Step by Step](https://www.trustedsec.com/2014/12/ms14-068-full-compromise-step-step/)

### DNSAdmins
* [Abusing DNSAdmins privilege for escalation in Active Directory](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
* [From DNSAdmins to Domain Admin, When DNSAdmins is More than Just DNS Administration](https://adsecurity.org/?p=4064)

### Unconstrained Delegation
* [Domain Controller Print Server + Unconstrained Kerberos Delegation = Pwned Active Directory Forest](https://adsecurity.org/?p=4056)
* [Active Directory Security Risk #101: Kerberos Unconstrained Delegation (or How Compromise of a Single Server Can Compromise the Domain)](https://adsecurity.org/?p=1667)
* [Unconstrained Delegation Permissions](https://blog.stealthbits.com/unconstrained-delegation-permissions/)
* [Trust? Years to earn, seconds to break](https://labs.mwrinfosecurity.com/blog/trust-years-to-earn-seconds-to-break/)
* [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)

### Constrained Delegation
* [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [From Kekeo to Rubeus](https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)
* [S4U2Pwnage](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
* [Kerberos Delegation, Spns And More...](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more)
* [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)

### Insecure Group Policy Object Permission Rights
* [Abusing GPO Permissions](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [A Red Teamer’s Guide to GPOs and OUs](https://wald0.com/?p=179)
* [File templates for GPO Abuse](https://github.com/rasta-mouse/GPO-Abuse)
* [GPO Abuse - Part 1](https://rastamouse.me/2019/01/gpo-abuse-part-1/)

### Insecure ACLs Permission Rights
* [Exploiting Weak Active Directory Permissions With Powersploit](https://blog.stealthbits.com/exploiting-weak-active-directory-permissions-with-powersploit/)
* [Escalating privileges with ACLs in Active Directory
](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [Abusing Active Directory Permissions with PowerView
](http://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/)
* [BloodHound 1.3 – The ACL Attack Path Update](https://wald0.com/?p=112)
* [Scanning for Active Directory Privileges & Privileged Accounts](https://adsecurity.org/?p=3658)
* [Active Directory Access Control List – Attacks and Defense](https://techcommunity.microsoft.com/t5/Enterprise-Mobility-Security/Active-Directory-Access-Control-List-8211-Attacks-and-Defense/ba-p/250315)
* [aclpwn - Active Directory ACL exploitation with BloodHound](https://www.slideshare.net/DirkjanMollema/aclpwn-active-directory-acl-exploitation-with-bloodhound)

### Domain Trusts
* [A Guide to Attacking Domain Trusts](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [It's All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts](https://adsecurity.org/?p=1588)
* [Active Directory forest trusts part 1 - How does SID filtering work?](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work)
* [The Forest Is Under Control. Taking over the entire Active Directory forest](https://hackmag.com/security/ad-forest/)
* [Not A Security Boundary: Breaking Forest Trusts](https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d)
* [The Trustpocalypse](http://www.harmj0y.net/blog/redteaming/the-trustpocalypse/)
* [Pentesting Active Directory Forests](https://www.dropbox.com/s/ilzjtlo0vbyu1u0/Carlos%20Garcia%20-%20Rooted2019%20-%20Pentesting%20Active%20Directory%20Forests%20public.pdf?dl=0)

### DCShadow
* [Privilege Escalation With DCShadow](https://blog.stealthbits.com/privilege-escalation-with-dcshadow/)
* [DCShadow](https://pentestlab.blog/2018/04/16/dcshadow/)
* [DCShadow explained: A technical deep dive into the latest AD attack technique](https://blog.alsid.eu/dcshadow-explained-4510f52fc19d)
* [DCShadow - Silently turn off Active Directory Auditing](http://www.labofapenetrationtester.com/2018/05/dcshadow-sacl.html)
* [DCShadow - Minimal permissions, Active Directory Deception, Shadowception and more](http://www.labofapenetrationtester.com/2018/04/dcshadow.html)

### RID
* [Rid Hijacking: When Guests Become Admins](https://blog.stealthbits.com/rid-hijacking-when-guests-become-admins/)

### Microsoft SQL Server
* [How to get SQL Server Sysadmin Privileges as a Local Admin with PowerUpSQL](https://blog.netspi.com/get-sql-server-sysadmin-privileges-local-admin-powerupsql/)
* [Compromise With Powerupsql – Sql Attacks](https://blog.stealthbits.com/compromise-with-powerupsql-sql-attacks/)

### Red Forest
* [Attack and defend Microsoft Enhanced Security Administrative](https://download.ernw-insight.de/troopers/tr18/slides/TR18_AD_Attack-and-Defend-Microsoft-Enhanced-Security.pdf)

### Exchange
* [Exchange-AD-Privesc](https://github.com/gdedrouas/Exchange-AD-Privesc)
* [Abusing Exchange: One API call away from Domain Admin](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
* [NtlmRelayToEWS](https://github.com/Arno0x/NtlmRelayToEWS)

### NTML Relay
* [Pwning with Responder – A Pentester’s Guide](https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/)
* [Practical guide to NTLM Relaying in 2017 (A.K.A getting a foothold in under 5 minutes)](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
* [Relaying credentials everywhere with ntlmrelayx](https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/)
------

## 横展開
### Microsoft SQL Server Database links
* [SQL Server – Link… Link… Link… and Shell: How to Hack Database Links in SQL Server!](https://blog.netspi.com/how-to-hack-database-links-in-sql-server/)
* [SQL Server Link Crawling with PowerUpSQL](https://blog.netspi.com/sql-server-link-crawling-powerupsql/)

### Pass The Hash
* [Performing Pass-the-hash Attacks With Mimikatz](https://blog.stealthbits.com/passing-the-hash-with-mimikatz)
* [How to Pass-the-Hash with Mimikatz](https://blog.cobaltstrike.com/2015/05/21/how-to-pass-the-hash-with-mimikatz/)
* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)

### System Center Configuration Manager (SCCM)
* [Targeted Workstation Compromise With Sccm](https://enigma0x3.net/2015/10/27/targeted-workstation-compromise-with-sccm/)
* [PowerSCCM - PowerShell module to interact with SCCM deployments](https://github.com/PowerShellMafia/PowerSCCM)

### WSUS
* [Remote Weaponization of WSUS MITM](https://www.sixdub.net/?p=623)
* [WSUSpendu](https://www.blackhat.com/docs/us-17/wednesday/us-17-Coltel-WSUSpendu-Use-WSUS-To-Hang-Its-Clients-wp.pdf)
* [Leveraging WSUS – Part One](https://ijustwannared.team/2018/10/15/leveraging-wsus-part-one/)

### パスワードスプレー
* [Password Spraying Windows Active Directory Accounts - Tradecraft Security Weekly #5](https://www.youtube.com/watch?v=xB26QhnL64c)
* [Attacking Exchange with MailSniper](https://www.blackhillsinfosec.com/attacking-exchange-with-mailsniper/)
* [A Password Spraying tool for Active Directory Credentials by Jacob Wilkin](https://github.com/SpiderLabs/Spray)

### 横展開の自動化
* [GoFetch is a tool to automatically exercise an attack plan generated by the BloodHound application](https://github.com/GoFetchAD/GoFetch)
* [DeathStar - Automate getting Domain Admin using Empire](https://github.com/byt3bl33d3r/DeathStar)
* [ANGRYPUPPY - Bloodhound Attack Path Automation in CobaltStrike](https://github.com/vysec/ANGRYPUPPY)
------

## 防衛回避

### インメモリ回避
* [Bypassing Memory Scanners with Cobalt Strike and Gargoyle](https://labs.mwrinfosecurity.com/blog/experimenting-bypassing-memory-scanners-with-cobalt-strike-and-gargoyle/)
* [In-Memory Evasions Course](https://www.youtube.com/playlist?list=PL9HO6M_MU2nc5Q31qd2CwpZ8J4KFMhgnK)
* [Bring Your Own Land (BYOL) – A Novel Red Teaming Technique](https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html)

### EDR回避
* [Red Teaming in the EDR age](https://youtu.be/l8nkXCOYQC4)
* [Sharp-Suite - Process Argument Spoofing](https://github.com/FuzzySecurity/Sharp-Suite)

### OPSEC
* [Modern Defenses and YOU!](https://blog.cobaltstrike.com/2017/10/25/modern-defenses-and-you/)
* [OPSEC Considerations for Beacon Commands](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/)
* [Red Team Tradecraft and TTP Guidance](https://sec564.com/#!docs/tradecraft.md)
* [Fighting the Toolset](https://www.youtube.com/watch?v=RoqVunX_sqA)

### Microsoft ATA & ATP回避
* [Red Team Techniques for Evading, Bypassing, and Disabling MS
Advanced Threat Protection and Advanced Threat Analytics](https://www.blackhat.com/docs/eu-17/materials/eu-17-Thompson-Red-Team-Techniques-For-Evading-Bypassing-And-Disabling-MS-Advanced-Threat-Protection-And-Advanced-Threat-Analytics.pdf)
* [Red Team Revenge - Attacking Microsoft ATA](https://www.slideshare.net/nikhil_mittal/red-team-revenge-attacking-microsoft-ata)
* [Evading Microsoft ATA for Active Directory Domination](https://www.slideshare.net/nikhil_mittal/evading-microsoft-ata-for-active-directory-domination)

### PowerShell スクリプトブロックログ回避
* [PowerShell ScriptBlock Logging Bypass](https://cobbr.io/ScriptBlock-Logging-Bypass.html)

### PowerShell アンチマルウェアスキャンインタフェース (AMSI) バイパス
* [How to bypass AMSI and execute ANY malicious Powershell code](https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html)
* [AMSI: How Windows 10 Plans to Stop Script-Based Attacks](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [AMSI Bypass: Patching Technique](https://www.cyberark.com/threat-research-blog/amsi-bypass-patching-technique/)
* [Invisi-Shell - Hide your Powershell script in plain sight. Bypass all Powershell security features](https://github.com/OmerYa/Invisi-Shell)

### アンチマルウェアスキャンインタフェース (AMSI) をバイパスして.NETアセンブリをロード
* [A PoC function to corrupt the g_amsiContext global variable in clr.dll in .NET Framework Early Access build 3694](https://gist.github.com/mattifestation/ef0132ba4ae3cc136914da32a88106b9)

### AppLocker & Device Guard バイパス
* [Living Off The Land Binaries And Scripts - (LOLBins and LOLScripts)](https://github.com/LOLBAS-Project/LOLBAS)

### Sysmon 回避
* [Subverting Sysmon: Application of a Formalized Security Product Evasion Methodology](https://github.com/mattifestation/BHUSA2018_Sysmon)
* [sysmon-config-bypass-finder](https://github.com/mkorman90/sysmon-config-bypass-finder)

### HoneyTokens 回避
* [Forging Trusts for Deception in Active Directory](http://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [Honeypot Buster: A Unique Red-Team Tool](https://jblog.javelin-networks.com/blog/the-honeypot-buster/)

### セキュリティツールの無効化
* [Invoke-Phant0m - Windows Event Log Killer](https://github.com/hlldz/Invoke-Phant0m)

------

## 認証情報ダンピング

### NTDS.DIT Password Extraction
* [How Attackers Pull the Active Directory Database (NTDS.dit) from a Domain Controller](https://adsecurity.org/?p=451)
* [Extracting Password Hashes From The Ntds.dit File](https://blog.stealthbits.com/extracting-password-hashes-from-the-ntds-dit-file/)

### SAM (Security Accounts Manager)
* [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)

### Kerberoasting
* [Kerberoasting Without Mimikatz](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
* [Cracking Kerberos TGS Tickets Using Kerberoast – Exploiting Kerberos to Compromise the Active Directory Domain](https://adsecurity.org/?p=2293)
* [Extracting Service Account Passwords With Kerberoasting](https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/)
* [Cracking Service Account Passwords with Kerberoasting](https://www.cyberark.com/blog/cracking-service-account-passwords-kerberoasting/)
* [Kerberoast PW list for cracking passwords with complexity requirements](https://gist.github.com/edermi/f8b143b11dc020b854178d3809cf91b5)

### Kerberos AP-REP Roasting
* [Roasting AS-REPs](http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/) 

### Windows Credential Manager/Vault
* [Operational Guidance for Offensive User DPAPI Abuse](https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/)
* [Jumping Network Segregation with RDP](https://rastamouse.me/2017/08/jumping-network-segregation-with-rdp/)

### DCSync
* [Mimikatz and DCSync and ExtraSids, Oh My](https://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/)
* [Mimikatz DCSync Usage, Exploitation, and Detection](https://adsecurity.org/?p=1729)
* [Dump Clear-Text Passwords for All Admins in the Domain Using Mimikatz DCSync](https://adsecurity.org/?p=2053)

### LLMNR/NBT-NS ポイズニング
* [LLMNR/NBT-NS Poisoning Using Responder](https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/)

### その他
* [Compromising Plain Text Passwords In Active Directory](https://blog.stealthbits.com/compromising-plain-text-passwords-in-active-directory)
------

## 永続化
### ゴールデンチケット
* [Golden Ticket](https://pentestlab.blog/2018/04/09/golden-ticket/)
* [Kerberos Golden Tickets are Now More Golden](https://adsecurity.org/?p=1640)

### SID 履歴
* [Sneaky Active Directory Persistence #14: SID History](https://adsecurity.org/?p=1772)

### シルバーチケット
* [How Attackers Use Kerberos Silver Tickets to Exploit Systems](https://adsecurity.org/?p=2011)
* [Sneaky Active Directory Persistence #16: Computer Accounts & Domain Controller Silver Tickets](https://adsecurity.org/?p=2753)

### DCShadow
* [Creating Persistence With Dcshadow](https://blog.stealthbits.com/creating-persistence-with-dcshadow/)

### AdminSDHolder
* [Sneaky Active Directory Persistence #15: Leverage AdminSDHolder & SDProp to (Re)Gain Domain Admin Rights](https://adsecurity.org/?p=1906)
* [Persistence Using Adminsdholder And Sdprop](https://blog.stealthbits.com/persistence-using-adminsdholder-and-sdprop/)

### グループポリシーオブジェクト
* [Sneaky Active Directory Persistence #17: Group Policy](https://adsecurity.org/?p=2716)

### Skeleton Keys
* [Unlocking All The Doors To Active Directory With The Skeleton Key Attack](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)
* [Skeleton Key](https://pentestlab.blog/2018/04/10/skeleton-key/)
* [Attackers Can Now Use Mimikatz to Implant Skeleton Key on Domain Controllers & BackDoor Your Active Directory Forest](https://adsecurity.org/?p=1275)

### SeEnableDelegationPrivilege
* [The Most Dangerous User Right You (Probably) Have Never Heard Of](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)
* [SeEnableDelegationPrivilege Active Directory Backdoor](https://www.youtube.com/watch?v=OiqaO9RHskU)

### Security Support Provider
* [Sneaky Active Directory Persistence #12: Malicious Security Support Provider (SSP)](https://adsecurity.org/?p=1760)

### ディレクトリサービスリストアモード
* [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
* [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

### ACLs & Security Descriptors
* [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf)
* [Shadow Admins – The Stealthy Accounts That You Should Fear The Most](https://www.cyberark.com/threat-research-blog/shadow-admins-stealthy-accounts-fear/)
* [The Unintended Risks of Trusting Active Directory](https://www.slideshare.net/harmj0y/the-unintended-risks-of-trusting-active-directory)

## ツール＆スクリプト
* [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) - 状況認識を助けるPowerShellフレームワーク
* [BloodHound](https://github.com/BloodHoundAD/BloodHound) - ドメイン管理者への六次の隔たり
* [Impacket](https://github.com/SecureAuthCorp/impacket) - Impacketはネットワークプロトコルを扱うためのPythonクラスの集まりです。
* [aclpwn.py](https://github.com/fox-it/aclpwn.py) - BloodHoundによるActive Directory ACLの悪用
* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - ネットワークをテストするためのスイスアーミーナイフ
* [ADACLScanner](https://github.com/canix1/ADACLScanner) - Active Directoryでアクセス制御リスト（DACL）およびシステムアクセス制御リスト（SACL）のレポートを作成するために使用されるGUIまたはコマンドlintを備えたツール
* [zBang](https://github.com/cyberark/zBang) - zBangは、潜在的な特権アカウントの脅威を検出するリスク評価ツールです。
* [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) - SQL Serverを攻撃するためのPowerShellツールキット
* [Rubeus](https://github.com/GhostPack/Rubeus) -  Rubeusは、生のKerberos対話および悪用のためのC#ツールセットです。
* [ADRecon](https://github.com/sense-of-security/ADRecon) - Active Directoryに関する情報を収集し、ターゲットAD環境の現在の状態の全体像を提供できるレポートを生成するツール
* [Mimikatz](https://github.com/gentilkiwi/mimikatz) - プレーンテキストのパスワード、ハッシュ、PINコード、Kerberosチケットをメモリから抽出するだけでなく、pass-the-hashの実行、pass-the-ticketの実行、またはゴールデンチケットを作成するためのユーティリティ
* [Grouper](https://github.com/l0ss/Grouper) - ADグループポリシーで脆弱な設定を見つけるのを助けるためのPowerShellスクリプト。

## 電子書籍
* [The Dog Whisperer’s Handbook – A Hacker’s Guide to the BloodHound Galaxy](https://www.ernw.de/download/BloodHoundWorkshop/ERNW_DogWhispererHandbook.pdf)
* [Varonis eBook: Pen Testing Active Directory Environments](https://www.varonis.com/blog/varonis-ebook-pen-testing-active-directory-environments/)

## チートシート
* [Tools Cheat Sheets](https://github.com/HarmJ0y/CheatSheets) - ツール (PowerView、 PowerUp、 Empire および PowerSploit)
* [DogWhisperer - BloodHound Cypher Cheat Sheet (v2)](https://github.com/SadProcessor/Cheats/blob/master/DogWhispererV2.md)
* [PowerView-3.0 tips and tricks](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)
* [PowerView-2.0 tips and tricks](https://gist.github.com/HarmJ0y/3328d954607d71362e3c)

## Other Resources
* [Tactics, Techniques and Procedures for Attacking Active Directory BlackHat Asia 2019](https://docs.google.com/presentation/d/1j2nW05H-iRz7-FVTRh-LBXQm6M6YIBQNWa4V7tp99YQ/)
------

## 防衛＆検知
### ツール＆スクリプト
* [Create-Tiers in AD](https://github.com/davidprowe/AD_Sec_Tools) - Project Title Active Directory Auto Deployment of Tiers in any environment
* [SAMRi10](https://gallery.technet.microsoft.com/SAMRi10-Hardening-Remote-48d94b5b)  - Windows 10/Server 2016でのSAMリモートアクセスの強化
* [Net Cease](https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b)  - ネットセッション列挙の強化
* [PingCastle](https://www.pingcastle.com/) - リスク評価と成熟度フレームワークに基づいた方法で、Active Directoryのセキュリティレベルを迅速に評価するように設計されたツール
* [Aorato Skeleton Key Malware Remote DC Scanner](https://gallery.technet.microsoft.com/Aorato-Skeleton-Key-24e46b73) - Skeleton Key マルウェアの存在をリモートでスキャンします。
* [Reset the krbtgt account password/keys](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51) - このスクリプトを使用すると、操作によってKerberos認証の問題が発生する可能性を最小限に抑えながら、krbtgtアカウントのパスワードと関連キーをリセットできます。
* [Reset The KrbTgt Account Password/Keys For RWDCs/RODCs](https://gallery.technet.microsoft.com/Reset-The-KrbTgt-Account-5f45a414)
* [Deploy-Deception](https://github.com/samratashok/Deploy-Deception) - Active DirectoryのおとりオブジェクトをデプロイするためのPowerShellモジュール
* [dcept](https://github.com/secureworks/dcept) - Active Directory honeytokenの展開と使用を検出するためのツール
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Windowsイベントログを視覚化および分析して、悪意のあるWindowsログオンを調査する
* [DCSYNCMonitor](https://github.com/shellster/DCSYNCMonitor) - DCSYNCおよびDCSHADOW攻撃を監視し、これらのイベントに対するカスタムWindowsイベントを作成します。
* [Sigma](https://github.com/Neo23x0/sigma/) - SIEMシステム向けのシグネチャフォーマット

### Active Directory セキュリティチェック (by Sean Metcalf - @Pyrotek3)

#### 一般的な推奨事項
* ローカル管理者パスワードを管理（LAPS）します。
* （必要に応じて）RDP制限付きAdminモードを実装します。
* サポートされていないOSをネットワークから削除してください。
* センシティブなシステム（DCなど）ではスケジュールされたタスクを監視します。
* OOB管理パスワード（DSRM）が定期的かつ安全に保存されていることを確認してください。
* SMB v2/v3+を使用してください
* デフォルトドメイン管理者とKRBTGTパスワードは、毎年、そしてAD管理者が退任するときに変更する必要があります。
* 不要になった信頼関係を削除し、必要に応じてSIDフィルタリングを有効にします。
* すべてのドメイン認証は、（可能であれば）「NTLMv2応答のみを送信し、LMとNTLMを拒否する」に設定する必要があります。
* DC、サーバー、およびすべての管理システムに対するインターネットアクセスをブロックします。

#### Admin 認証情報の保護
* 管理者グループに「ユーザー」またはコンピュータアカウントがないこと
* すべての管理者アカウントが「センシティブで委任できない」ようにします。
* 「保護されたユーザー」グループに管理者アカウントを追加します（ドメイン保護にはWindows Server 2012 R2ドメインコントローラー、2012R2 DFLが必要です）。
* 非アクティブな管理者アカウントをすべて無効にし、特権グループから削除します。

#### AD Admin 認証情報の保護
* AD管理者メンバーシップ（DA、EA、Schema Adminsなど）を制限し、カスタム委任グループのみを使用します。
* 認証情報が窃取される影響を軽減する「階層型」管理を行います
* 承認された管理者ワークステーション／サーバーに管理者のみがログオンするようにしてください。
* すべての管理者アカウントに時間ベースの一時的なグループメンバーシップを活用します

#### サービスアカウントの認証情報保護
* 同じセキュリティレベルのシステムに制限します。
* 「（グループ）管理されたサービスアカウント」（または20文字以上のパスワード）を利用して、資格情報の窃取（kerberoast）を軽減します。
* SAおよび管理者のためのパスワード要件を高めるためにFGPP（DFL => 2008）を実装します。
* ログオン制限 - 対話型ログオンを防止し、ログオン機能を特定のコンピュータに制限します。
* 非アクティブなSAを無効にし、特権グループから削除します。

#### リソース保護
* 管理者および重要なシステムを保護するためにネットワークをセグメント化します。
* 社内ネットワークの内部を監視するためにIDSを展開します。
* 別のネットワーク上のネットワークデバイスとOOBの管理

#### ドメインコントローラの保護
* ADをサポートするためにのみソフトウェアとサービスを実行してください。
* DC管理者/ログオン権限を持つ最小限のグループ（とユーザ）にしてください。
* DCPromo（特にMS14-068およびその他の重要なパッチ）を実行する前にパッチが適用されていることを確認してください。
* スケジュールされたタスクとスクリプトを検証します。

#### ワークステーション(とサーバ)の保護
* 特に権限昇格の脆弱性を迅速にパッチしてください。
* セキュリティバックポート修正プログラム（KB2871997）を展開します。
* Wdigest regキーを0に設定します（KB2871997/Windows 8.1/2012R2+）：HKEY_LOCAL_MACHINESYSTEMCurrentControlSetControlSecurityProvidersWdigest
* ユーザーフォルダでコードの実行をブロックするために、ワークステーションホワイトリスト（Microsoft AppLocker）を展開します - ホームディレクトリとプロファイルパス。
* アプリケーションメモリのエクスプロイト（ゼロデイ）を軽減するために、ワークステーションアプリケーションサンドボックステクノロジ（EMET）を展開します。

#### ロギング
* 拡張監査を有効にする
* 「監査：監査ポリシーのサブカテゴリ設定（Windows Vista以降）で監査ポリシーのカテゴリ設定を上書きする」
* PowerShellモジュールのログ記録を有効にし（"*"）、ログを中央ログサーバーに転送します（WEFまたはその他の方法で）。
* CMDプロセスのログ記録と機能強化（KB3004375）を有効にして、ログを中央ログサーバーに転送します。
* できるだけ多くのログデータを集中管理するためのSIEMまたは同等の機能。
* ユーザーの行動に関する高度な知識を得るためのユーザー行動分析システム（Microsoft ATAなど）。

#### セキュリティプロフェッショナルのチェック
* 誰がAD管理者権限を持っているかを特定します（ドメイン/フォレスト）。
* だれがドメインコントローラにログオンできるか（および仮想DCをホストしている仮想環境への管理者権限）を識別します。
* Active Directoryドメイン、OU、AdminSDHolder、およびGPOをスキャンして不適切なカスタム権限を探します。
* 信頼されていないシステム（ワークステーション）にログインしないようにして、AD管理者（別名Domain Admins）が自分の資格情報を保護するようにします。
* 現在DA（または同等）であるサービスアカウントの権利を制限します。

### 検知
|攻撃|イベントID|
|------|--------|
|アカウントとグループの列挙|4798: ユーザーのローカル グループ メンバーシップが列挙されました。<br>4799: セキュリティが有効なローカル グループ メンバーシップが列挙されました。|
|AdminSDHolder|4780: 管理者グループのメンバーのアカウントに ACL が設定されました。|
|Kekeo|4624: アカウントが正常にログオンしました。<br>4672: 特殊なログオン<br>4768: Kerberos認証サービス|
|シルバーチケット|4624: アカウントが正常にログオンしました。<br>4634: オグオフ<br>4672: 特殊なログオン|
|ゴールデンチケット|4624: アカウントが正常にログオンしました。<br>4672: 特殊なログオン|
|PowerShell|4103: Script Block Logging<br>400: エンジンノライフサイクル<br>403: エンジンノライフサイクル<br>4103: Module Logging<br>600: プロバイダーのライフサイクル<br>|
|DCShadow|4742: コンピューター アカウントが変更されました。<br>5137: ディレクトリ サービス オブジェクトが作成されました。<br>5141: ディレクトリ サービス オブジェクトが削除されました。<br>4929: Active Directory レプリカ ソース名前付けコンテキストが削除されました。|
|Skeleton Keys|4673: 特権を持つサービスが呼び出されました。<br>4611: 信頼されたログオン プロセスがローカル セキュリティ機関に登録されています。<br>4688: 新しいプロセスが作成されました。<br>4689: プロセスが終了しました。|
|PYKEK MS14-068|4672: 特殊なログオン<br>4624: アカウントが正常にログオンしました。<br>4768: Kerberos認証サービス|
|Kerberoasting|4769: Kerberos サービス チケットが要求されました。|
|S4U2Proxy|4769: Kerberos サービス チケットが要求されました。|
|横展開|4688: 新しいプロセスが作成されました。<br>4689: プロセスが終了しました。<br>4624: アカウントが正常にログオンしました。<br>4625: アカウントがログオンに失敗しました。|
|DNSAdmin|770: DNS Server plugin DLL has been loaded<br>541: The setting serverlevelplugindll on scope . has been set to `<dll path>`<br>150: DNS Server could not load or initialize the plug-in DLL|
|DCSync|4662: オブジェクトの操作を実行しました。|
|パスワードスプレー|4625: アカウントがログオンに失敗しました。<br>4771: Kerberos 事前認証に失敗しました。<br>4648: 明示的な資格情報を使用してログオンが試行されました。|

### リソース
* [ASD Strategies to Mitigate Cyber Security Incidents](https://acsc.gov.au/publications/Mitigation_Strategies_2017.pdf)
* [Reducing the Active Directory Attack Surface](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface)
* [Changes to Ticket-Granting Ticket (TGT) Delegation Across Trusts in Windows Server (AskPFEPlat edition)](https://blogs.technet.microsoft.com/askpfeplat/2019/04/11/changes-to-ticket-granting-ticket-tgt-delegation-across-trusts-in-windows-server-askpfeplat-edition/)
* [Active Directory: Ultimate Reading Collection](https://social.technet.microsoft.com/wiki/contents/articles/20964.active-directory-ultimate-reading-collection.aspx)
* [Securing Domain Controllers to Improve Active Directory Security](https://adsecurity.org/?p=3377)
* [Securing Windows Workstations: Developing a Secure Baseline](https://adsecurity.org/?p=3299)
* [Implementing Secure Administrative Hosts](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-secure-administrative-hosts)
* [Privileged Access Management for Active Directory Domain Services](https://docs.microsoft.com/en-us/microsoft-identity-manager/pam/privileged-identity-management-for-active-directory-domain-services)
* [Awesome Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening)
* [Best Practices for Securing Active Directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Introducing the Adversary Resilience Methodology — Part One](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-one-e38e06ffd604)
* [Introducing the Adversary Resilience Methodology — Part Two](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-two-279a1ed7863d)
* [Mitigating Pass-the-Hash and Other Credential Theft, version 2](https://download.microsoft.com/download/7/7/A/77ABC5BD-8320-41AF-863C-6ECFB10CB4B9/Mitigating-Pass-the-Hash-Attacks-and-Other-Credential-Theft-Version-2.pdf)
* [Configuration guidance for implementing the Windows 10 and Windows Server 2016 DoD Secure Host Baseline settings](https://github.com/nsacyber/Windows-Secure-Host-Baseline)
* [Monitoring Active Directory for Signs of Compromise](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise)
* [Detecting Lateral Movement through Tracking Event Logs](https://www.jpcert.or.jp/english/pub/sr/Detecting%20Lateral%20Movement%20through%20Tracking%20Event%20Logs_version2.pdf)
* [Kerberos Golden Ticket Protection Mitigating Pass-the-Ticket on Active Directory](https://cert.europa.eu/static/WhitePapers/UPDATED%20-%20CERT-EU_Security_Whitepaper_2014-007_Kerberos_Golden_Ticket_Protection_v1_4.pdf)
* [Overview of Microsoft's "Best Practices for Securing Active Directory"](https://digital-forensics.sans.org/blog/2013/06/20/overview-of-microsofts-best-practices-for-securing-active-directory)
* [The Keys to the Kingdom: Limiting Active Directory Administrators](https://dsimg.ubm-us.net/envelope/155422/314202/1330537912_Keys_to_the_Kingdom_Limiting_AD_Admins.pdf)
* [Protect Privileged AD Accounts With Five Free Controls](https://blogs.sans.org/cyber-defense/2018/09/10/protect-privileged-ad-accounts-with-five-free-controls/)
* [The Most Common Active Directory Security Issues and What You Can Do to Fix Them](https://adsecurity.org/?p=1684)
* [Event Forwarding Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance)
* [Planting the Red Forest: Improving AD on the Road to ESAE](https://www.mwrinfosecurity.com/our-thinking/planting-the-red-forest-improving-ad-on-the-road-to-esae/)
* [Detecting Kerberoasting Activity](https://adsecurity.org/?p=3458)
* [Security Considerations for Trusts](https://docs.microsoft.com/pt-pt/previous-versions/windows/server/cc755321(v=ws.10))
* [Advanced Threat Analytics suspicious activity guide](https://docs.microsoft.com/en-us/advanced-threat-analytics/suspicious-activity-guide)
* [Protection from Kerberos Golden Ticket](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_14_07_PassTheGolden_Ticket_v1_1.pdf)
* [Windows 10 Credential Theft Mitigation Guide](https://download.microsoft.com/download/C/1/4/C14579CA-E564-4743-8B51-61C0882662AC/Windows%2010%20credential%20theft%20mitigation%20guide.docx)
* [Detecting Pass-The- Ticket and Pass-The- Hash Attack Using Simple WMI Commands](https://blog.javelin-networks.com/detecting-pass-the-ticket-and-pass-the-hash-attack-using-simple-wmi-commands-2c46102b76bc)
* [Step by Step Deploy Microsoft Local Administrator Password Solution](https://gallery.technet.microsoft.com/Step-by-Step-Deploy-Local-7c9ef772)
* [Active Directory Security Best Practices](https://www.troopers.de/downloads/troopers17/TR17_AD_signed.pdf)
* [Finally Deploy and Audit LAPS with Project VAST, Part 1 of 2](https://blogs.technet.microsoft.com/jonsh/2018/10/03/finally-deploy-and-audit-laps-with-project-vast-part-1-of-2/)
* [Windows Security Log Events](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)
* [Talk Transcript BSidesCharm Detecting the Elusive: Active Directory Threat Hunting](https://www.trimarcsecurity.com/single-post/Detecting-the-Elusive-Active-Directory-Threat-Hunting)
* [Preventing Mimikatz Attacks](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5)
* [Understanding "Red Forest" - The 3-Tier ESAE and Alternative Ways to Protect Privileged Credentials](https://www.slideshare.net/QuestSoftware/understanding-red-forest-the-3tier-esae-and-alternative-ways-to-protect-privileged-credentials)
* [AD Reading: Active Directory Backup and Disaster Recovery](https://adsecurity.org/?p=22)
* [Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
* [Hunting For In-Memory .NET Attacks](https://www.endgame.com/blog/technical-blog/hunting-memory-net-attacks)
* [Mimikatz Overview, Defenses and Detection](https://www.sans.org/reading-room/whitepapers/detection/mimikatz-overview-defenses-detection-36780)
* [Trimarc Research: Detecting Password Spraying with Security Event Auditing](https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing)
* [Hunting for Gargoyle Memory Scanning Evasion](https://www.countercept.com/blog/hunting-for-gargoyle/)
* [Planning and getting started on the Windows Defender Application Control deployment process](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control-deployment-guide)
* [Preventing Lateral Movement Using Network Access Groups](https://medium.com/think-stack/preventing-lateral-movement-using-network-access-groups-7e8d539a9029)
* [How to Go from Responding to Hunting with Sysinternals Sysmon](https://onedrive.live.com/view.aspx?resid=D026B4699190F1E6!2843&ithint=file%2cpptx&app=PowerPoint&authkey=!AMvCRTKB_V1J5ow)
* [Windows Event Forwarding Guidance](https://github.com/palantir/windows-event-forwarding)
* [Threat Mitigation Strategies: Part 2 ? Technical Recommendations and Information](http://threatexpress.com/2018/05/threat-mitigation-strategies-technical-recommendations-and-info-part-2/)

## ライセンス
[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0)

To the extent possible under law, Rahmat Nurfauzi &#34;@infosecn1nja&#34; has waived all copyright and related or neighboring rights to this work.
