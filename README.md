# 🛡️ CyberPatriot Windows Security Checklist Updated in 2025-2026 Season

> A comprehensive security hardening checklist for CyberPatriot competitions on Windows systems. Items are ordered from highest to lowest point value.

## BIG FIRST THINGS

**DO THESE BEFORE ANYTHING ELSE:**

1. **Read the README thoroughly** - Contains critical information about required services and authorized users
2. **Answer all forensics questions** - Complete BEFORE making system changes
3. **Document authorized users and admins** - Write down who should have access according to README
4. **Document required services and other critical infastructure
5. Don't forget about the network quiz on cisco because you will likely be done before Linux


Go top to bottom unless you see something in the readme that indicates extra points for skipping.

Find key terms at the bottom
Do things in the readme before going through this standardized list
---

### 1 User Account Management

#### Remove Unauthorized Users
```powershell
# View all local users
net user

# Delete unauthorized user
net user <username> /delete
```

**Instructions:**
- Compare user list against README authorized users
- Delete any user accounts not explicitly listed as authorized
- Don't delete your own account, dat bad

#### Remove Unauthorized Administrators
```powershell
# View members of Administrators group
net localgroup administrators

# Remove user from administrators group
net localgroup administrators <username> /delete
```

**Instructions:**
- Check README for who should be an administrator
- Remove anyone from Administrators group who isn't authorized
- **Be careful here**

#### Add Missing Users
```powershell
# Create new user
net user <username> <password> /add

# Add to administrators if README says they should be admin
net localgroup administrators <username> /add

# Add to standard users group
net localgroup users <username> /add
```

#### Disable Guest Account
```powershell
# Disable the guest account
net user guest /active:no
```

#### Check for Hidden/Backdoor Accounts
```powershell
# View all accounts including hidden ones
Get-LocalUser | Select-Object Name, Enabled, Description
```
- Look for suspicious account names
- Look for accounts with $ at the end (usually system accounts, but could be backdoors)

---

### 2 Password Policies

#### Configure Password Policy
1. Press `Win + R`, type `secpol.msc`, press Enter
2. Navigate to **Account Policies → Password Policy**
3. Configure the following settings:

| Policy | Recommended Setting |
|--------|-------------------|
| Enforce password history | 5 passwords remembered |
| Maximum password age | 90 days |
| Minimum password age | 1 day |
| Minimum password length | 8 characters (or 10-12 for higher security) |
| Password must meet complexity requirements | **Enabled** |
| Store passwords using reversible encryption | **Disabled** |

**What complexity means:**
- Password must contain characters from 3 of these 4 categories:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Numbers (0-9)
  - Special characters (!@#$%^&*)

#### Configure Account Lockout Policy
1. In `secpol.msc`, navigate to **Account Policies → Account Lockout Policy**
2. Configure:

| Policy | Recommended Setting |
|--------|-------------------|
| Account lockout threshold | 5 invalid logon attempts |
| Account lockout duration | 30 minutes |
| Reset account lockout counter after | 30 minutes |

---

### 3 Windows Updates (Maybe ask Gavin before you do this, it *may* brick the machine)

#### Install All Updates
```powershell
# Method 1: GUI
# Settings → Update & Security → Windows Update → Check for updates
# Click "Check for updates" and install ALL available updates

# Method 2: PowerShell (Windows 10/11)
Install-Module PSWindowsUpdate
Get-WindowsUpdate
Install-WindowsUpdate -AcceptAll -AutoReboot
```

**Instructions:**
- Install ALL critical, security, and recommended updates
- This usually gives multiple points

#### Enable Automatic Updates
1. Settings → Update & Security → Windows Update → Advanced options
2. Enable automatic updates
3. Set active hours to prevent unexpected restarts during competition

---

### 4 Firewall Configuration

#### Enable Windows Defender Firewall
```powershell
# Enable firewall for all profiles via PowerShell
netsh advfirewall set allprofiles state on

# Verify it's enabled
netsh advfirewall show allprofiles
```

**GUI Method:**
1. Control Panel → System and Security → Windows Defender Firewall
2. Click "Turn Windows Defender Firewall on or off"
3. Enable for:
   - Domain networks
   - Private networks
   - Public networks

#### Configure Basic Firewall Rules
```powershell
# Set default behavior
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
```

**Instructions:**
- Block all inbound by default
- Allow outbound by default
- Only create allow rules for services required by README
- Common required services: HTTP (80), HTTPS (443), SSH (22), RDP (3389)

---

### 5 Remove Prohibited Software

#### Common Prohibited Software
Look for and remove these programs (careful, some of these are needed):

**Hacking Tools:**
- Wireshark (network analyzer)
- Nmap (port scanner)
- Cain & Abel (password recovery)
- John the Ripper (password cracker)
- Ophcrack (password cracker)
- Metasploit
- Aircrack-ng
- Burp Suite
- Netcat

**Unauthorized Programs:**
- Games (we don't allow fun)):
  - Minesweeper
  - Solitaire
  - Hearts
- P2P/Torrent software:
  - uTorrent
  - BitTorrent
  - LimeWire
  - FrostWire
- Unauthorized remote access:
  - TeamViewer
  - AnyDesk
  - VNC

#### How to Remove Software
```powershell
# Method 1: GUI
# Control Panel → Programs and Features → Uninstall

# Method 2: PowerShell
Get-WmiObject -Class Win32_Product | Select-Object Name, Version
(Get-WmiObject -Class Win32_Product -Filter "Name='<program name>'").Uninstall()

# Method 3: For Windows Store apps
Get-AppxPackage | Select-Object Name, PackageFullName
Get-AppxPackage <PackageFullName> | Remove-AppxPackage
```

#### Find and Delete Prohibited Media Files
```powershell
# Search for media files (run from C:\)
Get-ChildItem -Path C:\ -Include *.mp3,*.mp4,*.avi,*.mkv,*.flac,*.wav -Recurse -ErrorAction SilentlyContinue

# Check common locations
dir "C:\Users\*\Music" /s
dir "C:\Users\*\Videos" /s
dir "C:\Users\*\Downloads" /s
dir "C:\Users\*\Desktop" /s
```

**Instructions:**
- Delete any unauthorized media files
- Check README - sometimes specific files are allowed
- Look in Desktop, Downloads, Music, Videos, and Documents folders

---

### 6 Windows Defender/Antivirus

#### Enable and Update Windows Defender
```powershell
# Enable real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Update definitions
Update-MpSignature

# Run full scan
Start-MpScan -ScanType FullScan
```

**GUI Method:**
1. Windows Security → Virus & threat protection
2. Click "Check for updates" under Virus & threat protection updates
3. Click "Scan options" → Full scan → Scan now

**Instructions:**
- Ensure Windows Defender is enabled
- Update virus definitions
- Run a full system scan

#### Remove Other Antivirus (If Present)
- Windows Defender is good
- Multiple antivirus programs can conflict
- Remove Norton, McAfee, AVG, they are evil and vampires and they steal and evil
---


### 7 Service Management

#### Disable Unnecessary Services
```powershell
# View all services
services.msc

# Or via PowerShell
Get-Service | Select-Object Name, DisplayName, Status, StartType
```

**Services to Commonly Disable (unless required by README):**

| Service Name | Display Name | Why Disable |
|-------------|--------------|-------------|
| RemoteRegistry | Remote Registry | Allows remote registry access |
| RemoteAccess | Routing and Remote Access | Remote access vulnerability |
| TlntSvr | Telnet | Unencrypted remote access |
| FTPSVC | FTP Publishing Service | Insecure file transfer |
| SNMP | SNMP Service | Can leak system information |
| W3SVC | World Wide Web Publishing | Web server (disable if not needed) |
| SSDPSRV | SSDP Discovery | UPnP vulnerability |

```powershell
# Disable a service
Stop-Service -Name "<ServiceName>" -Force
Set-Service -Name "<ServiceName>" -StartupType Disabled

# Example: Disable Telnet
Stop-Service -Name "TlntSvr" -Force
Set-Service -Name "TlntSvr" -StartupType Disabled
```

- Always check README for required services
- Don't disable: Windows Update, Windows Defender, DNS Client, DHCP Client, Workstation

#### Secure Remote Desktop (Skip to disable if it isn't required)
If README says Remote Desktop should be enabled:

1. System Properties → Remote tab
2. Enable "Allow remote connections to this computer"
3. **Check** "Require Network Level Authentication" (more secure)
4. Click "Select Users" → only add authorized users

```powershell
# Enable RDP with NLA via PowerShell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1

# Enable firewall rule for RDP
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

If README says Remote Desktop should be disabled or doesn't mention it as essential:
```powershell
# Disable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

---

### 8 Local Security Policy Settings

Open `secpol.msc` and configure these settings:

#### Security Options
Navigate to **Local Policies → Security Options**:

| Policy | Setting |
|--------|---------|
| Accounts: Administrator account status | **Disabled** (if not needed) |
| Accounts: Guest account status | **Disabled** |
| Accounts: Rename administrator account | Change to something non-obvious (e.g., "MainAdmin") |
| Accounts: Rename guest account | Change to something non-obvious (e.g., "RandomGuest") |
| Interactive logon: Do not display last user name | **Enabled** |
| Interactive logon: Machine inactivity limit | 900 seconds (15 min) |
| Microsoft network server: Digitally sign communications (always) | **Enabled** |
| Network access: Do not allow anonymous enumeration of SAM accounts | **Enabled** |
| Network access: Do not allow anonymous enumeration of SAM accounts and shares | **Enabled** |
| Network security: Do not store LAN Manager hash value on next password change | **Enabled** |
| Network security: LAN Manager authentication level | Send NTLMv2 response only. Refuse LM & NTLM |
| Shutdown: Allow system to be shut down without having to log on | **Disabled** |

#### User Rights Assignment
Navigate to **Local Policies → User Rights Assignment**:

| Policy | Recommended Users/Groups |
|--------|-------------------------|
| Access this computer from the network | Remove "Everyone", add only specific users |
| Allow log on locally | Administrators, Users (remove Guest) |
| Allow log on through Remote Desktop Services | Only authorized RDP users |
| Deny access to this computer from the network | Guest |
| Deny log on locally | Guest |


---

### 9 Audit Policies

Enable auditing to track security events:

In `secpol.msc`, navigate to **Local Policies → Audit Policy**:

| Policy | Setting |
|--------|---------|
| Audit account logon events | Success, Failure |
| Audit account management | Success, Failure |
| Audit directory service access | No Auditing (unless DC) |
| Audit logon events | Success, Failure |
| Audit object access | Failure |
| Audit policy change | Success, Failure |
| Audit privilege use | Failure |
| Audit process tracking | No Auditing |
| Audit system events | Success, Failure |

---

### 10 Browser Security

#### Internet Explorer / Edge Settings
1. Open Internet Options (Control Panel → Internet Options)
2. **Security tab:**
   - Internet zone: High
   - Trusted sites: Remove unnecessary sites
   - Restricted sites: Add any suspicious domains
3. **Privacy tab:**
   - Set to High
   - Enable "Turn on Pop-up Blocker"
   - Advanced → Accept only first-party cookies
4. **Advanced tab:**
   - Enable "Use TLS 1.2" and "Use TLS 1.3"
   - Disable "Enable third-party browser extensions"

#### Remove Suspicious Browser Extensions
**Edge:**
1. edge://extensions/
2. Remove any suspicious or unauthorized extensions

**Chrome:**
1. chrome://extensions/
2. Remove unauthorized extensions

**Common malicious extensions:**
- Unexpected toolbars
- "Download managers"
- "Video downloaders"
- Extensions you didn't install

---


### 11 Additional Security Features

#### Disable AutoRun/AutoPlay
Prevents automatic execution of programs from USB/CD:

```powershell
# Via Registry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

# Verify
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun
```

**GUI Method:**
1. Control Panel → AutoPlay
2. Uncheck "Use AutoPlay for all media and devices"

#### Configure User Account Control (UAC)
```powershell
# Check current UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
```

**GUI Method:**
1. Control Panel → User Accounts → Change User Account Control settings
2. Set to "Always notify" (highest level)

**What UAC does:**
- Prompts for admin permission before making system changes
- Helps prevent malware from making unauthorized changes

#### Enable Secure Screen Saver
1. Control Panel → Personalization → Lock screen → Screen saver settings
2. Set wait time: 10-15 minutes
3. **Check** "On resume, display logon screen"
4. **Note**: Windows 10/11 use lock screen timeout instead

**Windows 10/11 Lock Screen:**
1. Settings → Accounts → Sign-in options
2. Set "Require sign-in" to "When PC wakes up from sleep"
3. Settings → System → Power & sleep
4. Set screen timeout to 10-15 minutes

---

### 12 Check for Malicious Configurations

#### Review Scheduled Tasks
```powershell
# Open Task Scheduler
taskschd.msc

# Or via PowerShell
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName, TaskPath, State
```

**Look for:**
- Tasks that run suspicious executables
- Tasks that run from Temp folders
- Tasks from unknown sources
- Tasks that run at logon or startup

**Delete suspicious tasks:**
1. Right-click task → Delete
2. Or via PowerShell: `Unregister-ScheduledTask -TaskName "<name>" -Confirm:$false`

#### Check Startup Programs
```powershell
# Method 1: msconfig
msconfig → Startup tab

# Method 2: Task Manager
Ctrl + Shift + Esc → Startup tab

# Method 3: PowerShell (requires admin)
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
```

**Disable suspicious startup items:**
- Unknown programs
- Programs from Temp folders
- Anything related to prohibited software

#### Inspect Hosts File
```powershell
# Open hosts file
notepad C:\Windows\System32\drivers\etc\hosts
```

**What to look for:**
- Should only contain localhost entries:
  ```
  127.0.0.1 localhost
  ::1 localhost
  ```
- **Remove** any other entries (especially redirecting legitimate sites to malicious IPs)

#### Check for Rogue Shares
```powershell
# List all shares
net share

# Remove unnecessary shares
net share <sharename> /delete
```

**Default shares (usually okay):**
- C$ - Administrative share
- ADMIN$ - Remote admin
- IPC$ - Inter-process communication

**Remove any non-standard shares** unless required by README

---

### 13 File System Security

#### Set Proper File Permissions
Check critical folders have correct permissions:

**User Home Directories:**
- Right-click folder → Properties → Security
- Users should only access their own home directory
- Remove "Everyone" and "Users" groups if present

**System Directories:**
- `C:\Windows` - Only SYSTEM and Administrators should have modify rights
- `C:\Program Files` - Only Administrators should have modify rights

**VERY RISKY**: Changing system folder permissions can break Windows!

#### Find Files with Unusual Permissions
```powershell
# Find world-writable files in Program Files (PowerShell)
Get-ChildItem "C:\Program Files" -Recurse | Get-Acl | Where-Object {$_.Access | Where-Object {$_.IdentityReference -eq "Everyone" -and $_.FileSystemRights -match "Write"}}
```

**This is the point of: "probably go help with linux or packet tracer"**

#### Enable BitLocker (If Available)
Only if README mentions encryption:

1. Control Panel → BitLocker Drive Encryption
2. Turn on BitLocker for C: drive
3. Save recovery key securely
4. **RISKY**: Takes long time, could cause issues
5. (Bitlocker can be mean, maybe just go help with linux)

---

### 14 Additional Hardening

#### Disable SMBv1 Protocol
SMBv1 is vulnerable to WannaCry and other attacks:

```powershell
# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Verify it's disabled
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

#### Configure Windows Features
```powershell
# Open Windows Features
OptionalFeatures.exe
```

**Disable these if not needed:**
- ☐ SMB 1.0/CIFS File Sharing Support
- ☐ Telnet Client
- ☐ TFTP Client
- ☐ Simple TCPIP Services

**Enable these for security:**
- Windows Defender (should already be on)

#### Registry Security Checks
**Be careful doing this**

**Disable LM Hash Storage:**
```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f
```

**Disable LLMNR (Link-Local Multicast Name Resolution):**
```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
```

---


**KEY TERMS**

Powershell: a terminal like enviornment, its a program you can run

GUI: graphical user interface, the settings pane and everything you can understand without the text

