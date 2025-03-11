$services = @("wampapache64", "wampmysqld64")
foreach ($service in $services) {
    if ((Get-Service $service).Status -ne 'Running') {
        Start-Service $service
        Write-Host "🚀 Restarted $service"
    }
}
🔑 STEP 1: CHANGE PASSWORDS & REMOVE UNNECESSARY ACCOUNTS
🔹 Attackers will try default credentials. Fix this ASAP!

1️⃣ Rename & Change Administrator Password
powershell
Copy
Edit
Rename-LocalUser -Name "Administrator" -NewName "ServerAdmin"
Set-LocalUser -Name "ServerAdmin" -Password (ConvertTo-SecureString "SuperStrongPassword123!" -AsPlainText -Force)
2️⃣ Remove Guest & Other Default Accounts
powershell
Copy
Edit
Remove-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
Remove-LocalUser -Name "DefaultAccount" -ErrorAction SilentlyContinue
3️⃣ Check for Suspicious Users & Remove Them
powershell
Copy
Edit
Get-LocalUser
Remove-LocalUser -Name "Hacker" -ErrorAction SilentlyContinue
4️⃣ Force Log Off All Other Users
powershell
Copy
Edit
query session
logoff 2  # Replace '2' with unwanted user session ID
✅ This kicks out any attackers who got in!

🔒 STEP 2: SECURE IIS & WEBSITE FILES
Attackers will try to modify website files. Prevent this!

1️⃣ Disable Directory Browsing (Prevents File Snooping)
powershell
Copy
Edit
Import-Module WebAdministration
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/directoryBrowse' -name enabled -value false
2️⃣ Restrict IIS File Permissions
powershell
Copy
Edit
icacls "C:\inetpub\wwwroot" /inheritance:r /grant IIS_IUSRS:(RX)
icacls "C:\inetpub\wwwroot" /remove Everyone
3️⃣ Disable WebDAV & FTP (Common Exploits)
powershell
Copy
Edit
Uninstall-WindowsFeature -Name Web-Ftp-Server -ErrorAction SilentlyContinue
Uninstall-WindowsFeature -Name Web-WebDAV-Publishing -ErrorAction SilentlyContinue
4️⃣ Remove Unused IIS Modules
powershell
Copy
Edit
Remove-WebFeature -Name Web-DAV-Publishing
Remove-WebFeature -Name Web-Ftp-Server
✅ These steps prevent file modifications & directory exploits.

🛡 STEP 3: FIREWALL – BLOCK UNWANTED ACCESS
Attackers will try to remotely access your system. Stop them!

1️⃣ Allow Only HTTP/HTTPS Traffic
powershell
Copy
Edit
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
New-NetFirewallRule -DisplayName "Block Everything Else" -Direction Inbound -Action Block
2️⃣ Block RDP (If Not Needed)
powershell
Copy
Edit
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
3️⃣ Block SMB (Prevents EternalBlue Exploit)
powershell
Copy
Edit
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
✅ Stops attackers from remotely accessing your system.

📡 STEP 4: MONITOR FOR ATTACKS
Catch attackers BEFORE they shut down IIS!

1️⃣ Watch for Failed Login Attempts
powershell
Copy
Edit
Get-EventLog -LogName Security -Newest 20 | Where-Object { $_.EventID -eq 4625 }
2️⃣ Monitor IIS Logs for Suspicious Requests
powershell
Copy
Edit
Get-Content "C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log" -Wait




# cyber-defense

🛑 STEP 1: REMOVE DEFAULT USERS & CHANGE PASSWORDS
Change Administrator Password & Rename It

Powershell

Rename-LocalUser -Name "Administrator" -NewName "ServerAdmin"
Set-LocalUser -Name "ServerAdmin" -Password (ConvertTo-SecureString "SuperStrongPass123!" -AsPlainText -Force)

This makes it harder for them to brute-force your admin account.
-----------------------------
-**Remove Guest & Other Default Users**

Powershell

Remove-LocalUser -Name "Guest"
Remove-LocalUser -Name "DefaultAccount"
Check for Any Suspicious Users

-----------------------------
-**Check for Any Suspicious Users**
powershell

Get-LocalUser

🚨 If you see unknown users, remove them immediately:
powershell

Remove-LocalUser -Name "SuspiciousUser"

-----------------------------
Force Log Off All Users Except You

powershell

query session
logoff 2  # Replace '2' with the session ID of unwanted users
✅ This kicks out any attackers already logged in!
-----------------------------
**🔐 STEP 2: LOCK DOWN IIS TO PREVENT FILE MODIFICATIONS**
Attackers will try to delete or modify your website files. Stop them.
Disable Directory Browsing (So They Can’t See Your Files)
Powershell

Import-Module WebAdministration
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/directoryBrowse' -name enabled -value false

✅ This prevents attackers from viewing file structures in your website.
-----------------------------
🛡 Prevent IIS File Tampering
Powershell

icacls "C:\inetpub\wwwroot" /inheritance:r /grant IIS_IUSRS:(RX)
icacls "C:\inetpub\wwwroot" /remove Everyone
✅ Only IIS can read website files – no one else can modify them.

-----------------------------

🛑 Remove Unused IIS Features (They Can Be Exploited)

powershell
CopyEdit
Uninstall-WindowsFeature -Name Web-Ftp-Server
Uninstall-WindowsFeature -Name Web-WebDAV-Publishing
✅ This removes FTP & WebDAV, which are common attack vectors.

-----------------------------

**🛑 STEP 3: FIREWALL – BLOCK COMMON ATTACK METHODS**
Attackers will try to access your system remotely. Stop them.
🚫 Allow ONLY HTTP/HTTPS Traffic

Powershell

New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
New-NetFirewallRule -DisplayName "Block Everything Else" -Direction Inbound -Action Block

✅ This keeps the website online while blocking everything else.

-----------------------------
🛑 Block Remote Desktop (If Not Needed)

powershell

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
✅ Prevents attackers from brute-forcing RDP logins.
-----------------------------
🚫 Block SMB (Prevents Exploits Like EternalBlue)

powershell

Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force

✅ Stops attackers from using SMB-based exploits.

-----------------------------

📡 STEP 4: MONITOR FOR ATTACKS IN REAL-TIME
If you can detect an attack early, you can stop it before damage is done.
👀 See Who is Logging In

powershell

Get-EventLog -LogName Security -Newest 20 | Where-Object { $_.EventID -eq 4624 -or $_.EventID -eq 4625 }

✅ Shows login attempts & failed logins (brute-force attacks).
-----------------------------
🕵️‍♂️ Watch IIS Logs for Suspicious Activity
powershell

Get-Content "C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log" -Wait
✅ Watch in real-time for hacking attempts.
-----------------------------
🔍 Find & Kill Malicious Processes
powershell

Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 10
Stop-Process -Name "SuspiciousProcess" -Force

✅ If CPU spikes, attackers might be running malware! Kill it fast.

-----------------------------

**🚀 STEP 5: AUTO-RECOVERY (IF IIS GOES DOWN)**
The Red Team will try to stop IIS. Make sure it restarts immediately.
👨‍🔧 Auto-Restart IIS If It Stops
powershell

$service = Get-Service W3SVC
if ($service.Status -ne 'Running') { Start-Service W3SVC }

✅ If attackers stop IIS, it comes back up automatically.

-----------------------------

🛠 Create a Scheduled Task to Restart IIS Every Minute

powershell

schtasks /create /tn "AutoRestartIIS" /tr "iisreset" /sc minute /ru System

✅ Even if IIS crashes, it gets restarted immediately!

💾 STEP 6: BACKUPS & RESTORATION
🔹 If attackers modify or delete files, restore them instantly.
📂 Backup Website Files

powershell

Copy-Item -Path "C:\inetpub\wwwroot" -Destination "D:\backup\wwwroot" -Recurse
✅ You can restore your website instantly if defaced.
♻️ Restore a Backup If IIS Config is Modified

powershell
CopyEdit
Copy-Item -Path "C:\inetpub\history\CFGHISTORY\*" -Destination "C:\Windows\System32\inetsrv\config\" -Recurse -Force
iisreset
✅ If attackers change IIS settings, this resets them.
![image](https://github.com/user-attachments/assets/9506a754-40f2-4625-b213-a32d96e4a649)
