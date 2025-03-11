
🛑 STEP 1: REMOVE DEFAULT USERS & CHANGE PASSWORDS
🔹 Attackers will try to log in with default credentials. Change passwords IMMEDIATELY.
👤 Change Root Password & Disable Root SSH Login

bash
CopyEdit
sudo passwd root
sudo sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
✅ Prevents root from being brute-forced over SSH.
🚫 Remove Guest & Other Default Users

bash
CopyEdit
sudo userdel -r msfadmin  # If Metasploitable default user exists
sudo userdel -r user  # Any other generic users
🕵️‍♂️ Check for Any Suspicious Users

bash
CopyEdit
cut -d: -f1 /etc/passwd
🚨 If you see unknown users, remove them immediately:

bash
CopyEdit
sudo userdel -r suspicioususer
👀 Force Log Off All Users Except You

bash
CopyEdit
w  # List logged-in users
sudo pkill -u unwanteduser  # Kill a specific user session
✅ This kicks out any attackers already logged in!

🔐 STEP 2: LOCK DOWN APACHE/NGINX TO PREVENT FILE MODIFICATIONS
Attackers will try to delete or modify your website files. Stop them.
🚫 Disable Directory Listing (Prevents File Snooping)

bash
CopyEdit
sudo sed -i 's/Options Indexes/Options -Indexes/' /etc/apache2/apache2.conf
sudo systemctl restart apache2
✅ This prevents attackers from viewing file structures in your website.
🛡 Prevent Apache/Nginx File Tampering

bash
CopyEdit
sudo chown -R root:www-data /var/www/html
sudo chmod -R 750 /var/www/html
✅ Only root & web server can access files – attackers can’t modify them.
🛑 Remove Unused Apache/Nginx Modules (They Can Be Exploited)

bash
CopyEdit
sudo a2dismod autoindex status cgi
sudo systemctl restart apache2
✅ Disables directory listing & unnecessary modules.

🛑 STEP 3: FIREWALL – BLOCK COMMON ATTACK METHODS
Attackers will try to access your system remotely. Stop them.
🚫 Allow ONLY HTTP/HTTPS Traffic

bash
CopyEdit
sudo ufw default deny incoming
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
✅ This keeps the website online while blocking everything else.
🛑 Block Remote SSH (If Not Needed)

bash
CopyEdit
sudo ufw deny 22/tcp
✅ Prevents attackers from brute-forcing SSH logins.
🚫 Disable Unused Services

bash
CopyEdit
sudo systemctl stop ftp
sudo systemctl disable ftp
✅ Blocks FTP access if you’re not using it.

📡 STEP 4: MONITOR FOR ATTACKS IN REAL-TIME
If you can detect an attack early, you can stop it before damage is done.
👀 See Who is Logging In

bash
CopyEdit
sudo last -a | head -10
✅ Shows login attempts (watch for suspicious logins).
🕵️‍♂️ Watch Apache/Nginx Logs for Suspicious Activity

bash
CopyEdit
sudo tail -f /var/log/apache2/access.log
sudo tail -f /var/log/nginx/access.log
✅ Watch in real-time for hacking attempts.
🔍 Find & Kill Malicious Processes

bash
CopyEdit
ps aux --sort=-%cpu | head -10
sudo kill -9 <PID>
✅ If CPU spikes, attackers might be running malware! Kill it fast.

🚀 STEP 5: AUTO-RECOVERY (IF APACHE/NGINX GOES DOWN)
The Red Team will try to stop Apache/Nginx. Make sure it restarts immediately.
👨‍🔧 Auto-Restart Apache/Nginx If It Stops

bash
CopyEdit
while true; do
    if ! pgrep apache2 > /dev/null; then
        echo "🚨 ALERT! Apache was stopped! Restarting..."
        sudo systemctl restart apache2
    fi
    sleep 10
done
✅ If attackers stop Apache, it comes back up automatically.
🛠 Create a Cron Job to Restart Apache Every Minute

bash
CopyEdit
echo '* * * * * root pgrep apache2 || systemctl restart apache2' | sudo tee -a /etc/crontab
✅ Even if Apache crashes, it gets restarted immediately!

💾 STEP 6: BACKUPS & RESTORATION
🔹 If attackers modify or delete files, restore them instantly.
📂 Backup Website Files

bash
CopyEdit
sudo cp -r /var/www/html /var/www/html_backup
✅ You can restore your website instantly if defaced.
♻️ Restore a Backup If Apache/Nginx Config is Modified

bash
CopyEdit
sudo cp /etc/apache2/apache2.conf.bak /etc/apache2/apache2.conf
sudo systemctl restart apache2
![image](https://github.com/user-attachments/assets/b48dc21c-ca1e-48e1-a87d-5dd6e8777989)
