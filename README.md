# ssh_pot


ln -s /usr/bin/krb5-config.mit /usr/bin/krb5-config
ln -s /usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2 /usr/lib/libgssapi_krb5.so
apt-get install python-pip libkrb5-dev virtualenv python3-dev sqlite3

virtualenv -p python3 ssh_pot
cd ssh_pot
source bin/activate

pip install paramiko peewee python-gssapi

-----------------------------------------------------------------------------------
/lib/systemd/system/ssh_pot.service

[Unit]
Description=SSH server in port 22

[Service]
ExecStart=%FOLDER_PATH%/ssh_client/bin/python %FOLDER_PATH%/ssh_client/src/ssh_server.py
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=SSHPotServer
#Restart=on-failure
Restart=always

[Install]
WantedBy=multi-user.target


------------------------------------------------------------------------------------
touch /var/log/SSHPotServer.log
vim /etc/rsyslog.d/ssh_pot.conf

if $programname == 'SSHPotServer' then /var/log/SSHPotServer.log #the file exists
if $programname == 'SSHPotServer' then stop

------------------------------------------------------------------------------------
vim /etc/logrotate.d/ssh_pot

/var/log/SSHPotServer.log {
        daily
        rotate 36
        compress
        delaycompress
        missingok
        notifempty
        create 644 syslog adm
}
