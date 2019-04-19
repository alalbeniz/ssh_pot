# ssh_pot


ln -s /usr/bin/krb5-config.mit /usr/bin/krb5-config                                     <br />
ln -s /usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2 /usr/lib/libgssapi_krb5.so          <br />
apt-get install python-pip libkrb5-dev virtualenv python3-dev sqlite3                   <br />

virtualenv -p python3 ssh_pot                                                           <br />
cd ssh_pot                                                                              <br />
source bin/activate                                                                     <br />

pip install paramiko peewee python-gssapi                                               <br />

-----------------------------------------------------------------------------------
/lib/systemd/system/ssh_pot.service                                                     <br />

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
touch /var/log/SSHPotServer.log                                                          <br />
vim /etc/rsyslog.d/ssh_pot.conf                                                          <br />

if $programname == 'SSHPotServer' then /var/log/SSHPotServer.log #the file exists        <br />
if $programname == 'SSHPotServer' then stop                                              <br />

------------------------------------------------------------------------------------
vim /etc/logrotate.d/ssh_pot                                                             <br />

/var/log/SSHPotServer.log {
        daily
        rotate 36
        compress
        delaycompress
        missingok
        notifempty
        create 644 syslog adm
}
