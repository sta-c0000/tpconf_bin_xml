## Running sshd on the TP-Link TD-W9970 modem router

The official OpenSSH server (sshd deamon) can be made to work on the TP-Link modem router.  It consumes more RAM than dropbear, however it is the standard and can provide chrooted sftp.

You can create a host key for the router on your PC (do not use passphrase for host keys!):
```sh
ssh-keygen -t ed25519 -f openssh_ed25519_host_key   # or any key type you want
```

In your startup script on the USB drive (typically mounted at */var/usbdisk/sda1*) you will also need to add (assuming you have those directories and files on the USB drive):
```sh
# copy sshd host key with correct permissions (empty dir for privilege separation user)
mkdir /var/ssh /var/empty
cp /var/usbdisk/sda1/ssh/openssh_ed25519_host_key /var/ssh/openssh_ed25519_host_key
chmod 400 /var/ssh/openssh_ed25519_host_key
# Start sshd
/var/usbdisk/sda1/bin/sshd -f /var/usbdisk/sda1/ssh/sshd_config -E /var/usbdisk/sda1/log/sshd.log
```
In this case, *sshd_config* file would contain ```HostKey /var/ssh/openssh_ed25519_host_key```.
(Also possible to launch sshd from busybox's inetd using the -i parameter)

To enable admin (root) logins using keys, you can use the following line in your *sshd_config* file (use *no* if you only want chrooted sftp, *yes* to enable admin password logins):
```
PermitRootLogin prohibit-password
```
Copy the contents of the public keys (.pub) you want to use to login to admin (root) to ```/var/usbdisk/sda1/root/.ssh/authorized_keys``` assuming you've also updated the passwd file's admin home directory field with ```/var/usbdisk/sda1/root/```

You will need to add to your passwd file an sshd privilege separation user; and optionally an sftp user (*sftp-user* can be named whatever you want):
```
sshd:x:74:74:Privilege separation user:/var/empty:nologin
sftp-user:x:1001:1001:sftp user:/var/usbdisk/sda1/home/sftp:/bin/sh
```
For key based password-less access, simply append the contents of the public keys (*.pub) wanting access to a ```/var/usbdisk/sda1/home/sftp/.ssh/authorized_keys``` file.

If you want to enable password access for the *sftp-user*, you can simply replace the *x* (password field) with a password generated using this command on your PC:
```sh
openssl passwd -1
```
Your sshd_config should also contain (sftp chroot to the *sftp-root* directory on the USB drive):
```
# Uncomment next line to enable sftp-user password access
# PasswordAuthentication yes
StrictModes no
Subsystem sftp internal-sftp
Match User sftp-user
    ChrootDirectory /var/usbdisk/sda1/sftp-root
    ForceCommand internal-sftp
    AllowTCPForwarding no
    X11Forwarding no
```

By default the sshd server should only be visible from within the LAN.  Generally you should not enable Internet (outside) access to your sshd server, however you can enable this with *iptables* commands in your startup script.  If you do this you may want to consider changing the sshd port (because the default one *WILL* get probed) and maybe even use something like knockd to limit access to this port.
