# Guided Threat Hunt Lab Writeup :telescope:
# "HTB Intrusion Detection With Splunk (Real-world Scenario)"

### Main Goal and Takeaway's

The goal of this lab was to practice detecting and analyzing malicious activity using **Splunk** and **Sysmon** logs. 
Key points include:

1. **Analyzing Sysmon Data**: We identified suspicious process behaviors, like **notepad.exe** spawning **PowerShell**, indicative of attack techniques.
   
2. **Identifying Indicators of Compromise**: We focused on signs of **DCSync attacks**, **LSASS dumps**, and abnormal network activity to trace malicious actions.

3. **Cross-Platform Attacks**: We explored how a **Linux VM** could be used as a pivot point for transferring malicious tools into a Windows environment.

4. **Building Detection Queries**: We crafted **SPL queries** to spot unusual processes and behaviors, enhancing detection capabilities.

5. **Incident Response Skills**: The lab emphasized tracking an attack across multiple hosts and crafting alerts to prevent future incidents.


## Setup

- **Kali Linux** (Personal Machine)
- **Splunk Host**
- **Enterprise Dataset**: 500k+ logs, consisting of various threats and log sources

---

## 1. Familiarizing Ourselves with the Dataset

We start by exploring the dataset and the sources available to us.

```spl
index="main" | stats count by sourcetype
```

From this query, we can see that we have the following sourcetypes:

- **WinEventLog**
- **Application**
- **Security**
- **Sysmon**
- **Linux:Auth**
- **Linux:Syslog**

For this hunt, we will focus on **Sysmon** data.

```spl
index="main" sourcetype="WinEventLog:Sysmon"
```

---

## 2. Initial Queries for Familiarization

To get more comfortable with our environment, we run a few more SPL queries:

1. **Search for logs related to `uniwaldo.local`:**

```spl
index="main" uniwaldo.local
```

2. **Filter by `ComputerName`:**

```spl
index="main" ComputerName="*uniwaldo.local"
```

---

## 3. Exploring Sysmon Event Codes

Next, we begin investigating Sysmon Event Codes to identify any significant patterns.

### Query: List all Sysmon Event Codes by count

```spl
index="main" sourcetype="WinEventLog:Sysmon" | stats count by EventCode
```

### Overview of Relevant Sysmon Event IDs:

- **[Event ID 1 - Process Creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)**: Useful for hunting abnormal parent-child process hierarchies (e.g., notepad spawning PowerShell).
- **[Event ID 2 - Process File Time Change](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90002)**: Detects time-stomping attacks.
- **[Event ID 3 - Network Connection](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90003)**: Can uncover network anomalies.
- **[Event ID 4 - Sysmon Service State Change](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90004)**: Detects Sysmon service stops, potentially malicious.
- **[Event ID 5 - Process Terminated](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90005)**: Helps identify when malicious processes are terminated.
- **[Event ID 7 - Image Loaded](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90007)**: Detects DLL hijacks.
- **[Event ID 8 - CreateRemoteThread](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90008)**: Useful for identifying injected threads.
- **[Event ID 10 - Process Access](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90010)**: Tracks remote code injection and memory dumping.

We will focus on **Event ID 1** (Process Creation), as this often provides useful insight into process execution anomalies.

---

## 4. Searching for Suspicious Processes

### 4.1. Target Search: CMD and PowerShell Process Creation

We start by searching for the creation of **cmd.exe** and **powershell.exe**.

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") | stats count by ParentImage, Image
```

We identify a suspicious log where **notepad.exe** is spawning a **PowerShell** session. This is unusual and could indicate a malicious actor leveraging legitimate tools.

### 4.2. Investigating Notepad Executing PowerShell

To follow the trail, we use the following query:

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") ParentImage="C:\\Windows\\System32\\notepad.exe"
```

![image](https://github.com/user-attachments/assets/de3f86a0-065c-4494-8d17-ec525395b570)


Upon inspecting the results, we see **notepad.exe** calling **PowerShell** to download a file from the IP `10.0.0.229`. This is a clear red flag.

---

## 5. Investigating the IP Address `10.0.0.229`

### 5.1. Searching for Logs Containing `10.0.0.229`

We investigate the logs for **10.0.0.229** to understand its role in this attack.

```spl
index="main" 10.0.0.229 | stats count by sourcetype
```

### 5.2. Identifying the IP’s Role

It turns out **10.0.0.229** is a **Linux VM**.

```spl
index="main" 10.0.0.229 sourcetype="linux:syslog"
```

We now see that the Linux system is being used to transfer tools.

---

## 6. Identifying Compromised Hosts

### 6.1. Finding Hosts Linked to IP `10.0.0.229`

To find the hosts interacting with this IP, we run:

```spl
index="main" 10.0.0.229 sourcetype="WinEventLog:sysmon" | stats count by CommandLine, host
```
![image](https://github.com/user-attachments/assets/a5d887b6-7664-4947-a743-cecfd933cdaf)

We find that two hosts are involved. One of them shows activity consistent with a **DCSync** attack, where PowerShell scripts were executed to simulate **DCSync** behavior.

---

## 7. Investigating the DCSync Attack

We refine our search to target **Event Code 4662**, which corresponds to access of Active Directory objects, specifically looking for **DCSync** indicators.

```spl
index="main" EventCode=4662 Access_Mask=0x100 Account_Name!=*$
```
![image](https://github.com/user-attachments/assets/14d04b78-807c-40f7-800c-fa238590ff7f)


By inspecting the GUIDs in these logs, we confirm that they correspond to **Control Access** and **DS-Replication**, which are related to DCSync attacks. This indicates that **Waldo** (the user) performed a **DCSync** attack on the domain.

---

## 8. Investigating the LSASS Dump

To understand how this attack was carried out, we investigate potential **LSASS dumps**, which may have allowed the attacker to escalate permissions.

### 8.1. Searching for LSASS Dumps

```spl
index="main" EventCode=10 lsass | stats count by SourceImage
```
![image](https://github.com/user-attachments/assets/84da7a5f-c67f-41cf-a742-5125476a93c0)

We find that **notepad.exe** is associated with the LSASS dump, suggesting that it was involved in memory dumping.

```spl
index="main" EventCode=10 lsass SourceImage="C:\\Windows\\System32\\notepad.exe"
```
![image](https://github.com/user-attachments/assets/64f66d35-17cc-475d-bc38-824a763994b4)


This is a clear indication that the LSASS dump was executed via **notepad.exe**.

---

## 9. Crafting an Alert

With all the data we've gathered, we can now craft an alert to detect similar attacks in the future.

---

## 10. Unguided Assessment Tasks

### 10.1. Finding the Process that Dumped LSASS

```spl
index="main" EventCode=10 lsass | stats count by SourceImage
```

### 10.2. Identifying the DLL Used to Dump LSASS

```spl
index="main" EventCode=10 TargetImage="*\\lsass.exe" | stats count by SourceImage, CallTrace | search SourceImage="*\\rundll32.exe" | rex field=CallTrace "(?i)(?P<DLLs>[^,]*\.dll)" | stats count by DLLs | sort -count | table DLLs
```

### 10.3. Finding Suspicious `clr.dll` Loads for C# Injection

```spl
index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* | where SourceImage!=TargetImage | stats count by SourceImage
```

### 10.4. Finding the C2 Callback IPs

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 Image="C:\\Windows\\system32\\notepad.exe" DestinationIp="*" | rex field=DestinationIp "10\\.0\\.0\\.(?<octet>\\d{1,3})" | search (octet>=0 AND octet<=99) OR (octet>=100 AND octet<=199) | stats values(DestinationIp) as destination_ips
```

### 10.5. Identifying the Port Used for C2 Communication

```spl
index="main" EventCode=3 (SourceIp="10.0.0.186" OR SourceIp="10.0.0.91") DestinationPort="*" | stats values(DestinationPort) as destination_ports
```

---

By completing this simulation, we strengthened our ability to detect advanced persistent threats (APTs), analyze system logs, and respond effectively to intrusions in an enterprise network.
