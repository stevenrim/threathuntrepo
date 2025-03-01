(Disclaimer: This article presents a fictional threat hunting scenario created for educational and portfolio purposes. Any similarities to real individuals, organizations, or events are purely coincidental. The investigation techniques, queries, and methodologies demonstrated are based on real-world cybersecurity practices but are applied in a simulated environment. This content is intended to showcase threat hunting skills, analytical thinking, and investigative processes for professional development. It does not reflect or promote any actual security incidents or breaches.)

# Threat Hunt Report: Unauthorized Download, Installation, and Use of TOR
## Platforms Used
- EDR: Microsoft Defender for Endpoint
- Query Language: KQL (Kusto Query Language)
- Windows VM on Azure
  
## Scenario Overview
An alert was triggered in the security monitoring system regarding unusual network activity originating from an internal workstation in the finance department. The workstation "stevenmde", assigned to Sam who is a mid-level employee, exhibited encrypted traffic patterns that indicated connections to known TOR exit nodes. This behavior raised red flags, as the use of TOR and similar privacy tools were strictly prohibited within the organization.

To address these concerns, I was tasked to investigate Sam's workstation for any signs of unusual activity.

## Step 1
1.0 Known Information
- TOR file was downloaded
- Workstation is "stevenmde"

1.1 Objective 
- Start initial KQL Query to pull all relevant logs on "stevenmde" having to with any files that contain "TOR".

1.2 KQL Query
```kql
// Detect TOR installer download
DeviceFileEvents
| where DeviceName == "stevenmde"
| where FileName startswith "tor"
```
1.3 Query Results
<br>
The following screenshot shows that the tor installer file (tor-browser-windows-x86_64-portable-14.0.6.exe) was downloaded into the downloads folder on "stevemde" and moved to the desktop. Notice that a tor-shopping-list.txt file was created as well. 
<a href="https://github.com/stevenrim/threathuntrepo/blob/main/step1.png"><img src="https://github.com/stevenrim/threathuntrepo/blob/main/step1.png"/>

## Step 2
2.0 Known Information
- TOR installer file name: tor-browser-windows-x86_64-portable-14.0.6.exe

2.1 Objective 
- Investigate Process Command Line for suspicious activity.

2.2 KQL Query
```kql
//Detect silent download of TOR 
DeviceProcessEvents
| where DeviceName == "stevenmde"
| where FileName == "tor-browser-windows-x86_64-portable-14.0.6.exe"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

//Detect silent download of TOR
DeviceFileEvents
| where DeviceName == "xxxx"
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine
```
2.3 Query Results
<br>
The DeviceProcessEvents screenshot shows the process was created or TOR was installed silently, indicated by the ProcessCommandLine "/S" function.
<a href="https://github.com/stevenrim/threathuntrepo/blob/main/step2.png"><img src="https://github.com/stevenrim/threathuntrepo/blob/main/step2.png"/>

The DevicefileEvents screenshot shows additional verification that TOR exists on the machine and was installed silently.
<a href="https://github.com/stevenrim/threathuntrepo/blob/main/step2(2).png"><img src="https://github.com/stevenrim/threathuntrepo/blob/main/step2(2).png"/>


## Step 3
3.0 Known Information
- N/A

3.1 Objective 
- Confirm the TOR browser was launched and created network connections.

3.2 KQL Query
```kql
// TOR Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service being used and is actively creating network connections
DeviceNetworkEvents
| where DeviceName == "stevenmde"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
3.3 Query Results
<br>
The DeviceProcessEvents screenshot shows that the TOR browser was launched.
<a href="https://github.com/stevenrim/threathuntrepo/blob/main/step3.png"><img src="https://github.com/stevenrim/threathuntrepo/blob/main/step3.png"/>

The DeviceNetworkEvents screenshot shows the the RemoteIP addresses and RemoteUrl links. These are destinations that "stevenmde" is connecting to. Notice the url's seem to be obfuscated or could be TOR relays addresses instead of the real domain. The RemotIP addresses are supposedly in different parts of the world. It also shows the RemotePort or the type of connections that are commonly associated with TOR (9150, 9002, and 443). 
<a href="https://github.com/stevenrim/threathuntrepo/blob/main/step3(2).png"><img src="https://github.com/stevenrim/threathuntrepo/blob/main/step3(2).png"/>

## Step 4 (final)
4.0 Known Information
- From the initial KQL query, there was a file text file created with a suspicious file name titled "tor-shopping-list.txt".

4.1 Objective 
- Confirm the contents of the text file to see if it can support that Sam had motive to be on the darkweb. 

4.2 KQL Query
```kql
// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where FileName contains "tor-shopping-list.txt"

```
4.3 Query Results
<br>
Unfortunately, the analyst would not have access to the file unless the "Live Response" function was enabled on MDE by the administrator. But if the analyst did have access to that function, they could easily open up PowerShell and access the file with simple commands. However, the screeshot shows that the file was created, renamed with a suspicious title, and modified.
<a href="https://github.com/stevenrim/threathuntrepo/blob/main/step4.png"><img src="https://github.com/stevenrim/threathuntrepo/blob/main/step4.png"/>


5.0 Conclusion & Next Steps
<br>
This threat hunt aimed to detect and analyze the unauthorized download, installation, and usage of the Tor browser on an Azure Windows 10 VM. The goal was to identify indicators of compromise (IOCs) and assess the potential security risks associated with anonymized network traffic. To conduct this investigation, Microsoft Defender for Endpoint (MDE) was used to query system logs related to file creation, process execution, and network events. Specifically, DeviceFileEvents was used to track tor.exe installation and execution, while DeviceNetworkEvents helped identify outbound connections to known Tor exit nodes and suspicious remote URLs. 

The investigation revealed several key findings. tor.exe was downloaded and executed without authorization. Multiple outbound connections to Tor exit nodes were detected on ports 443, 9002, and 9150, indicating active Tor network usage. MDE logs captured obfuscated URLs rather than recognizable domain names, likely representing Tor relay addresses instead of the actual websites visited. Furthermore, tor.exe was launched multiple times, establishing encrypted connections that bypass traditional logging mechanisms, making monitoring and tracking of activity difficult.

The unauthorized use of TOR presents significant security risks. Since TOR anonymizes traffic, it allows users to evade network monitoring and potentially bypass security controls. Attackers can leverage TOR to exfiltrate sensitive data, access restricted content, or download malicious payloads, increasing the risk of data breaches and malware infections. Additionally, the ability to communicate anonymously over TOR could facilitate insider threats or unauthorized external access to sensitive systems.

To mitigate these risks, several security controls should be implemented. First, preventing TOR installation and execution is essential. This can be achieved by enforcing AppLocker or Windows Defender Application Control (WDAC) policies to block tor.exe execution. Additionally, custom MDE indicators should be created to detect and block TOR-related file activities, such as logging instances where files named tor.exe or stored in a directory containing "Tor Browser" appear in DeviceFileEvents. Next, restricting network traffic to TOR nodes is critical. Firewall rules should be configured to block known TOR exit node IPs, and network protection policies should prevent outbound traffic to TOR-related ports (9001, 9002, 9050, and 9150).

In addition to blocking mechanisms, detection and alerting should be strengthened. Custom MDE alerts should be configured to detect unauthorized processes interacting with ToR-related IPs, while SIEM rules should flag unusual encrypted traffic patterns. Furthermore, user awareness and policy enforcement must be prioritized. Security awareness training should educate users on the risks of anonymization tools and reinforce corporate policies that prohibit unauthorized software installations.

Moving forward, continuous monitoring will be essential to detect new evasion techniques and ensure ongoing security. A further investigation is needed to determine whether the TOR usage was intentional or a sign of a potential compromise. Lastly, incident response readiness should be enhanced by establishing an automated response workflow to mitigate similar threats proactively. By enforcing these security controls, organizations can effectively reduce the risks associated with unauthorized TOR usage while maintaining better visibility and control over network activities.


