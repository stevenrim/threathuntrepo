(Disclaimer: This article presents a fictional threat hunting scenario created for educational and portfolio purposes. Any similarities to real individuals, organizations, or events are purely coincidental. The investigation techniques, queries, and methodologies demonstrated are based on real-world cybersecurity practices but are applied in a simulated environment. This content is intended to showcase threat hunting skills, analytical thinking, and investigative processes for professional development. It does not reflect or promote any actual security incidents or breaches.)

# Threat Hunt Report: Unauthorized Download, Installation, and Use of TOR
## Platforms Used
- EDR: Microsoft Defender for Endpoint
- Query Language: KQL (Kusto Query Language)
- Windows VM on Azure
## Scenario
An alert was triggered in the security monitoring system regarding unusual network activity originating from an internal workstation in the finance department. The workstation "stevenmde", assigned to Sam who is a mid-level employee, exhibited encrypted traffic patterns that indicated connections to known TOR exit nodes. This behavior raised red flags, as the use of TOR and similar privacy tools were strictly prohibited within the organization.

To address these concerns, I was tasked to investigate Sam's workstation for any signs of unusual activity.

## Step 1
1.0 Known Information
- TOR file was downloaded
- Workstation is "stevenmde"

1.1 Objective 
- Start initial KQL Query to pull all relevant logs on "stevenmde".

1.2 KQL Query
```kql
DeviceFileEvents
| where DeviceName == "stevenmde"
| where FileName startswith "tor"
```
1.3 Query Results
<br>
The following screenshot shows that the tor installer file (tor-browser-windows-x86_64-portable-14.0.6.exe) was downloaded into the downloads folder on "stevemde" and moved to the desktop.
<a href="https://github.com/stevenrim/threathuntrepo/blob/main/step1.png"><img src="https://github.com/stevenrim/threathuntrepo/blob/main/step1.png"/>

## Step 2
2.0 Known Information
- TOR installer file name

2.1 Objective 
- Investigate Process Command Line

2.2 KQL Query
```kql
DeviceProcessEvents
| where DeviceName == "stevenmde"
| where FileName == "tor-browser-windows-x86_64-portable-14.0.6.exe"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
2.3 Query Results
The following screenshot shows the process was created or TOR was installed silently, indicated by the ProcessCommandLine "/S" function.
<a href="https://github.com/stevenrim/threathuntrepo/blob/main/step2.png"><img src="https://github.com/stevenrim/threathuntrepo/blob/main/step2.png"/>

