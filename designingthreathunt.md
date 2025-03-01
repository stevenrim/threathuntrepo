(Disclaimer: This article presents a fictional threat hunting scenario created for educational and portfolio purposes. Any similarities to real individuals, organizations, or events are purely coincidental. The investigation techniques, queries, and methodologies demonstrated are based on real-world cybersecurity practices but are applied in a simulated environment. This content is intended to showcase threat hunting skills, analytical thinking, and investigative processes for professional development. It does not reflect or promote any actual security incidents or breaches.)

# Designing the Threat Hunt Scenario (Unauthorized TOR Usage)
## Unauthorized TOR Browser Installation and Use
Sam, a mid-level employee in the finance department, was growing increasingly frustrated with the company's strict internet usage policies. He felt that his personal browsing and online interests were being overly restricted and after some research, he came across TOR, a privacy tool that promised to mask his internet traffic and give him the anonymity he desired. Also, the IT team didn't deprovision his workstation from the previous employee/user (stevenmde). Did they not even care or were they being incompetent? Regardless, Sam felt that his actions would go undetected and decided to install the TOR browser during a quiet evening shift.

## Steps to take as a "bad actor" to create logs and IoCs:
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```.\tor-browser-windows-x86_64-portable-14.0.6.exe /S```
3. Open the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites: Google.com, Yahoo.com, and Reddit.com
6. Create a file on the desktop called ```tor-shopping-list.txt``` and make a shopping list for the darkweb. 
7. Delete the file.

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|


## Related Queries:
```kql
// Detect TOR installer download
DeviceFileEvents
| where DeviceName == "xxxx"
| where FileName startswith "tor"

//Detect silent download of TOR 
DeviceProcessEvents
| where DeviceName == "xxxx"
| where FileName == "tor-browser-windows-x86_64-portable-xxxxxx.exe"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

//Detect silent download of TOR
DeviceFileEvents
| where DeviceName == "xxxx"
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// TOR Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service being used and is actively creating network connections
DeviceNetworkEvents
| where DeviceName == "xxxx"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where DeviceName == "xxxx"
| where FileName contains "tor-shopping-list.txt"
```


## Created By:
- **Author Name**: Steven 
- **Author Contact**: https://www.linkedin.com/in/stevenrim
- **Date**: March 1, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 



## Additional Notes:
- [Threat Hunt Report: Unauthorized Download, Installation, and Use of TOR](https://github.com/stevenrim/threathuntrepo/blob/main/threathunt.md)



## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March  1, 2025`  | `Steven Rim`   
