# FalconFlank
Crowdstrike Falcon 0day Privilege Escalation Vulnerability

FalconFlank is a 0day privilege escalation that abuses the office malicious macros remediation in Crowdstrike Falcon Sensor, obviously by the time I drop this Crowdstrike would already have detections for it so if you want to test you either have to add it to the exclusions or obfuscate the PoC and change the dll load technique.
As of now it works in a fully updated windows 11 25H2 / Windows Server 2025 with Crowdstrike Falcon - Phase 3 Optimal Protection + needs "Microsoft Office file malicious macro removal"
<img width="1125" height="910" alt="Screenshot 2026-09-02 195701" src="https://github.com/user-attachments/assets/41c7dbb2-f48c-447e-a9c3-12d0bbc2db92" />
