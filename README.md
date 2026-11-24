# Active Directory Detection Engineering Lab

The **blue-team counterpart** to my [Active Directory Attack & Defense Lab](https://github.com/CenkSec). I take the same attack chain that compromised `adlab.local` up to Domain Admin — then switch sides, re-run it under full logging, and **hunt it in the Windows event logs** with Sigma, Hayabusa, Chainsaw, and four detection rules I wrote myself.

> **Environment & authorisation.** All testing was performed against `adlab.local`, a self-built, **deliberately vulnerable** Active Directory domain on an **isolated virtual network** (VirtualBox internal network, no internet access), with Kali Linux as the attacker/analyst host. No real systems, accounts, or data are involved. Every credential and event shown exists only inside this lab.

## 📄 Read the report

**[Active_Directory_Detection_Engineering_Lab.pdf](./Active_Directory_Detection_Engineering_Lab.pdf)** — full write-up with the detection pipeline, the four custom Sigma rules, MITRE ATT&CK mapping, tool evidence, and a root-cause analysis of a false negative (renders in your browser).

## What this project demonstrates

- Re-running a real AD attack chain (AS-REP roasting, Kerberoasting, `wmiexec` lateral movement, Domain Admins escalation) under **Windows Security auditing + Sysmon**
- Exporting `.evtx` logs and hunting them with **Hayabusa** and **Chainsaw** (Sigma-based engines)
- Authoring **four custom Sigma detection rules** — one per attack stage — targeting the single most reliable indicator of each technique
- **Validating** rules against real event data, including diagnosing and documenting a **false negative** (field-mapping mismatch) — the honest core of detection engineering
- Mapping every detection to **MITRE ATT&CK** and pairing it with a preventive control

## The detection pipeline

```
Re-run attack  →  Windows Security + Sysmon logs  →  Export .evtx  →  Baseline (Hayabusa)  →  Author 4 Sigma rules  →  Test (Chainsaw)
```

Baseline scan result: **6,174 events reduced to the 17 that mattered** (99.7% reduction), with the stock rule set independently flagging the AS-REP roasting, Kerberoasting, and Domain Admins changes.

## The custom Sigma rules

| Rule | Technique | ATT&CK | Event | Key indicator | Result |
|---|---|---|---|---|---|
| `kerberoasting-rc4` | Kerberoasting | T1558.003 | 4769 | Encryption type `0x17` (RC4), excluding machine accounts | ✅ Fired |
| `wmiexec-lateral` | WMI lateral movement | T1047 / T1021.006 | Sysmon 1 | `WmiPrvSE.exe` spawning `cmd.exe` / `powershell.exe` | ✅ Fired |
| `domain-admins-change` | Account Manipulation | T1098 | 4728 | Member added to `Domain Admins` | ✅ Fired |
| `asrep-roasting` | AS-REP roasting | T1558.004 | 4768 | Pre-authentication type `0` | ⚠️ Documented false negative |

Testing with Chainsaw produced **17 detections** across the three logs. The AS-REP rule did not fire despite the attack being present — traced to a field-mapping mismatch between the rule and the EVTX schema, and documented with its tuning path. That false negative is the most instructive result in the project.

## Tools

Sigma · Hayabusa · Chainsaw · Sysmon · Windows Event Logs (4768 / 4769 / 4728 / 4624) · MITRE ATT&CK · Kali Linux

## What I'd do next

- Tune and re-test the AS-REP rule to a firing state
- Convert the four rules to a SIEM backend (Splunk / Microsoft Sentinel) to demonstrate Sigma portability
- Extend coverage to a technique with no single obvious event — such as **DCSync** — where detection depends on correlating 4662 directory-access events
