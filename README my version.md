# windows-dfir-lab64-accessibility-features-persistence-investigation
## Overview
Windows provides accessibility programs such as:

utilman.exe — Utility Manager
sethc.exe — Sticky Keys
osk.exe — On-Screen Keyboard
magnify.exe — Magnifier
narrator.exe — Narrator

These are legitimate Windows components.

The security concern arises when an attacker modifies the configuration associated with one of these components so that a different program is launched instead.

Conceptually:

Normal:

Logon Screen
     ↓
Accessibility Feature
     ↓
Legitimate Windows Program

A persistence attempt may look like:

Logon Screen
     ↓
Accessibility Feature
     ↓
Modified Configuration
     ↓
Attacker-Controlled Program

This can provide execution in a privileged context or before a normal user session is established, depending on the technique and Windows configuration.

The important DFIR question is:

Has an accessibility-related configuration been altered from its expected Windows state?

One of the most important areas to investigate is:

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options

Attackers can abuse Image File Execution Options (IFEO) by creating a subkey for a legitimate Windows executable and configuring a debugger or other value that changes how that executable is launched.

For example:

Image File Execution Options
        ↓
utilman.exe
        ↓
Suspicious Debugger Value
        ↓
Unexpected Executable

This is why this investigation is closely related to both persistence and Registry modification.

An analyst should compare the expected state against the observed state.

For example:

Expected:
utilman.exe
    ↓
No unexpected IFEO configuration

versus:

Observed:
utilman.exe
    ↓
IFEO entry exists
    ↓
Debugger = unexpected executable

The second situation deserves investigation.

But again:

An IFEO key by itself does not automatically prove malicious persistence.

Legitimate software can sometimes use IFEO for debugging or compatibility purposes.


This lab investigates Windows accessibility features from a DFIR and persistence-detection perspective.

Accessibility executables such as `utilman.exe`, `sethc.exe`, `osk.exe`, `magnify.exe`, and `narrator.exe` are legitimate Windows components. The security concern arises when an attacker modifies the execution path or Registry configuration associated with one of these binaries so that an unexpected program is launched.

The investigation therefore focuses on identifying configuration changes around accessibility executables, particularly through Image File Execution Options (IFEO), while preserving the real Windows binaries and avoiding the creation of an actual logon bypass.

A safe lab-only Registry key was created under:

`HKLM:\SOFTWARE\Lab64-AccessibilityPersistence`

A simulated debugger value pointing to `C:\Lab64\simulated-payload.exe` was added to demonstrate how persistence evidence could appear during an investigation. The lab-only key was subsequently removed.

The actual accessibility executables were not modified.

## Investigation Objectives

Verify that Windows accessibility executables are present in their expected system location.
Establish a baseline for the integrity and authenticity of utilman.exe, sethc.exe, osk.exe, magnify.exe, and narrator.exe.
Record selected file metadata and cryptographic hashes for later comparison.
Examine the native Image File Execution Options Registry area for accessibility-related entries.
Determine whether utilman.exe or sethc.exe has an unexpected execution-related configuration.
Check the 32-bit IFEO Registry view for additional context.
Understand how a debugger-style Registry value could alter the normal execution path of a trusted Windows component.
Practice investigating persistence without modifying the real accessibility executables.
Correlate Registry activity with available process, PowerShell, and network telemetry.
Determine which telemetry sources provide useful evidence and which leave gaps.
Verify that the controlled Registry artifact is completely removed after the investigation.
Distinguish a persistence indicator from confirmed malicious persistence.

## Investigation Scenario

A Windows workstation is being reviewed for possible persistence involving accessibility features such as utilman.exe and sethc.exe. Since these are legitimate Windows components, the analyst needs to determine whether their normal execution configuration has been altered.

The investigation focuses on:

Verifying the accessibility binaries and their integrity.
Checking the related IFEO Registry configuration.
Looking for unexpected debugger or execution values.
Reviewing process and PowerShell telemetry.
Distinguishing a legitimate Windows configuration from a persistence indicator.

A separate lab-only Registry artifact is used to safely simulate the persistence pattern without modifying the actual accessibility binaries or creating a real logon bypass. The final assessment must determine whether the evidence represents actual persistence or only a controlled simulation.


## Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows |
| Investigation Type | Windows DFIR / Persistence |
| Primary Registry Area | `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` |
| Lab-only Registry Area | `HKLM:\SOFTWARE\Lab64-AccessibilityPersistence` |
| Accessibility Binaries | `utilman.exe`, `sethc.exe`, `osk.exe`, `magnify.exe`, `narrator.exe` |
| Sysmon Event ID 1 | Available |
| Sysmon Event ID 3 | Available |
| PowerShell Event ID 4104 | Present, no relevant lab result established |
| Security Event ID 4688 | Queried, no direct attribution established |

## Safety Boundaries

The lab did not:

- Replace `utilman.exe`.
- Replace `sethc.exe`.
- Modify files in `C:\Windows\System32`.
- Configure a real accessibility logon bypass.
- Launch a shell from the Windows logon screen.
- Modify the native accessibility IFEO keys.
- Execute a payload.

The persistence demonstration used only:

`HKLM:\SOFTWARE\Lab64-AccessibilityPersistence`

This was explicitly separated from the real Windows configuration.

## Accessibility Binary Baseline

The following binaries were verified under:

`C:\Windows\System32`

- `utilman.exe`
- `sethc.exe`
- `osk.exe`
- `magnify.exe`
- `narrator.exe`

Observed metadata included:

| File | Path | Length |
|---|---|---:|
| `utilman.exe` | `C:\Windows\System32\utilman.exe` | 126464 bytes |
| `sethc.exe` | `C:\Windows\System32\sethc.exe` | 107008 bytes |
| `osk.exe` | `C:\Windows\System32\osk.exe` | 674304 bytes |
| `magnify.exe` | `C:\Windows\System32\Magnify.exe` | 650752 bytes |
| `narrator.exe` | `C:\Windows\System32\Narrator.exe` | 534016 bytes |

All five binaries returned:

`Valid`

for the Authenticode status checks.

## utilman.exe Integrity

The `utilman.exe` file was recorded as:

```text
Path:
C:\Windows\System32\utilman.exe

Length:
126464

CreationTime:
04-08-2026 07:04:28

LastWriteTime:
04-08-2026 07:04:28
```

The recorded SHA-256 was:

```text
7D536447FFDDBAD5C9E99159087A6EBB7CA2324BC39FF80FD10E3E3106CC6849
```

The Authenticode status was:

`Valid`

## sethc.exe Integrity

The `sethc.exe` file was recorded as:

```text
Path:
C:\Windows\System32\sethc.exe

Length:
107008

CreationTime:
04-08-2026 07:04:28

LastWriteTime:
04-08-2026 07:04:28
```

Its Authenticode status was:

`Valid`

## IFEO Investigation

The native IFEO location examined was:

```text
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
```

The enumeration returned multiple existing entries, including items such as:

- `mshta.exe`
- `MsMpEng.exe`
- `svchost.exe`
- `spoolsv.exe`
- `SystemSettings.exe`
- `wpr.exe`
- `wprui.exe`

The investigation did not establish that these existing entries were malicious.

## Accessibility-Specific IFEO Checks

The investigation specifically checked:

- `utilman.exe`
- `sethc.exe`
- `osk.exe`
- `magnify.exe`
- `narrator.exe`

The targeted checks for `utilman.exe` and `sethc.exe` did not return evidence of configured values.

The broader accessibility verification script also did not produce evidence that those accessibility-specific entries contained suspicious configuration.

## WOW6432Node IFEO

The 32-bit Registry view was also enumerated:

```text
HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
```

Multiple entries were present, including:

- `mshta.exe`
- `svchost.exe`
- `spoolsv.exe`
- `splwow64.exe`
- `PrintIsolationHost.exe`
- `MsMpEng.exe`
- `PresentationHost.exe`

The presence of an IFEO entry alone was not interpreted as malicious persistence.

## Safe Persistence Simulation

A separate lab-only Registry key was created:

```text
HKLM:\SOFTWARE\Lab64-AccessibilityPersistence
```

The key was populated with:

```text
Simulated Debugger = C:\Lab64\simulated-payload.exe
```

This was intentionally not placed beneath the real accessibility IFEO configuration.

The lab artifact existed only to demonstrate how an analyst could investigate a Registry persistence indicator safely.

## Lab Artifact Verification

The simulated value was successfully retrieved:

```text
Simulated Debugger : C:\Lab64\simulated-payload.exe
```

The Registry key path was:

```text
HKEY_LOCAL_MACHINE\SOFTWARE\Lab64-AccessibilityPersistence
```

## Sysmon Event ID 1

Sysmon Event ID 1 was queried for `powershell.exe`.

The investigation returned process-create events at:

```text
28-08-2026 06:36:37
28-08-2026 06:36:35
28-08-2026 06:35:36
```

These demonstrate process telemetry was available.

The supplied output did not directly prove that a specific process creation event created the lab Registry persistence artifact.

## Sysmon Event ID 3

Sysmon Event ID 3 was available.

The investigation returned numerous network connection events during the morning of 28 August 2026.

No network activity was established as being caused by the simulated Registry artifact.

## PowerShell Event ID 4104

PowerShell Event ID 4104 was queried using:

```text
Lab64-AccessibilityPersistence
SimulatedDebugger
```

No relevant result was returned in the supplied evidence.

Therefore, PowerShell Script Block Logging did not directly establish the Registry modification.

## Security Event ID 4688

Security Event ID 4688 was queried for:

```text
powershell.exe
```

No result was returned in the supplied evidence.

Therefore, no relevant Security process-creation evidence was established for the configuration activity.

## Registry Cleanup

The lab-only persistence artifact was removed with:

```powershell
Remove-Item `
"HKLM:\SOFTWARE\Lab64-AccessibilityPersistence" `
-Recurse `
-Force
```

A subsequent check returned:

```text
False
```

for:

```powershell
Test-Path "HKLM:\SOFTWARE\Lab64-AccessibilityPersistence"
```

This confirmed that the lab-only Registry artifact had been removed.

## Evidence Correlation

The investigation followed:

```text
Accessibility Binary
        |
        v
Expected Windows Path
        |
        v
Metadata
        |
        v
Signature
        |
        v
Hash
        |
        v
Native IFEO Configuration
        |
        v
Lab Persistence Simulation
        |
        v
Process Telemetry
        |
        v
PowerShell Telemetry
        |
        v
Network Telemetry
        |
        v
Cleanup Verification
```

## MITRE ATT&CK Relevance

Potentially relevant techniques in a real incident include:

**T1546 — Event Triggered Execution**

Relevant to persistence mechanisms that trigger execution based on specific system events or conditions.

**T1546.012 — Image File Execution Options Injection**

Relevant when IFEO is used to manipulate execution of a target process.

**T1112 — Modify Registry**

Relevant when Registry modification is part of the persistence mechanism.

The controlled lab demonstrates Registry-based simulation and does not establish malicious persistence.

