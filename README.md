# Windows DFIR Lab 64 — Accessibility Features Persistence Investigation

## Overview

This lab investigates Windows accessibility features from a DFIR and persistence-detection perspective.

Accessibility executables such as `utilman.exe`, `sethc.exe`, `osk.exe`, `magnify.exe`, and `narrator.exe` are legitimate Windows components. The security concern arises when an attacker modifies the execution path or Registry configuration associated with one of these binaries so that an unexpected program is launched.

The investigation therefore focuses on identifying configuration changes around accessibility executables, particularly through Image File Execution Options (IFEO), while preserving the real Windows binaries and avoiding the creation of an actual logon bypass.

A safe lab-only Registry key was created under:

`HKLM:\SOFTWARE\Lab64-AccessibilityPersistence`

A simulated debugger value pointing to `C:\Lab64\simulated-payload.exe` was added to demonstrate how persistence evidence could appear during an investigation. The lab-only key was subsequently removed.

The actual accessibility executables were not modified.

## Investigation Objectives

- Establish a baseline for Windows accessibility executables.
- Verify the legitimate locations of accessibility binaries.
- Collect file metadata for selected accessibility executables.
- Validate their Authenticode signatures.
- Record SHA-256 evidence for file-integrity comparison.
- Enumerate native IFEO configuration entries.
- Check specifically for accessibility-related IFEO entries.
- Examine the 32-bit IFEO Registry view.
- Safely simulate a persistence-related Registry artifact without modifying a real Windows accessibility configuration.
- Determine whether process telemetry records the investigation activity.
- Review PowerShell Script Block Logging for related activity.
- Review Security Event ID 4688 for process evidence.
- Examine Sysmon Event ID 3 for surrounding network activity.
- Remove and verify cleanup of the lab-only Registry artifact.
- Distinguish a safe simulation artifact from confirmed persistence.

## Investigation Scenario

A Windows workstation is being assessed for possible persistence involving accessibility features. The analyst is concerned that a legitimate Windows accessibility program may have had its normal execution behavior altered through Registry configuration.

The investigation begins by validating the integrity and legitimacy of the accessibility executables and then examines IFEO configuration for entries associated with those programs.

Because modifying real accessibility binaries or creating a logon-screen bypass would be unsafe, the persistence behavior is simulated using a clearly named lab-only Registry key. The analyst must then determine whether the available telemetry can identify the configuration activity and whether the evidence represents an actual persistence mechanism or only a controlled investigation artifact.

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

## Key Findings

- All five reviewed accessibility binaries were located in `C:\Windows\System32`.
- Authenticode validation returned `Valid` for all five reviewed accessibility binaries.
- `utilman.exe` SHA-256 was recorded.
- The native IFEO configuration was inspected.
- Accessibility-specific IFEO checks did not establish suspicious configured values.
- A separate lab-only Registry key was created for safe persistence simulation.
- The simulated debugger value pointed to `C:\Lab64\simulated-payload.exe`.
- The lab-only Registry key was successfully removed.
- Sysmon Event ID 1 was available.
- Sysmon Event ID 3 was available.
- PowerShell Event ID 4104 did not establish relevant configuration-change evidence.
- Security Event ID 4688 did not establish relevant process evidence for the simulation.
- No real accessibility persistence mechanism was created.

## DFIR Interpretation

The main forensic question is whether a legitimate accessibility executable has had its normal execution path altered.

A legitimate baseline looks like:

```text
C:\Windows\System32\utilman.exe
        |
        +-- Valid signature
        +-- Expected metadata
        +-- Expected system location
```

A suspicious persistence configuration could look like:

```text
utilman.exe
    |
    +-- IFEO entry
          |
          +-- Unexpected Debugger
                 |
                 +-- User-writable executable
```

The lab demonstrated this concept safely by creating the simulated Registry artifact outside the real IFEO configuration.

## What Would Increase Suspicion?

A real investigation would become more concerning if the evidence showed:

- An accessibility executable-specific IFEO entry.
- An unexpected `Debugger` value.
- A debugger pointing to a user-writable directory.
- An unsigned or unknown executable.
- Suspicious process creation.
- Additional persistence mechanisms.
- Network activity originating from the unexpected process.
- Changes to the legitimate accessibility binary itself.

## MITRE ATT&CK Relevance

Potentially relevant techniques in a real incident include:

**T1546 — Event Triggered Execution**

Relevant to persistence mechanisms that trigger execution based on specific system events or conditions.

**T1546.012 — Image File Execution Options Injection**

Relevant when IFEO is used to manipulate execution of a target process.

**T1112 — Modify Registry**

Relevant when Registry modification is part of the persistence mechanism.

The controlled lab demonstrates Registry-based simulation and does not establish malicious persistence.

## Evidence Limitations

- No direct native accessibility IFEO persistence was established.
- Sysmon Event ID 7 was not part of this investigation evidence.
- PowerShell Event ID 4104 did not provide a relevant Registry-change event.
- Security Event ID 4688 did not provide relevant attribution.
- Sysmon Event ID 1 showed PowerShell process activity but did not by itself prove the Registry modification.
- Sysmon Event ID 3 showed network activity but did not establish a connection to the lab artifact.
- No actual logon-screen persistence mechanism was created.

## Conclusion

The investigation established a healthy baseline for the Windows accessibility executables and demonstrated how IFEO-based persistence should be investigated without modifying real Windows accessibility mechanisms.

All reviewed accessibility binaries were present in the expected System32 location and returned valid Authenticode results. The native accessibility-specific IFEO checks did not establish suspicious configuration.

A lab-only Registry artifact containing a simulated debugger value was created to demonstrate the persistence-investigation workflow and was successfully removed afterward.

The evidence therefore supports:

```text
Accessibility Feature Baseline
+
Safe IFEO Persistence Simulation
+
Telemetry Review
+
Successful Cleanup
```

but does not support:

```text
Confirmed Malicious Accessibility Persistence
```
