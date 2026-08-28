# Investigation Notes 

## Accessibility Binary Baseline

The following files were examined:

```text
C:\Windows\System32\utilman.exe
C:\Windows\System32\sethc.exe
C:\Windows\System32\osk.exe
C:\Windows\System32\Magnify.exe
C:\Windows\System32\Narrator.exe
```

Observed file sizes were:

```text
utilman.exe   126464 bytes
sethc.exe     107008 bytes
osk.exe       674304 bytes
Magnify.exe   650752 bytes
Narrator.exe  534016 bytes
```

## Digital Signatures

The multi-binary Authenticode check returned:

```text
utilman.exe   Valid
sethc.exe     Valid
osk.exe       Valid
magnify.exe   Valid
narrator.exe  Valid
```

This established a trusted baseline for the reviewed accessibility executables.

## utilman.exe Hash

The collected SHA-256 for:

```text
C:\Windows\System32\utilman.exe
```

was:

```text
7D536447FFDDBAD5C9E99159087A6EBB7CA2324BC39FF80FD10E3E3106CC6849
```

## utilman.exe Metadata

Observed:

```text
Name          : utilman.exe
FullName      : C:\Windows\System32\utilman.exe
Length        : 126464
CreationTime  : 04-08-2026 07:04:28
LastWriteTime : 04-08-2026 07:04:28
```

## sethc.exe Metadata

Observed:

```text
Name          : sethc.exe
FullName      : C:\Windows\System32\sethc.exe
Length        : 107008
CreationTime  : 04-08-2026 07:04:28
LastWriteTime : 04-08-2026 07:04:28
```

Its Authenticode status was:

```text
Valid
```

## Native IFEO Enumeration

The main IFEO location was enumerated:

```text
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
```

Existing entries included:

```text
DefenderAgentScan.exe
ExtExport.exe
ie4uinit.exe
ieinstal.exe
ielowutil.exe
ieUnatt.exe
iexplore.exe
MicrosoftEdgeUpdate.exe
MRT.exe
mscorwsv.exe
msfeedssync.exe
mshta.exe
MsMpEng.exe
ngen.exe
ngentask.exe
PresentationHost.exe
PrintDialog.exe
PrintIsolationHost.exe
runtimebroker.exe
splwow64.exe
spoolsv.exe
svchost.exe
SystemSettings.exe
wpr.exe
wprui.exe
```

The presence of these entries was not itself treated as malicious.

## Accessibility IFEO Checks

The investigation specifically checked:

```text
utilman.exe
sethc.exe
osk.exe
magnify.exe
narrator.exe
```

The verification script did not return output indicating that these accessibility-specific IFEO entries were configured.

Targeted checks for `utilman.exe` and `sethc.exe` also did not return suspicious values.

## WOW6432Node IFEO

The 32-bit IFEO view contained multiple entries.

Examples included:

```text
mshta.exe
MsMpEng.exe
PresentationHost.exe
PrintDialog.exe
PrintIsolationHost.exe
runtimebroker.exe
splwow64.exe
spoolsv.exe
svchost.exe
SystemSettings.exe
wpr.exe
wprui.exe
```

No conclusion of malicious persistence was drawn from the existence of these entries.

## Safe Persistence Simulation

A separate Registry key was created:

```text
HKLM:\SOFTWARE\Lab64-AccessibilityPersistence
```

The purpose was to simulate what a persistence indicator might look like without altering any real Windows accessibility configuration.

The key contained:

```text
Simulated Debugger : C:\Lab64\simulated-payload.exe
```

This was a clearly labeled laboratory artifact.

## Lab Artifact Verification

The Registry key was successfully queried.

Observed:

```text
Simulated Debugger : C:\Lab64\simulated-payload.exe
```

The key's PowerShell provider information confirmed the path:

```text
HKEY_LOCAL_MACHINE\SOFTWARE\Lab64-AccessibilityPersistence
```

## Sysmon Event ID 1

The investigation searched for `powershell.exe`.

Observed process creation events included:

```text
28-08-2026 06:36:37
28-08-2026 06:36:35
28-08-2026 06:35:36
```

These events establish that Sysmon process telemetry was functioning.

The supplied output did not expose enough detail to attribute a specific event directly to the Registry artifact.

## Sysmon Event ID 3

Network telemetry was available.

The investigation returned numerous Event ID 3 records.

No specific network connection was attributed to the lab Registry simulation.

## PowerShell Event ID 4104

The following values were searched:

```text
Lab64-AccessibilityPersistence
SimulatedDebugger
```

No relevant 4104 result was returned.

Therefore, PowerShell Script Block Logging did not independently establish the creation of the lab Registry artifact.

## Security Event ID 4688

The Security log was queried for:

```text
powershell.exe
```

No relevant result was returned.

Therefore, Security Event ID 4688 did not provide supporting evidence for the Registry simulation.

## Cleanup

The lab-only Registry key was deleted:

```powershell
Remove-Item `
"HKLM:\SOFTWARE\Lab64-AccessibilityPersistence" `
-Recurse `
-Force
```

The cleanup verification returned:

```text
False
```

for:

```powershell
Test-Path "HKLM:\SOFTWARE\Lab64-AccessibilityPersistence"
```

This confirmed successful removal of the laboratory persistence artifact.

## Evidence Correlation

The investigation followed:

```text
Accessibility Baseline
        |
        v
Binary Integrity
        |
        v
Native IFEO Review
        |
        v
Lab-Only Registry Simulation
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

