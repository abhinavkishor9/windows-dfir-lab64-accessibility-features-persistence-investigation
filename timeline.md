# Timeline — Lab 64 Accessibility Features Persistence Investigation

## Timeline Purpose

This timeline records the accessibility binary baseline, IFEO investigation, safe Registry persistence simulation, telemetry review, and cleanup.

## Investigation Timeline

| Time | Source | Activity | Result |
|---|---|---|---|
| 06:20 | Registry | Lab-only Registry key created | `Lab64-AccessibilityPersistence` established |
| 06:35:36 | Sysmon Event ID 1 | PowerShell process observed | Process telemetry available |
| 06:36:35 | Sysmon Event ID 1 | PowerShell process observed | Process telemetry available |
| 06:36:37 | Sysmon Event ID 1 | PowerShell process observed | Process telemetry available |
| 06:30–07:44 | Sysmon Event ID 3 | Network events reviewed | Network telemetry available |
| During investigation | File System | `utilman.exe` inspected | Legitimate System32 location |
| During investigation | File System | `sethc.exe` inspected | Legitimate System32 location |
| During investigation | Authenticode | Accessibility binaries checked | All reviewed files Valid |
| During investigation | Hash | `utilman.exe` hashed | SHA-256 recorded |
| During investigation | Registry | Native IFEO enumerated | Existing entries identified |
| During investigation | Registry | Accessibility-specific IFEO checked | No suspicious accessibility entry established |
| During investigation | Registry | Lab-only simulated debugger added | Controlled persistence artifact created |
| During investigation | Registry | Lab-only key queried | Simulated debugger confirmed |
| During investigation | PowerShell | Event ID 4104 searched | No relevant result |
| During investigation | Security | Event ID 4688 searched | No relevant result |
| Final | Registry | Lab-only key removed | Simulation cleaned up |
| Final | Registry | Cleanup verified | `Test-Path` returned `False` |

## Phase 1 — Accessibility Baseline

The following accessibility programs were confirmed in the Windows System32 directory:

```text
utilman.exe
sethc.exe
osk.exe
Magnify.exe
Narrator.exe
```

All reviewed binaries returned valid Authenticode results.

## Phase 2 — File Integrity

### utilman.exe

Observed:

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

SHA-256:

```text
7D536447FFDDBAD5C9E99159087A6EBB7CA2324BC39FF80FD10E3E3106CC6849
```

Signature:

```text
Valid
```

### sethc.exe

Observed:

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

Signature:

```text
Valid
```

## Phase 3 — Native IFEO Investigation

The main IFEO key was enumerated:

```text
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
```

Multiple entries were present.

The investigation then targeted:

```text
utilman.exe
sethc.exe
osk.exe
magnify.exe
narrator.exe
```

No suspicious accessibility-specific configuration was established.

## Phase 4 — Safe Persistence Simulation

A separate key was created:

```text
HKLM:\SOFTWARE\Lab64-AccessibilityPersistence
```

A simulated debugger value was added:

```text
Simulated Debugger = C:\Lab64\simulated-payload.exe
```

This was intentionally separate from the real Windows IFEO configuration.

## Phase 5 — Lab Artifact Verification

The simulated Registry configuration was successfully queried.

Observed:

```text
Simulated Debugger : C:\Lab64\simulated-payload.exe
```

This confirmed that the controlled persistence artifact existed for investigation.

## Phase 6 — Process Telemetry

Sysmon Event ID 1 returned PowerShell-related events:

```text
28-08-2026 06:36:37
28-08-2026 06:36:35
28-08-2026 06:35:36
```

These events demonstrated process telemetry availability.

The supplied evidence did not establish direct attribution to the Registry modification.

## Phase 7 — PowerShell Telemetry

PowerShell Event ID 4104 was searched for:

```text
Lab64-AccessibilityPersistence
SimulatedDebugger
```

No relevant event was identified.

## Phase 8 — Security Telemetry

Security Event ID 4688 was searched for:

```text
powershell.exe
```

No relevant event was identified in the supplied evidence.

## Phase 9 — Network Telemetry

Sysmon Event ID 3 produced numerous network events during the investigation period.

No specific network event was connected to the lab persistence simulation.

## Phase 10 — Cleanup

The lab-only Registry key was removed:

```powershell
Remove-Item `
"HKLM:\SOFTWARE\Lab64-AccessibilityPersistence" `
-Recurse `
-Force
```

Cleanup verification:

```powershell
Test-Path "HKLM:\SOFTWARE\Lab64-AccessibilityPersistence"
```

Result:

```text
False
```

This confirmed removal of the simulated persistence artifact.

## Final Evidence Chain

```text
Accessibility Binary
        |
        v
Expected System Path
        |
        v
Metadata
        |
        v
Authenticode
        |
        v
SHA-256
        |
        v
Native IFEO Review
        |
        v
Safe Lab Simulation
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

## Final Evidence Summary

| Evidence Source | Finding |
|---|---|
| Accessibility binaries | Present in System32 |
| Authenticode | Valid for all reviewed accessibility binaries |
| utilman.exe SHA-256 | Recorded |
| Native accessibility IFEO | No suspicious entry established |
| Lab-only IFEO simulation | Successfully created |
| Simulated debugger | `C:\Lab64\simulated-payload.exe` |
| Sysmon Event ID 1 | Available |
| Sysmon Event ID 3 | Available |
| PowerShell Event ID 4104 | No relevant result |
| Security Event ID 4688 | No relevant result |
| Cleanup | Successful |
| Lab key after cleanup | Not present |

## Final Assessment

The endpoint's accessibility binaries were consistent with a legitimate Windows baseline.

The lab-only Registry simulation successfully demonstrated how an analyst could identify a suspicious debugger-style configuration while keeping the real Windows accessibility mechanisms untouched.

No evidence established malicious accessibility persistence.

## Investigation Conclusion

The final evidence supports:

```text
Legitimate Accessibility Binary Baseline
+
Native IFEO Review
+
Safe Persistence Simulation
+
Telemetry Review
+
Successful Cleanup
```

It does not support:

```text
Confirmed Accessibility-Based Persistence
```

The central DFIR lesson is that persistence investigations should focus on **unexpected changes to trusted execution paths**, while carefully separating real system artifacts from controlled laboratory simulations.
