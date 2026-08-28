# Timeline 

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

