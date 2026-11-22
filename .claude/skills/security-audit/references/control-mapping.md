# Control Mapping

Map each confirmed finding to the controls below. If a finding fits more than
one row, include the controls from every row it fits. If it fits no row, use
the closest row and say why in the finding.

## Issue types

| Issue type | SOC 2 | ISO 27001:2022 Annex A |
|---|---|---|
| Hard-coded secret | CC6.1 | 5.17, 8.24 |
| Injection (SQL, command, `eval`) | CC7.1, CC8.1 | 8.28 |
| Weak crypto / weak password hashing | CC6.1, CC6.7 | 8.24 |
| Missing authentication or authorization | CC6.1, CC6.3 | 5.15, 8.5 |
| Sensitive data in logs | CC6.1, CC7.2 | 8.11, 8.15 |
| Insecure defaults / debug mode | CC7.1, CC8.1 | 8.9 |
| CORS allows any origin | CC6.6 | 8.26 |
| Vulnerable dependency | CC7.1 | 8.8 |

## What the controls mean

Use these titles in the report so an auditor doesn't have to look them up.

### SOC 2 (Trust Services Criteria, 2017)
| ID | Title |
|---|---|
| CC6.1 | Logical access security over protected information assets |
| CC6.3 | Access is authorized, modified, or removed based on roles |
| CC6.6 | Protection against threats from outside system boundaries |
| CC6.7 | Restricts and protects data in transmission and movement |
| CC7.1 | Detects configuration changes and new vulnerabilities |
| CC7.2 | Monitors system components for anomalies |
| CC8.1 | Changes are authorized, tested, and approved |

### ISO 27001:2022 Annex A
| ID | Title |
|---|---|
| 5.15 | Access control |
| 5.17 | Authentication information |
| 8.5 | Secure authentication |
| 8.8 | Management of technical vulnerabilities |
| 8.9 | Configuration management |
| 8.11 | Data masking |
| 8.15 | Logging |
| 8.24 | Use of cryptography |
| 8.26 | Application security requirements |
| 8.28 | Secure coding |
