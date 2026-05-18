# Business-Email-Compromise-Account-Investigation

## IR-2026-0225-BEC — Incident Response Report
**LogN Pacific Financial Services**

---

## Incident Summary

| Field | Detail |
|---|---|
| Incident ID | IR-2026-0225-BEC |
| Severity | HIGH |
| Status | Contained |
| Reported | 26 February 2026, 09:30 UTC |
| Source | External bank fraud department |
| Financial Impact | £24,500 (frozen) |
| Threat Actor | Scattered Spider (UNC3944 / Octo Tempest) |
| Compromised Account | m.smith@lognpacific.org |
| Attacker IP | 205.147.16.190 (Netherlands) |
| Attack Window | 25 Feb 2026, 21:44 UTC – 26 Feb 2026, 00:00 UTC |

---

## What Happened

A financially motivated threat actor obtained credentials for Mark Smith, a finance employee at LogN Pacific Financial Services, via an infostealer malware log purchase. Using MFA fatigue (push bombing), the attacker defeated Microsoft Authenticator and gained full access to Mark's Microsoft 365 account via Outlook Web Access.

Once inside, the attacker read Mark's inbox to understand active payment threads, created two silent inbox rules for persistence and evidence suppression, then sent a fraudulent invoice email to a finance colleague (j.reynolds@lognpacific.org) impersonating Mark. The colleague processed a £24,500 payment to an attacker-controlled account. The receiving bank flagged the transaction as suspicious and froze the funds.

---

## Attack Timeline

| Time (UTC) | Event |
|---|---|
| 25 Feb 21:44 | Mark signs in legitimately — US, Windows 10, Edge 145.0.0, IP `172.175.65.103` |
| 25 Feb 21:52 | Attacker authenticates Mark's password from Netherlands IP `205.147.16.190` |
| 25 Feb 21:54 | **MFA push #1** — Mark denies (ResultType `50074`) |
| 25 Feb 22:24 | **MFA push #2** — Mark denies (ResultType `50074`) |
| 25 Feb 22:25 | **MFA push #3** — Mark approves to make notifications stop. Account compromised (ResultType `0`) |
| 25 Feb 21:56 | Attacker reads inbox via `MailItemsAccessed` — identifies active vendor payment threads |
| 25 Feb 22:02 | Inbox rule **`.`** created — forwards financial emails to `insights@duck.com` |
| 25 Feb 22:03 | Inbox rule **`..`** created — deletes security alert emails |
| 25 Feb 22:06 | Fraudulent BEC email sent to `j.reynolds@lognpacific.org` |
| 25 Feb 22:07 | Attacker accesses SharePoint Online and OneDrive for Business |
| 26 Feb 09:30 | Bank fraud department flags £24,500 transfer — funds frozen |

---

## Confirmed Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| IP | `205.147.16.190` | Attacker source IP (Netherlands) |
| Email | `insights@duck.com` | Exfiltration forward-to address |
| Email | `j.reynolds@lognpacific.org` | BEC fraud recipient |
| Inbox Rule | `.` | Forwards financial emails externally |
| Inbox Rule | `..` | Deletes security alert emails |
| Session ID | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` | AAD session linking all attacker activity |
| Network Message ID | `af6891d8-99ad-4c07-37d2-08de74ba239f` | Fraudulent BEC email |
| Subject | `RE: Invoice #INV-2026-0892 - Updated Banking Details` | Thread-hijacked BEC pretext |

---

## Inbox Rules Detail

### Rule 1 — `.`
| Parameter | Value |
|---|---|
| Name | `.` |
| Trigger | `SubjectOrBodyContainsWords`: invoice, payment, wire, transfer |
| Action | `ForwardTo`: insights@duck.com |
| StopProcessingRules | True |

### Rule 2 — `..`
| Parameter | Value |
|---|---|
| Name | `..` |
| Trigger | `SubjectOrBodyContainsWords`: suspicious, security, phishing, unusual, compromised, verify |
| Action | `DeleteMessage`: True |
| StopProcessingRules | True |

---

## Attacker Session Profile

| Signal | Legitimate (Mark) | Attacker |
|---|---|---|
| IP Address | `172.175.65.103` | `205.147.16.190` |
| Country | United States | Netherlands |
| OS | Windows 10 | Ubuntu Linux |
| Browser | Edge 145.0.0 | Firefox 147.0 |
| Application | OfficeHome | One Outlook Web |
| Auth method | Single factor | MFA (push bombing) |

---

## Data Sources Queried

| Table | Purpose |
|---|---|
| `SigninLogs` | Confirm compromise, identify attacker IP, MFA bypass method, application access |
| `CloudAppEvents` | Inbox rule creation, mailbox access, OneDrive/SharePoint activity |
| `EmailEvents` | BEC email identification, recipient, subject, delivery status |

---

## KQL Queries Used

### Q1 — Confirm compromise
```kql
SigninLogs
| where TimeGenerated between (
    datetime(2026-02-25T21:00:00Z) ..
    datetime(2026-02-26T00:00:00Z)
)
| where UserPrincipalName == "m.smith@lognpacific.org"
| project TimeGenerated, UserPrincipalName, IPAddress,
    Location, ResultType, ResultDescription,
    AuthenticationRequirement, AuthenticationDetails,
    UserAgent, CorrelationId
| order by TimeGenerated asc
```
<img width="1175" height="422" alt="image" src="https://github.com/user-attachments/assets/15434af9-fb2b-4033-ae7e-5eacd86bed18" />


### Q2 — Comparison of Legitimate Device vs Attacker device profile
```kql
//Legitimate Device
SigninLogs
| where TimeGenerated between (
    datetime(2026-02-25T21:00:00Z) ..
    datetime(2026-02-25T22:00:00Z)
)
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "172.175.65.103"
| extend OS = tostring(DeviceDetail.operatingSystem),
         Browser = tostring(DeviceDetail.browser)
| project TimeGenerated, UserAgent, ClientAppUsed,
    AppDisplayName, OS, Browser, IPAddress
| order by TimeGenerated asc
```
<img width="1360" height="140" alt="image" src="https://github.com/user-attachments/assets/c39369ea-731d-40b1-909d-a8b94899b2e0" />

```kql
// Attacker Device
SigninLogs
| where TimeGenerated between (
    datetime(2026-02-25T21:00:00Z) ..
    datetime(2026-02-25T22:00:00Z)
)
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| extend OS = tostring(DeviceDetail.operatingSystem),
         Browser = tostring(DeviceDetail.browser)
| project TimeGenerated, UserAgent, ClientAppUsed,
    AppDisplayName, OS, Browser, IPAddress
| order by TimeGenerated asc
```
<img width="1355" height="164" alt="image" src="https://github.com/user-attachments/assets/504994de-ab6e-4b3d-a99d-de79df66d4a4" />

### Q3 — Inbox rule creation
```kql
CloudAppEvents
| where TimeGenerated between (
    datetime(2026-02-25T21:00:00Z) ..
    datetime(2026-02-26T00:00:00Z)
)
| where AccountObjectId == "fa5020a1-0d42-4839-bbfe-22db0861ced5"
| where ActionType == "New-InboxRule"
| extend ParsedData = parse_json(RawEventData)
| extend Parameters = parse_json(tostring(ParsedData.Parameters))
| mv-expand Parameters
| extend ParamName = tostring(Parameters.Name)
| extend ParamValue = tostring(Parameters.Value)
| project TimeGenerated, ActionType, ParamName, ParamValue, IPAddress, RawEventData
| order by TimeGenerated asc
```
<img width="1553" height="377" alt="image" src="https://github.com/user-attachments/assets/13374e6c-d3af-4789-aec1-2ba5169da497" />


### Q4 — BEC email
```kql
EmailEvents
| where TimeGenerated between (
    datetime(2026-02-25T21:00:00Z) ..
    datetime(2026-02-26T00:00:00Z)
)
| where SenderFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, SenderFromAddress,
    RecipientEmailAddress, Subject,
    SenderIPv4, DeliveryAction,
    EmailDirection, NetworkMessageId
| order by TimeGenerated asc
```
<img width="1552" height="77" alt="image" src="https://github.com/user-attachments/assets/e4ee5242-5fb6-484d-b4a5-bbbcbcf1fb13" />


### Q5 — Application footprint
```kql
SigninLogs
| where TimeGenerated between (
    datetime(2026-02-25T21:00:00Z) ..
    datetime(2026-02-26T00:00:00Z)
)
| where IPAddress == "205.147.16.190"
| where ResultType == "0"
| summarize count() by AppDisplayName
| order by count_ desc
```
<img width="489" height="163" alt="image" src="https://github.com/user-attachments/assets/70407066-c69d-49b2-babf-61a9bec4b1af" />

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Observed Behaviour |
|---|---|---|
| T1621 | Multi-Factor Authentication Request Generation | Push bombing — 2 denials before approval |
| T1078 | Valid Accounts | Purchased credentials used for initial access |
| T1114.002 | Email Collection: Remote Email Collection | `MailItemsAccessed` via OWA |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Inbox rules `.` and `..` created |
| T1020 | Automated Exfiltration | Rule forwarding financial emails to `insights@duck.com` |
| T1566.002 | Phishing: Spearphishing Link | Thread hijacking via `RE: Invoice #INV-2026-0892` |
| T1485 | Data Destruction | Rule `..` deleting security alert emails |

---

## Defensive Failures

| Control | Status | Finding |
|---|---|---|
| Conditional Access | `notApplied` | No policy evaluated — Security Defaults only |
| Device compliance | Not configured | Unmanaged Ubuntu device allowed to authenticate |
| Location-based policy | Not configured | Netherlands sign-in not challenged or blocked |
| MFA number matching | Not enabled | Blind push approval possible — fatigue attack succeeded |
| Entra ID Protection | Not configured | No risk-based sign-in policy to flag anomalous session |
| Token binding | Not configured | Session token replayed 13 times post-compromise |

---

## Scope of Access

| Application | Sign-ins | Data at Risk |
|---|---|---|
| One Outlook Web | 24 | Full mailbox access — emails read, BEC sent |
| SharePoint Online | 2 | Shared organisational document libraries |
| Microsoft OneDrive for Business | — | Personal file storage accessed |
| OfficeHome | 1 | M365 portal |

---

## Containment Actions

| Priority | Action |
|---|---|
| 1 | **Revoke session** — invalidate AAD session `00225cfa-a0ff-fb46-a079-5d152fcdf72a` |
| 2 | Reset Mark's password — invalidate purchased credential |
| 3 | Delete inbox rules `.` and `..` |
| 4 | Block `insights@duck.com` at mail gateway |
| 5 | Block `205.147.16.190` at firewall / Conditional Access named locations |
| 6 | Force MFA re-enrolment with number matching enabled |
| 7 | Notify J. Reynolds — confirm payment status with bank |

---

## Recommendations

1. **Replace Security Defaults with Conditional Access policies** — enforce device compliance, block high-risk locations, require compliant/hybrid-joined devices
2. **Enable MFA number matching** — defeats push bombing by requiring the user to match a displayed code
3. **Deploy Entra ID Protection** — risk-based sign-in policies will auto-block anomalous sessions
4. **Monitor for inbox rule creation** — alert on `New-InboxRule` / `Set-InboxRule` in CloudAppEvents, especially rules with `ForwardTo` external addresses or `DeleteMessage`
5. **Implement UEBA baseline profiling** — flag sign-ins deviating from established OS/browser/country baseline
6. **Vendor payment controls** — require out-of-band verification for any banking detail change requests regardless of sender

---

## Attribution

**Scattered Spider** (also tracked as UNC3944 by Mandiant, Octo Tempest by Microsoft)

A financially motivated threat actor known for MFA fatigue attacks, help desk social engineering, and business email compromise targeting finance teams. Uses legitimate cloud infrastructure to blend into normal traffic. Known victims include MGM Resorts, Caesars Entertainment, and multiple UK retailers.

Initial credential access via **infostealer** malware logs purchased from underground marketplaces (Redline, Raccoon, Vidar, LummaC2 family).

---

*Report generated: 26 February 2026 | Investigated using Microsoft Sentinel (law-cyber-range) | Data sources: SigninLogs, CloudAppEvents, EmailEvents*
