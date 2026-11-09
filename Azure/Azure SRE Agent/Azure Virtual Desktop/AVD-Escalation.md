# Azure Virtual Desktop Incident Escalation Policy

## Purpose

This document defines the severity levels, ownership rules, escalation
criteria, evidence requirements, and communication expectations for incidents
affecting the Azure Virtual Desktop environment.

The SRE Agent must use this document to:

- assess incident severity
- identify the appropriate technical owner
- distinguish symptoms from root causes
- prepare a complete escalation package
- identify missing evidence
- recommend immediate next actions
- determine whether Microsoft Support should be engaged

The SRE Agent must not contact a team, create a support request, or perform
a disruptive action without explicit approval.

---

# 1. General principles

For every incident, the SRE Agent must:

1. Assess user and business impact before assigning severity.
2. Establish a timeline using UTC timestamps.
3. Separate confirmed facts from hypotheses.
4. Identify the affected host pools, users, session hosts, and dependencies.
5. Determine whether the problem is isolated or widespread.
6. Preserve logs and diagnostic evidence before remediation.
7. Keep the current incident owner until the receiving team accepts ownership.
8. Document every remediation action and its result.
9. Provide a rollback procedure before recommending a change.
10. Clearly state when evidence is missing or inconclusive.

The SRE Agent must never assign blame to an individual.

---

# 2. Environment and contacts

> The following contact information is synthetic and intended for
> demonstration and testing purposes only.

| Area                           | Primary team                 | Backup team                    | Contact or queue                                            | Support hours                                                  |
| ------------------------------ | ---------------------------- | ------------------------------ | ----------------------------------------------------------- | -------------------------------------------------------------- |
| AVD platform                   | Virtual Workspace Operations | Cloud Platform Operations      | Teams: `AVD Operations` / Queue: `AVD-OPS`                  | Monday-Friday, 08:00-18:00 CET                                 |
| Session hosts                  | Windows Compute Operations   | Virtual Workspace Operations   | Teams: `Windows Compute Support` / Queue: `WIN-COMPUTE`     | Monday-Friday, 07:00-19:00 CET                                 |
| FSLogix                        | End User Computing Profiles  | Virtual Workspace Operations   | Teams: `EUC Profile Support` / Queue: `FSLOGIX-SUPPORT`     | Monday-Friday, 08:00-18:00 CET                                 |
| Profile storage                | Cloud Storage Operations     | Azure Platform Engineering     | Teams: `Cloud Storage Support` / Queue: `STORAGE-OPS`       | Monday-Friday, 08:00-18:00 CET; on-call for Sev 1              |
| Identity and authentication    | Identity Operations          | Directory Services Engineering | Teams: `Identity Support` / Queue: `IDENTITY-OPS`           | 24x7 for Sev 1 and Sev 2; business hours otherwise             |
| Network                        | Cloud Network Operations     | Enterprise Network Engineering | Teams: `Cloud Network Support` / Queue: `NETWORK-OPS`       | 24x7                                                           |
| Image management               | Workplace Image Engineering  | Endpoint Management            | Teams: `AVD Image Factory` / Queue: `IMAGE-ENGINEERING`     | Monday-Friday, 09:00-17:00 CET                                 |
| Endpoint management            | Modern Workplace Operations  | Workplace Image Engineering    | Teams: `Endpoint Operations` / Queue: `ENDPOINT-OPS`        | Monday-Friday, 08:00-18:00 CET                                 |
| Security                       | Security Operations Center   | Cloud Security Engineering     | Teams: `Security Incident Response` / Queue: `SOC-INCIDENT` | 24x7                                                           |
| Azure operations               | Azure Platform Engineering   | Cloud Platform Operations      | Teams: `Azure Operations` / Queue: `AZURE-OPS`              | 24x7 for Sev 1; Monday-Friday, 08:00-18:00 CET otherwise       |
| Business applications          | Business Application Support | Virtual Workspace Operations   | Teams: `Business Apps Support` / Queue: `APP-SUPPORT`       | Monday-Friday, 08:00-18:00 CET                                 |
| Microsoft Support coordination | Cloud Vendor Management      | Azure Platform Engineering     | Queue: `MS-SUPPORT-COORDINATION`                            | Monday-Friday, 08:00-18:00 CET; emergency escalation for Sev 1 |

## Incident coordination

- Incident manager: `Major Incident Management Team`
- Technical incident lead: `Virtual Workspace Operations Lead`
- Business communication owner: `IT Service Communication Team`
- Authority for disruptive actions: `Major Incident Manager or AVD Service Owner`
- Authority for Severity 1 declaration: `Major Incident Manager`
- Authority for Microsoft Support escalation: `Azure Platform Operations Manager`
- Out-of-hours coordination: `IT Operations On-Call`
- Emergency contact method: `Major Incident Management queue`

---

# 3. Severity model

## Severity 1: Critical

Classify the incident as Severity 1 when one or more conditions apply:

- complete production AVD outage
- no users can connect to a critical environment
- all session hosts in a critical host pool are unavailable
- widespread FSLogix profile attachment failure
- multiple host pools are unavailable
- a critical business process is stopped
- a security compromise is confirmed or strongly suspected
- there is a widespread risk of data loss or profile corruption
- no viable workaround exists

Required response:

- immediate escalation
- incident manager assigned
- continuous technical coordination
- business stakeholders notified
- Microsoft Support engaged when an Azure platform issue is suspected
- disruptive remediation performed only with incident manager approval

Recommended communication interval:

```text
Every 30 minutes or after any material change
