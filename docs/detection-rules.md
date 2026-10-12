# LogSentinel Detection Rules

This document describes the deterministic detection rules currently implemented in `src/logsentinel/detector.py`.

All three rules analyze authentication events and produce security findings with a `HIGH` severity classification when their conditions are met.

A finding identifies activity worth investigating. It does not independently establish that an attack occurred.

## DET001 — Repeated Failed Logins

### Purpose

Identify a source IP address associated with repeated failed login attempts within a short time window.

This pattern may indicate brute-force activity, automated credential guessing, or repeated authentication mistakes.

### Default trigger conditions

- Event type is `LOGIN_FAILURE`.
- Event status is `FAILURE`.
- At least 5 qualifying failed login events originate from the same source IP.
- The qualifying events occur within a 10-minute window.

The function accepts configurable `threshold` and `window_minutes` parameters.

### Evidence produced

The finding includes:

- Rule ID and name
- Severity
- Source IP address
- Number of matching failed login events
- Configured time window
- First and last timestamps in the matching window
- A description of the detected activity

### Limitations

- The rule groups events by source IP, not by username.
- Multiple legitimate users behind a shared network address may contribute to the same count.
- Distributed attempts from several IP addresses may not meet the per-IP threshold.
- The finding does not establish whether any account was compromised.

## DET002 — Possible Password Spraying

### Purpose

Identify a source IP address that records failed login attempts against multiple distinct usernames within a short time window.

Password spraying typically involves trying one or a small number of passwords against many accounts. The current rule detects a pattern consistent with that activity; it does not inspect the passwords used.

### Default trigger conditions

- Event type is `LOGIN_FAILURE`.
- Event status is `FAILURE`.
- Failed login events originate from the same source IP.
- At least 5 distinct usernames appear among the matching events within a 10-minute window.

The function accepts configurable `username_threshold` and `window_minutes` parameters.

### Evidence produced

The finding includes:

- Rule ID and name
- Severity
- Source IP address
- Number of failed login events in the matching window
- Configured time window
- First and last timestamps in the matching window
- A description reporting the number of distinct usernames targeted

### Limitations

- The implementation counts distinct usernames, not distinct passwords.
- Repeated failures against one username do not satisfy the default distinct-username threshold by themselves.
- Legitimate authentication problems affecting multiple accounts can produce a finding.
- Attempts distributed across multiple source IP addresses may evade this per-IP rule.
- A matching pattern alone does not prove password spraying occurred.

## DET003 — Successful Login After Repeated Failures

### Purpose

Highlight a successful login when the same username and source IP previously recorded multiple failed login attempts within a short period.

This sequence may deserve investigation because it can be consistent with successful credential guessing or a user eventually entering the correct credentials.

### Default trigger conditions

- Failed events have type `LOGIN_FAILURE` and status `FAILURE`.
- A successful event has type `LOGIN_SUCCESS` and status `SUCCESS`.
- Failed and successful events share the same username and source IP address.
- At least 3 qualifying failures occurred strictly before the successful login.
- Each qualifying failure is no more than 10 minutes before that success.

The function accepts configurable `threshold` and `window_minutes` parameters.

### Evidence produced

The finding includes:

- Rule ID and name
- Severity
- Source IP address
- Number of matching failed login attempts
- Configured time window
- Timestamp of the earliest matching failure
- Timestamp of the successful login
- A description identifying the account and source IP

### Limitations

- Failures for other usernames or source IP addresses do not contribute to the count.
- A successful login without enough preceding failures does not trigger this rule.
- Legitimate users who mistype their passwords several times may trigger a finding.
- The rule does not verify whether the successful login was authorized or whether the account was compromised.

## Implementation Notes

- All three rules use configurable thresholds and time windows with the defaults documented above.
- Each rule rejects threshold values below 1 and time windows below 1 minute by raising `ValueError`.
- Events are ordered by timestamp before the relevant time-window checks.
- DET001 and DET002 produce at most one finding per source IP per function call.
- DET003 produces at most one finding per username/source-IP pair per function call.
- Findings are based on the supplied event collection. Missing, malformed, delayed, or incomplete log data can affect detection results.
- The rules are deterministic: the same events and configuration produce the same detection decisions.

## Responsible Use

LogSentinel is a defensive log-analysis and learning project. Use findings as investigation leads, validate them against additional evidence, and consider legitimate explanations before drawing conclusions.

The current rules are not a replacement for a production SIEM, comprehensive monitoring, or a formal incident-response process.
