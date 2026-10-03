# LogSentinel Log Format

## Overview

LogSentinel uses a structured text log format for the first version of the project.

Each log line represents one security-related event.

The purpose of this format is to provide a consistent input for:

- Log ingestion
- Log parsing
- Event validation
- Security analysis
- Threat detection
- Statistics
- Reporting

## Log Structure

Each event contains seven fields separated by the pipe (`|`) character:

```text
timestamp | source | event_type | username | source_ip | status | message
```

Fields may contain surrounding whitespace. The parser removes surrounding whitespace from each field before validation.

## Fields

### 1. timestamp

The event timestamp must use ISO 8601 format.

Example:

```text
2026-10-03T08:14:22Z
```

The parser converts valid timestamps into Python `datetime` objects.

### 2. source

Identifies the system or component that generated the event.

Examples:

```text
server01
server02
firewall01
```

The field must not be empty.

### 3. event_type

The event type must be one of the supported values:

```text
LOGIN_SUCCESS
LOGIN_FAILURE
ACCOUNT_LOCK
PASSWORD_CHANGE
PRIVILEGE_CHANGE
FILE_ACCESS
CONNECTION
```

### 4. username

Identifies the account associated with the event.

Examples:

```text
alice
bob
charlie
```

For events where a user account is not applicable, the value `-` may be used.

### 5. source_ip

Identifies the source IPv4 address associated with the event.

Example:

```text
192.168.1.50
```

The parser validates that the value is a valid IPv4 address.

For the first version of LogSentinel, IPv6 is not supported.

### 6. status

The status must be one of the supported values:

```text
SUCCESS
FAILURE
INFO
WARNING
```

### 7. message

Contains a human-readable description of the event.

Example:

```text
Invalid password
```

The message must not be empty.

## Validation Rules

A valid log line must:

1. Contain exactly seven fields.
2. Contain a valid ISO 8601 timestamp.
3. Contain a non-empty source.
4. Contain a supported event type.
5. Contain a username or `-`.
6. Contain a valid IPv4 address.
7. Contain a supported status.
8. Contain a non-empty message.

Invalid lines must produce a controlled parser error.

A malformed event must not cause the entire log-analysis process to crash when the application processes a larger log file.

## Example Valid Events

```text
2026-10-03T08:12:04Z | server01 | LOGIN_SUCCESS | alice | 192.168.1.20 | SUCCESS | User authentication successful

2026-10-03T08:18:02Z | server01 | ACCOUNT_LOCK | alice | 192.168.1.50 | WARNING | Account locked after repeated authentication failures

2026-10-03T10:10:45Z | firewall01 | CONNECTION | - | 10.0.0.45 | INFO | Outbound connection established
```

## Example Invalid Events

### Wrong number of fields

```text
2026-10-03T08:14:22Z | server01 | LOGIN_FAILURE | alice
```

### Unsupported event type

```text
2026-10-03T08:14:22Z | server01 | UNKNOWN_EVENT | alice | 192.168.1.50 | FAILURE | Invalid password
```

### Invalid IPv4 address

```text
2026-10-03T08:14:22Z | server01 | LOGIN_FAILURE | alice | 999.999.999.999 | FAILURE | Invalid password
```

### Unsupported status

```text
2026-10-03T08:14:22Z | server01 | LOGIN_FAILURE | alice | 192.168.1.50 | ERROR | Invalid password
```

### Empty message

```text
2026-10-03T08:14:22Z | server01 | LOGIN_FAILURE | alice | 192.168.1.50 | FAILURE |
```

## Parser Behavior

The parser processes one raw log line at a time.

Processing flow:

```text
Raw Line
   │
   ▼
Remove Line Ending
   │
   ▼
Split Into 7 Fields
   │
   ▼
Trim Field Whitespace
   │
   ▼
Validate Fields
   │
   ├── Invalid ──► Parser Error
   │
   └── Valid
          │
          ▼
   Create SecurityEvent
```

The parser is responsible for converting valid raw text into a `SecurityEvent`.

The parser does not perform threat detection. Threat detection belongs to the Detection Engine phase.

