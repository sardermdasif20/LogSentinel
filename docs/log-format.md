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