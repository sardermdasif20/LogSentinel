# LogSentinel

**Security Log Analysis & Threat Detection Platform**

LogSentinel is a Python-based defensive cybersecurity project that transforms raw security logs into structured events, identifies suspicious login activity using explainable detection rules, calculates security analytics, and generates JSON investigation reports.

The project demonstrates practical skills in cybersecurity, Python software engineering, data analysis, automated testing, and command-line application development.

## Key Features

- **Log ingestion:** Read security log files using UTF-8 encoding.
- **Structured parsing:** Convert raw log lines into validated security events.
- **Event classification:** Assign severity classifications to security events.
- **Rule-based detection:** Identify suspicious login patterns using deterministic rules.
- **Security analytics:** Summarize events, findings, and source IP activity.
- **Investigation reports:** Generate structured JSON reports containing events, findings, statistics, and parsing errors.
- **Command-line interface:** Analyze a log file and save a report using configurable input and output paths.
- **Automated testing:** Validate core functionality with pytest.

## Detection Rules

| Rule ID | Detection | Purpose |
|---|---|---|
| DET001 | Repeated failed logins | Identify repeated authentication failures. |
| DET002 | Possible password spraying | Identify patterns of failed authentication involving multiple accounts. |
| DET003 | Successful login after repeated failures | Highlight a successful login following repeated failures. |

These rules are deterministic and explainable. A finding indicates activity that deserves investigation; it does not, by itself, prove that an account has been compromised.

## How It Works

```text
Raw Security Logs
        |
        v
   Log Ingestion
        |
        v
    Log Parser
        |
        v
Structured Security Events
        |
        +-------------------+
        |                   |
        v                   v
Event Classification   Detection Rules
        |                   |
        +---------+---------+
                  |
                  v
          Security Analytics
                  |
                  v
       Investigation Report
                  |
                  v
             JSON Output
```

Malformed log lines are recorded as parsing errors so they can be investigated instead of silently disappearing.

## Technology Stack

- **Language:** Python 3.12+
- **Testing:** pytest
- **Data format:** Structured log records and JSON reports
- **Build and packaging:** Python project configuration with `pyproject.toml`
- **Version control:** Git and GitHub
- **Automation:** GitHub Actions workflow directory

The current implementation uses Python's standard library for report generation and JSON export. The project is designed to evolve incrementally without unnecessary dependencies.

## Getting Started

### Prerequisites

- Python 3.12 or newer
- Git
- Windows PowerShell, or a compatible terminal

### 1. Clone the repository

```powershell
git clone https://github.com/sardermdasif20/LogSentinel.git
cd LogSentinel
```

### 2. Create a virtual environment

```powershell
py -m venv .venv
```

### 3. Activate the environment

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can use this temporary policy for the current terminal session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

### 4. Install the project

```powershell
python -m pip install --upgrade pip
python -m pip install -e .
```

### 5. Run LogSentinel

Analyze the included sample log:

```powershell
python -m logsentinel.main
```

The default input is `examples/sample_security.log`. The default output is `investigation_report.json`.

To specify paths explicitly:

```powershell
python -m logsentinel.main --input examples/sample_security.log --output investigation_report.json
```

The command prints a summary of the analysis and saves the detailed JSON report to the selected output path.

### 6. Run the tests

Install pytest if it is not already available:

```powershell
python -m pip install pytest
```

Run the complete test suite:

```powershell
python -m pytest
```

The current development checkpoint has **92 passing tests**. Test results may change as the project evolves.

## Example Output

Using the included sample dataset, the CLI currently reports a summary similar to:

```text
LogSentinel — Security Investigation Report
============================================
Input file:       examples/sample_security.log
Output file:      investigation_report.json
Events analyzed:  16
Findings:         1
Unique source IPs: 6
Parse errors:     0

Findings:
  [HIGH] DET001 — Repeated Failed Logins
    Source IP: 192.168.1.50
```

The exact formatting and finding descriptions may evolve as the implementation improves.

The JSON report includes:

- Report metadata and generation timestamp
- Summary analytics
- Parsed security events and their severity classifications
- Detection findings and associated evidence
- Parsing errors, including line numbers and raw input

## Project Structure

```text
LogSentinel/
├── .github/
│   └── workflows/
├── docs/
│   └── log-format.md
├── examples/
│   └── sample_security.log
├── src/
│   └── logsentinel/
│       ├── main.py
│       ├── models.py
│       ├── ingestion.py
│       ├── parser.py
│       ├── classifier.py
│       ├── detector.py
│       ├── analytics.py
│       └── reporting.py
├── tests/
├── .gitignore
├── pyproject.toml
└── README.md
```

## Current Development Status

**Implemented**

- Security event models
- Log ingestion and parsing
- Event classification
- Three deterministic detection rules
- Security analytics and statistics
- JSON investigation report generation
- Command-line interface
- Automated tests for the core components, reporting, and CLI

**Planned**

- Persistent storage and historical investigations
- Additional log formats and detection rules
- CSV report export
- REST API
- Web dashboard
- Additional security hardening and operational improvements

Planned capabilities are not yet part of the current implementation.

## Security and Limitations

LogSentinel is a learning and portfolio project for defensive log analysis. Its detection rules are based on predefined conditions, so they may produce false positives or miss activity that does not match those conditions.

- A detection finding is an investigative lead, not proof of an attack.
- Detection quality depends on the completeness and quality of the input logs.
- The current version is not a replacement for a production SIEM or incident-response platform.
- Review generated reports before using them in operational decisions.
- Avoid committing real credentials, personal data, or confidential security logs to a public repository.

## Development Workflow

The project follows an incremental workflow:

```text
Implement
   |
   v
Test
   |
   v
Review
   |
   v
Commit
   |
   v
Push
```

Correctness, maintainability, explainability, and testability are core development priorities.

## Author

**MD ASIF SARDER**

GitHub: https://github.com/sardermdasif20

## License

No license has been specified yet. Check the repository for licensing information before reusing or redistributing the code.
