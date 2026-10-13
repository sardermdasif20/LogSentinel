# LogSentinel

**Security Log Analysis & Threat Detection Platform**

LogSentinel is a Python-based defensive cybersecurity tool that transforms raw security logs into structured events, detects suspicious authentication patterns, calculates security analytics, and generates JSON investigation reports with supporting evidence.

Built as a portfolio project, LogSentinel demonstrates practical skills in cybersecurity, Python development, data analysis, software testing, and command-line application design.

## Key Features

* **Log ingestion:** Read security log files using UTF-8 encoding.
* **Structured parsing:** Convert raw log records into validated security events.
* **Event classification:** Assign severity classifications to security events.
* **Rule-based threat detection:** Identify suspicious authentication patterns using deterministic, explainable rules.
* **Security analytics:** Summarize events, findings, and source IP activity.
* **Investigation reports:** Export events, findings, statistics, and parsing errors to JSON.
* **Command-line interface:** Configure input files, output paths, terminal formats, and analysis options.
* **Error handling:** Report missing input files and other supported processing errors clearly.
* **Automated quality checks:** Use pytest and Ruff to support reliable, maintainable development.
* **Continuous integration:** Run automated quality checks through GitHub Actions.

## Detection Rules

| Rule ID | Detection                                | Purpose                                                                                  |
| ------- | ---------------------------------------- | ---------------------------------------------------------------------------------------- |
| DET001  | Repeated failed logins                   | Identify repeated authentication failures from a source IP.                              |
| DET002  | Possible password spraying               | Identify failed authentication patterns involving multiple accounts.                     |
| DET003  | Successful login after repeated failures | Flag a successful login following repeated failures from the same account and source IP. |

The rules use deterministic conditions and produce explainable findings. A finding is an investigative lead, not proof that an attack or account compromise occurred.

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
        v
Event Classification
        |
        v
 Rule-Based Detection
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

Malformed log lines are recorded as parsing errors, allowing users to investigate data-quality issues rather than silently losing visibility into them.

## Technology Stack

* **Language:** Python 3.12+
* **Testing:** pytest
* **Code quality:** Ruff
* **Data formats:** Security log records and JSON reports
* **Project configuration:** `pyproject.toml`
* **Version control:** Git and GitHub
* **Continuous integration:** GitHub Actions

The current implementation uses Python's standard library for core processing and JSON export, with pytest and Ruff used for development quality checks.

## Getting Started

### Prerequisites

* Python 3.12 or newer
* Git
* Windows PowerShell or another compatible terminal

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

In Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, allow it for the current terminal session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

### 4. Install the project and development tools

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### 5. Run LogSentinel

Analyze the included sample dataset:

```powershell
python -m logsentinel.main
```

By default, LogSentinel reads `examples/sample_security.log` and writes the report to `investigation_report.json`.

### Command-line options

**Choose an input file and output location:**

```powershell
python -m logsentinel.main --input examples/sample_security.log --output investigation_report.json
```

**Print the report as JSON in the terminal:**

```powershell
python -m logsentinel.main --format json
```

**Show the ten most active source IPs:**

```powershell
python -m logsentinel.main --top-ips 10
```

**Return exit code 2 when findings are detected:**

```powershell
python -m logsentinel.main --fail-on-findings
```

This option is useful when integrating LogSentinel into scripts or automated workflows. An exit code of 2 indicates that findings were detected when this option was enabled.

**Display all available options and examples:**

```powershell
python -m logsentinel.main --help
```

### 6. Run the tests

Run the complete test suite:

```powershell
python -m pytest -q
```

At the latest verified development checkpoint, **119 tests passed**. This count describes that checkpoint; future changes may alter the result.

Run the code-quality checks:

```powershell
python -m ruff check .
python -m ruff format --check .
```

## Example Output

The included sample dataset currently produces a summary similar to this:

```text
LogSentinel - Security Investigation Report
============================================
Input file:       examples\sample_security.log
Output file:      investigation_report.json
Events analyzed:  16
Findings:         1
Unique source IPs: 6
Parse errors:     0

Findings:
  [HIGH] DET001 - Repeated Failed Logins
    Source IP: 192.168.1.50
    5 failed login attempts from 192.168.1.50 within 10 minutes.

Report generated successfully.
```

The exact output may change as the implementation evolves.

The generated JSON report includes summary analytics, parsed security events, detection findings, supporting evidence, and parsing errors.

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

* Security event models and log ingestion
* Structured parsing and event classification
* Three deterministic detection rules
* Security analytics and statistics
* JSON investigation report generation
* Configurable command-line interface
* Automated tests for core functionality, reporting, and CLI behavior
* Automated code-quality checks and CI workflow

**Potential future enhancements**

* Persistent storage and historical investigations
* Additional log formats and detection rules
* CSV report export
* REST API
* Web dashboard
* Further security hardening and operational improvements

These enhancements are potential future work, not claims about existing functionality.

## Security and Limitations

LogSentinel is a learning and portfolio project for defensive security analysis. Its rule-based detections may produce false positives or miss activity that does not match the configured conditions.

* Findings should be investigated rather than treated as proof of malicious activity.
* Detection quality depends on the completeness and quality of input logs.
* The project is not a replacement for a production SIEM or incident-response platform.
* Review generated reports before making operational decisions.
* Do not commit credentials, personal data, or confidential security logs to a public repository.

## Development Workflow

The project follows an incremental engineering workflow:

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

Maintainability, correctness, explainability, and testability are core development priorities.

## Author

**MD ASIF SARDER**

GitHub: https://github.com/sardermdasif20

## License

No license has been specified in this README. Unless a license is added to the repository, others should not assume they have permission to reuse, modify, or redistribute the code.
