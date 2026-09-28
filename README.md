# SecureCode AI

## Autonomous AI Code Security Agent

SecureCode AI is an AI-assisted autonomous code security system that scans Python repositories, identifies security vulnerabilities, analyzes code quality and dependencies, generates remediation patches, validates the fixes, and safely writes patched code while preserving backups of the original files.

The project combines LangGraph, Google Gemini, Python AST-based security analysis, automated remediation, and validation into a single security workflow.

## Key Features

* Repository scanning for Python files and project dependencies
* AI-assisted security vulnerability analysis
* Deterministic AST-based security checks
* Code quality analysis
* Dependency analysis
* AI-powered security review
* Autonomous vulnerability remediation
* Patch validation before writing
* Automatic backups of original files
* Gemini-based patch generation
* Local remediation fallback when AI generation is unavailable
* LangGraph-based agent orchestration

## Supported Security Checks

* CWE-78 - OS Command Injection
* CWE-95 - Eval Injection
* CWE-95 - Unsafe `exec()` usage
* CWE-502 - Unsafe Deserialization with `pickle`

## How It Works

```text
Python Repository
        |
        v
Repository Scanner
        |
        v
+-------------------+-------------------+
|                   |                   |
v                   v                   v
Security Agent   Code Agent      Dependency Agent
|                   |                   |
+-------------------+-------------------+
                    |
                    v
              Review Agent
                    |
                    v
          Is Remediation Required?
               /           \
             No             Yes
             |               |
             |               v
             |       Remediation Agent
             |         Gemini + Local
             |               |
             |               v
             |       Validator Agent
             |               |
             |               v
             |       Validation Passed?
             |          /          \
             |        No            Yes
             |        |              |
             |      Retry            v
             |                 Patch Writer
             |                      |
             |                      v
             |              Backup + Safe Patch
             |                      |
             +----------+-----------+
                        |
                        v
                Final Security Report
```

## Agent Architecture

### Repository Scanner

Scans the project directory and identifies Python source files and project requirements.

### Security Agent

Analyzes source code for known security vulnerabilities using AI-assisted analysis and deterministic local checks.

### Code Quality Agent

Checks source files for common code-quality issues such as missing documentation.

### Dependency Agent

Detects third-party Python packages and checks whether they are declared in `requirements.txt`.

### Review Agent

Combines the analysis results and determines whether the source code requires security remediation.

### Remediation Agent

Generates a secure corrected version of vulnerable code using Google Gemini. A deterministic local fallback is also available when AI-generated remediation is unavailable or fails validation.

### Validator Agent

Re-parses, compiles, and re-checks patched code to ensure the vulnerability has been removed before the patch is written.

### Patch Writer

Creates a backup of the original file and writes the validated secure patch.

## Example: CWE-95 Eval Injection

### Vulnerable Code

```python
user_input = input("Enter expression: ")

result = eval(user_input)

print("Result:", result)
```

### Remediated Code

```python
import ast

user_input = input("Enter expression: ")

result = ast.literal_eval(user_input)

print("Result:", result)
```

For mathematical expressions, the system can also generate a restricted AST-based evaluation approach that allows only explicitly approved operations.

## Example: CWE-78 OS Command Injection

### Vulnerable Pattern

```python
import subprocess

user_input = input("Enter command: ")

subprocess.call(user_input, shell=True)
```

### Remediated Code

```python
import subprocess

user_input = input("Enter command: ")

if user_input == "whoami":
    subprocess.call(["whoami"])
elif user_input == "hostname":
    subprocess.call(["hostname"])
else:
    print("Command not allowed")
```

The remediation avoids passing uncontrolled input directly to shell execution and uses explicit command allowlisting.

## Safety Mechanisms

### Validation Before Writing

Generated patches must pass validation before they are written to the source file.

### Automatic Backups

The original file is backed up before modification.

Backups are stored in:

```text
.security_backups/
```

### AI + Local Fallback

When Gemini-generated remediation is unavailable or fails validation, deterministic local remediation logic can attempt the fix.

### Security Re-Validation

The patched source code is scanned again before being accepted.

### Runtime Artifact Protection

The scanner ignores runtime and backup directories such as:

```text
venv/
.venv/
__pycache__/
.git/
.security_backups/
```

## Technology Stack

| Technology             | Purpose                                   |
| ---------------------- | ----------------------------------------- |
| Python                 | Core implementation                       |
| LangGraph              | Agent workflow orchestration              |
| Google Gemini          | AI security analysis and patch generation |
| LangChain Google GenAI | Gemini integration                        |
| Python AST             | Security analysis and validation          |
| GitPython              | Git repository support                    |
| python-dotenv          | Environment configuration                 |

## Project Structure

```text
securecode-ai/
|
+-- agents/
|   +-- code_agent.py
|   +-- dependency_agent.py
|   +-- patch_agent.py
|   +-- remediation_agent.py
|   +-- review_agent.py
|   +-- security_agent.py
|   +-- validator_agent.py
|
+-- tools/
|   +-- dependency_scanner.py
|   +-- patch_writer.py
|   +-- repository_scanner.py
|
+-- main.py
+-- requirements.txt
+-- test_vulnerable.py
+-- test_eval_vulnerable.py
+-- README.md
+-- .gitignore
```

## Installation

Clone the repository:

```bash
git clone https://github.com/sanjitha-123/securecode-ai.git
cd securecode-ai
```

Create a virtual environment:

```powershell
python -m venv venv
venv\Scripts\activate
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```env
GOOGLE_API_KEY=your_google_api_key
```

## Running the Project

Run the autonomous security workflow:

```powershell
python main.py
```

The system produces a final report containing:

* Files scanned
* Security vulnerabilities
* Code-quality findings
* Dependency findings
* Review decisions
* Remediation attempts
* Validation results
* Patch results
* Backup locations
* Patched source code
* Final security status

## Validation

The project has been tested with intentionally vulnerable Python files.

### CWE-95 Test

```text
Unsafe eval()
      |
      v
Remediation
      |
      v
Secure replacement
      |
      v
Validator
      |
      v
PASS
```

### CWE-78 Test

```text
User-controlled subprocess execution
      |
      v
Remediation
      |
      v
Allowlisted command execution
      |
      v
Validator
      |
      v
PASS
```

The complete LangGraph workflow has also been successfully executed from repository scanning through remediation, validation, and patch writing.

## Sample Result

```text
SECURITY SCAN COMPLETE

Files scanned              : 11
Security vulnerabilities   : 1
Vulnerabilities remediated : 1
Remediation attempts       : 1
Patches written            : 1
Validation failures        : 0
Backups created            : 1

STATUS: SECURITY SCAN PASSED
```

## Future Enhancements

* Support for additional CWE categories
* Deeper dependency vulnerability analysis
* Integration with static analysis tools
* Web-based security dashboard
* JSON and PDF security reports
* CI/CD integration
* Pull-request based automated remediation
* Human approval workflow before patch deployment
* Automated test generation for patched code

## Project Status

**Functional Prototype / Working Project**

SecureCode AI currently provides an autonomous security workflow capable of detecting, reviewing, remediating, validating, and safely writing security patches for supported Python vulnerabilities.

## Author

**Sanjitha Lakshmi**

GitHub: https://github.com/sanjitha-123

Project Repository: https://github.com/sanjitha-123/securecode-ai
