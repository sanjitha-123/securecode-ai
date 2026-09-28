import ast
import os
import time

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI


load_dotenv()

API_KEY = os.getenv("GOOGLE_API_KEY")

llm = None

if API_KEY:
    try:
        llm = ChatGoogleGenerativeAI(
            model="gemini-3.8-flash",
            google_api_key=API_KEY
        )
    except Exception:
        llm = None


def is_fixed_command_map(tree):

    maps = set()

    for node in ast.walk(tree):

        if not isinstance(node, ast.Assign):
            continue

        if not isinstance(node.value, ast.Dict):
            continue

        valid = True

        for key, value in zip(
            node.value.keys,
            node.value.values
        ):

            if not isinstance(key, ast.Constant):
                valid = False
                break

            if not isinstance(value, (ast.List, ast.Tuple)):
                valid = False
                break

            for item in value.elts:

                if not isinstance(item, ast.Constant):
                    valid = False
                    break

            if not valid:
                break

        if valid:

            for target in node.targets:

                if isinstance(target, ast.Name):
                    maps.add(target.id)

    return maps


def contains_user_input(node):

    for child in ast.walk(node):

        if (
            isinstance(child, ast.Name)
            and child.id == "user_input"
        ):
            return True

    return False


def local_security_check(code, reason=""):

    findings = []

    try:
        tree = ast.parse(code)

    except SyntaxError as error:

        return (
            "Syntax error during security analysis: "
            + str(error)
        )

    command_maps = is_fixed_command_map(tree)

    for node in ast.walk(tree):

        if not isinstance(node, ast.Call):
            continue

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr == "call"
        ):

            shell_true = False

            for keyword in node.keywords:

                if (
                    keyword.arg == "shell"
                    and isinstance(
                        keyword.value,
                        ast.Constant
                    )
                    and keyword.value.value is True
                ):

                    shell_true = True

            if shell_true:

                findings.append(
                    "Vulnerability: OS Command Injection\n"
                    "CWE: CWE-78\n"
                    "Severity: High\n"
                    "Reason: subprocess.call() uses shell=True."
                )

                continue

            if not node.args:

                findings.append(
                    "Vulnerability: Unsafe subprocess usage\n"
                    "CWE: CWE-78\n"
                    "Severity: High"
                )

                continue

            command = node.args[0]

            if (
                isinstance(command, ast.Subscript)
                and isinstance(command.value, ast.Name)
                and command.value.id in command_maps
            ):

                continue

            if contains_user_input(command):

                findings.append(
                    "Vulnerability: OS Command Injection\n"
                    "CWE: CWE-78\n"
                    "Severity: High\n"
                    "Reason: User-controlled input reaches "
                    "subprocess.call()."
                )

        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "eval"
        ):

            findings.append(
                "Vulnerability: Code Injection\n"
                "CWE: CWE-95\n"
                "Severity: Critical\n"
                "Reason: eval() can execute arbitrary Python code."
            )

        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "exec"
        ):

            findings.append(
                "Vulnerability: Code Injection\n"
                "CWE: CWE-95\n"
                "Severity: Critical\n"
                "Reason: exec() can execute arbitrary Python code."
            )

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pickle"
            and node.func.attr == "loads"
        ):

            findings.append(
                "Vulnerability: Unsafe Deserialization\n"
                "CWE: CWE-502\n"
                "Severity: Critical\n"
                "Reason: pickle.loads() can execute malicious data."
            )

    findings = list(dict.fromkeys(findings))

    if findings:
        return "\n\n".join(findings)

    return (
        "No known security vulnerability was detected "
        "by the local security checks."
    )


def extract_response_text(content):

    if isinstance(content, str):

        if content.strip():
            return content.strip()

    if isinstance(content, list):

        text_parts = []

        for item in content:

            if isinstance(item, str):

                if item.strip():
                    text_parts.append(item.strip())

            elif isinstance(item, dict):

                if item.get("type") == "text":

                    text = item.get("text", "")

                    if isinstance(text, str) and text.strip():
                        text_parts.append(text.strip())

        if text_parts:
            return "\n".join(text_parts)

    return None


def security_agent(code):

    if llm is None:

        return local_security_check(
            code,
            "Gemini unavailable"
        )

    prompt = (
        "You are the Security Agent of an autonomous "
        "code security system.\n\n"
        "Analyze the following Python code.\n\n"
        "Identify:\n"
        "- Security vulnerability\n"
        "- CWE\n"
        "- Severity\n"
        "- Reason\n"
        "- Recommended fix\n\n"
        "Do not invent vulnerabilities.\n\n"
        "For subprocess.call():\n"
        "- Direct user-controlled commands are vulnerable.\n"
        "- shell=True with untrusted input is vulnerable.\n"
        "- A fixed command map selected by user input is safe.\n\n"
        "Code:\n\n"
        + code
    )

    for attempt in range(3):

        try:

            response = llm.invoke(prompt)

            result = extract_response_text(
                response.content
            )

            if result:
                return result

            return local_security_check(
                code,
                "Gemini returned an empty response"
            )

        except Exception as error:

            error_text = str(error).lower()

            is_rate_limit = (
                "429" in error_text
                or "rate limit" in error_text
                or "ratelimit" in error_text
            )

            if is_rate_limit and attempt < 2:

                time.sleep(
                    2 ** attempt
                )

                continue

            return local_security_check(
                code,
                type(error).__name__
            )

    return local_security_check(
        code,
        "Gemini failed"
    )