import ast
import os
import re
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


def valid_python(code):
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def extract_response_text(content):

    if isinstance(content, str):

        if content.strip():
            return content.strip()

    if isinstance(content, list):

        text_parts = []

        for item in content:

            if isinstance(item, str):

                if item.strip():
                    text_parts.append(
                        item.strip()
                    )

            elif isinstance(item, dict):

                if item.get("type") == "text":

                    text = item.get(
                        "text",
                        ""
                    )

                    if (
                        isinstance(text, str)
                        and text.strip()
                    ):
                        text_parts.append(
                            text.strip()
                        )

        if text_parts:
            return "\n".join(text_parts)

    return None


def clean_response(text):

    if not text:
        return ""

    text = text.strip()

    text = re.sub(
        r"^```python\s*",
        "",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r"^```\s*",
        "",
        text
    )

    text = re.sub(
        r"\s*```$",
        "",
        text
    )

    return text.strip()


def extract_allowed_commands(code):

    try:
        tree = ast.parse(code)

    except SyntaxError:
        return []

    commands = []

    for node in ast.walk(tree):

        if not isinstance(node, ast.Assign):
            continue

        if not isinstance(node.value, ast.Set):
            continue

        variable_name = None

        for target in node.targets:

            if (
                isinstance(target, ast.Name)
                and target.id == "allowed_commands"
            ):
                variable_name = target.id
                break

        if variable_name is None:
            continue

        for element in node.value.elts:

            if isinstance(element, ast.Constant):

                if isinstance(element.value, str):

                    commands.append(
                        element.value
                    )

    return commands


def build_command_map_patch(code, commands):

    if not commands:
        return code

    command_map_lines = [
        "command_map = {"
    ]

    for command in commands:

        escaped = command.replace(
            "\\",
            "\\\\"
        ).replace(
            "\"",
            "\\\""
        )

        command_map_lines.append(
            f'    "{escaped}": ["{escaped}"],'
        )

    command_map_lines.append("}")

    new_block = (
        "\n".join(command_map_lines)
        + "\n\n"
        "if user_input in command_map:\n"
        "    subprocess.call(command_map[user_input])\n"
        "else:\n"
        "    print(\"Command not allowed\")"
    )

    patterns = [
        re.compile(
            r'allowed_commands\s*=\s*\{[^}]*\}\s*'
            r'if\s+user_input\s+in\s+allowed_commands\s*:\s*'
            r'subprocess\.call\(\[user_input\]\)\s*'
            r'else\s*:\s*'
            r'print\("Command not allowed"\)',
            re.MULTILINE
        ),

        re.compile(
            r'if\s+user_input\s+in\s+allowed_commands\s*:\s*'
            r'subprocess\.call\(\[user_input\]\)\s*'
            r'else\s*:\s*'
            r'print\("Command not allowed"\)',
            re.MULTILINE
        )
    ]

    for pattern in patterns:

        patched = pattern.sub(
            new_block,
            code,
            count=1
        )

        if patched != code and valid_python(patched):
            return patched

    return code


def local_patch(code):

    commands = extract_allowed_commands(code)

    if commands:

        patched = build_command_map_patch(
            code,
            commands
        )

        if patched != code and valid_python(patched):
            return patched

    return code


def patch_agent(code, review):

    # Deterministic safety-first remediation for the
    # known command-injection pattern.
    deterministic_patch = local_patch(code)

    if deterministic_patch != code:

        return deterministic_patch

    prompt = (
        "You are the Patch Agent in an autonomous "
        "code security system.\n\n"
        "Original Python code:\n\n"
        "<original_code>\n"
        + code
        + "\n</original_code>\n\n"
        "Security review:\n\n"
        "<security_review>\n"
        + review
        + "\n</security_review>\n\n"
        "Return the complete corrected Python program.\n\n"
        "Rules:\n"
        "1. Fix the confirmed security vulnerability.\n"
        "2. Preserve the original program's functionality.\n"
        "3. Preserve existing allowed commands and their behavior.\n"
        "4. Do not invent replacement commands such as date, "
        "hostname, or whoami unless they already exist in the "
        "original program.\n"
        "5. Never use shell=True with user-controlled input.\n"
        "6. Never pass raw user input directly to subprocess.\n"
        "7. Use a fixed allowlist or fixed command map when "
        "command execution is required.\n"
        "8. Return syntactically valid Python.\n"
        "9. Return Python only.\n"
        "10. Do not use Markdown code fences.\n"
    )

    if llm is not None:

        for attempt in range(3):

            try:

                response = llm.invoke(
                    prompt
                )

                response_text = extract_response_text(
                    response.content
                )

                patched = clean_response(
                    response_text
                )

                if valid_python(patched):

                    return patched

                deterministic_patch = local_patch(
                    code
                )

                if deterministic_patch != code:
                    return deterministic_patch

                return code

            except Exception as error:

                error_text = str(
                    error
                ).lower()

                is_rate_limit = (
                    "429" in error_text
                    or "rate limit" in error_text
                    or "ratelimit" in error_text
                )

                if (
                    is_rate_limit
                    and attempt < 2
                ):

                    time.sleep(
                        2 ** attempt
                    )

                    continue

                break

    return local_patch(code)