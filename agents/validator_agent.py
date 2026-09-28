import ast
import os
import subprocess
import sys
import tempfile


def find_fixed_command_maps(tree):
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

            if not isinstance(
                value,
                (ast.List, ast.Tuple)
            ):
                valid = False
                break

            for item in value.elts:

                if not isinstance(
                    item,
                    ast.Constant
                ):
                    valid = False
                    break

            if not valid:
                break

        if valid:

            for target in node.targets:

                if isinstance(target, ast.Name):
                    maps.add(target.id)

    return maps


def detect_security_vulnerabilities(code):

    findings = []

    try:
        tree = ast.parse(code)

    except SyntaxError:
        return [
            "Syntax error prevents security validation."
        ]

    fixed_command_maps = find_fixed_command_maps(tree)

    for node in ast.walk(tree):

        if not isinstance(node, ast.Call):
            continue

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr == "call"
        ):

            shell_true = any(
                keyword.arg == "shell"
                and isinstance(
                    keyword.value,
                    ast.Constant
                )
                and keyword.value.value is True
                for keyword in node.keywords
            )

            if shell_true:

                findings.append(
                    "CWE-78: OS Command Injection "
                    "(subprocess.call with shell=True)"
                )

                continue

            if not node.args:

                findings.append(
                    "CWE-78: Unsafe subprocess.call() "
                    "without a command argument"
                )

                continue

            command = node.args[0]

            if (
                isinstance(command, ast.Subscript)
                and isinstance(
                    command.value,
                    ast.Name
                )
                and command.value.id in fixed_command_maps
            ):
                continue

            user_controlled = False

            for child in ast.walk(command):

                if (
                    isinstance(child, ast.Name)
                    and child.id == "user_input"
                ):

                    user_controlled = True
                    break

            if user_controlled:

                findings.append(
                    "CWE-78: OS Command Injection "
                    "(user-controlled input passed "
                    "to subprocess.call)"
                )

        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "eval"
        ):

            findings.append(
                "CWE-95: Unsafe eval() usage"
            )

        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "exec"
        ):

            findings.append(
                "CWE-95: Unsafe exec() usage"
            )

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pickle"
            and node.func.attr == "loads"
        ):

            findings.append(
                "CWE-502: Unsafe pickle deserialization"
            )

    return list(
        dict.fromkeys(findings)
    )


def validator_agent(
    code,
    original_code=None
):

    temp_path = None

    try:

        ast.parse(code)

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8"
        ) as temp_file:

            temp_file.write(code)
            temp_path = temp_file.name

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "py_compile",
                temp_path
            ],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:

            return {
                "valid": False,
                "message": (
                    "Compilation failed: "
                    + result.stderr
                )
            }

        security_findings = (
            detect_security_vulnerabilities(code)
        )

        if security_findings:

            return {
                "valid": False,
                "message": (
                    "Validation failed: security "
                    "vulnerabilities are still present.\n"
                    + "\n".join(
                        "- " + finding
                        for finding in security_findings
                    )
                )
            }

        if original_code is not None:

            original_findings = (
                detect_security_vulnerabilities(
                    original_code
                )
            )

            patched_findings = (
                detect_security_vulnerabilities(code)
            )

            if (
                original_findings
                and patched_findings
            ):

                return {
                    "valid": False,
                    "message": (
                        "Validation failed: the security "
                        "vulnerability detected in the "
                        "original code is still present "
                        "after remediation."
                    )
                }

        return {
            "valid": True,
            "message": (
                "Patched code passed syntax, compilation, "
                "and security re-validation."
            )
        }

    except SyntaxError as error:

        return {
            "valid": False,
            "message": (
                "Syntax error: "
                + str(error)
            )
        }

    except Exception as error:

        return {
            "valid": False,
            "message": (
                "Validation error: "
                + str(error)
            )
        }

    finally:

        if (
            temp_path
            and os.path.exists(temp_path)
        ):

            try:
                os.remove(temp_path)
            except OSError:
                pass