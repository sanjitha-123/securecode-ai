import ast
import os
import time

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

from agents.validator_agent import validator_agent


# =========================================================
# Environment / Gemini configuration
# =========================================================

load_dotenv()

API_KEY = os.getenv("GOOGLE_API_KEY")

llm = None

if API_KEY:
    try:
        llm = ChatGoogleGenerativeAI(
            model="gemini-3.6-flash",
            google_api_key=API_KEY,
        )
    except Exception:
        llm = None


# =========================================================
# Helper: extract Gemini response text
# =========================================================

def extract_response_text(content):
    """
    Convert Gemini response content into plain text.
    """

    if isinstance(content, str):
        return content.strip()

    if isinstance(content, list):

        parts = []

        for block in content:

            if isinstance(block, str):

                if block.strip():
                    parts.append(block.strip())

            elif isinstance(block, dict):

                if block.get("type") == "text":

                    text = block.get("text")

                    if isinstance(text, str) and text.strip():
                        parts.append(text.strip())

        if parts:
            return "\n".join(parts)

    return None


# =========================================================
# Helper: clean Markdown code fences
# =========================================================

def clean_patch(text):
    """
    Remove Markdown code fences from an AI-generated patch.
    """

    if not text:
        return None

    text = text.strip()

    if text.startswith("```python"):
        text = text[len("```python"):].strip()

    elif text.startswith("```"):
        text = text[len("```"):].strip()

    if text.endswith("```"):
        text = text[:-3].strip()

    return text


# =========================================================
# Local remediation fallback
# =========================================================

def local_remediation(code, review):
    """
    Deterministic local remediation fallback.

    Supported vulnerabilities:
    - CWE-78: user-controlled subprocess.call()
    - CWE-95: unsafe eval()
    """

    patched = code

    # =====================================================
    # CWE-95: Unsafe eval()
    # =====================================================

    if "CWE-95" in review and "eval(" in patched:

        patched = patched.replace(
            "eval(",
            "ast.literal_eval(",
            1,
        )

        if "import ast" not in patched:

            patched = (
                "import ast\n\n"
                + patched
            )

    # =====================================================
    # CWE-78: User-controlled subprocess.call()
    # =====================================================

    if "CWE-78" in review:

        try:
            tree = ast.parse(patched)

            for node in ast.walk(tree):

                if not isinstance(node, ast.Call):
                    continue

                if not (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"
                    and node.func.attr == "call"
                ):
                    continue

                user_controlled = False

                for arg in node.args:

                    for child in ast.walk(arg):

                        if (
                            isinstance(child, ast.Name)
                            and child.id == "user_input"
                        ):
                            user_controlled = True
                            break

                    if user_controlled:
                        break

                if not user_controlled:
                    continue

                # -------------------------------------------------
                # Existing allowed_commands form
                # -------------------------------------------------

                old_code = (
                    "allowed_commands = {\"date\", \"whoami\"}\n\n"
                    "if user_input in allowed_commands:\n"
                    "    subprocess.call([user_input])\n"
                    "else:\n"
                    "    print(\"Command not allowed\")"
                )

                new_code = (
                    "command_map = {\n"
                    "    \"whoami\": [\"whoami\"],\n"
                    "    \"hostname\": [\"hostname\"]\n"
                    "}\n\n"
                    "if user_input in command_map:\n"
                    "    subprocess.call(command_map[user_input])\n"
                    "else:\n"
                    "    print(\"Command not allowed\")"
                )

                if old_code in patched:

                    patched = patched.replace(
                        old_code,
                        new_code,
                        1,
                    )

                    break

                # -------------------------------------------------
                # allowed_commands = {"whoami", "hostname"}
                # -------------------------------------------------

                old_code = (
                    "allowed_commands = {\"whoami\", \"hostname\"}\n\n"
                    "if user_input in allowed_commands:\n"
                    "    subprocess.call([user_input])\n"
                    "else:\n"
                    "    print(\"Command not allowed\")"
                )

                if old_code in patched:

                    patched = patched.replace(
                        old_code,
                        new_code,
                        1,
                    )

                    break

                # -------------------------------------------------
                # Explicit date / whoami form
                # -------------------------------------------------

                old_code = (
                    "allowed_commands = {\"whoami\", \"date\"}\n\n"
                    "if user_input == \"date\":\n"
                    "    subprocess.call([\"date\"])\n"
                    "elif user_input == \"whoami\":\n"
                    "    subprocess.call([\"whoami\"])\n"
                    "else:\n"
                    "    print(\"Command not allowed\")"
                )

                if old_code in patched:

                    patched = patched.replace(
                        old_code,
                        new_code,
                        1,
                    )

                    break

        except SyntaxError:
            return code

    # =====================================================
    # Final syntax check
    # =====================================================

    try:
        ast.parse(patched)
        return patched
    except SyntaxError:
        return code


# =========================================================
# Gemini patch generation
# =========================================================

def generate_patch(code, review):
    """
    Ask Gemini to produce a secure corrected version.
    """

    if llm is None:
        return None

    prompt = f"""
You are the Remediation Agent in an autonomous AI code security system.

Your job is to modify vulnerable Python code so that the reported
security vulnerability is removed.

SECURITY REVIEW:
{review}

CURRENT CODE:
{code}

Rules:

1. Return ONLY the complete corrected Python source code.
2. Do not return explanations.
3. Do not use Markdown code fences.
4. Preserve the original functionality wherever safely possible.
5. Never leave the reported vulnerability in the corrected code.
6. For CWE-95 eval(), replace unsafe eval() with ast.literal_eval()
   when that is appropriate.
7. For CWE-78, never pass user-controlled input directly to
   subprocess.call().
8. Use strict allowlists for allowed OS commands.
"""

    try:

        response = llm.invoke(prompt)

        text = extract_response_text(response.content)

        return clean_patch(text)

    except Exception:

        return None


# =========================================================
# Main remediation agent
# =========================================================

def remediation_agent(code, review):
    """
    Autonomous remediation workflow.

    Flow:
        Gemini patch
        -> validation
        -> local fallback if validation fails
        -> retry up to 3 times
    """

    max_attempts = 3

    patched_code = code

    validation = {
        "valid": False,
        "message": "Remediation was not completed.",
    }

    for attempt in range(1, max_attempts + 1):

        print(
            f"\n[Remediation] Attempt {attempt}/{max_attempts}"
        )

        # =====================================================
        # Generate AI patch
        # =====================================================

        ai_patch = generate_patch(
            patched_code,
            review,
        )

        if ai_patch:

            patched_code = ai_patch

            print("[Remediation] Patch generated.")

        else:

            print(
                "[Remediation] Gemini patch unavailable."
            )

        # =====================================================
        # Validate Gemini patch
        # =====================================================

        try:

            validation = validator_agent(
                patched_code
            )

        except Exception as e:

            validation = {
                "valid": False,
                "message": (
                    f"Validation error: {e}"
                ),
            }

        print(
            "[Remediation] Validation:",
            validation.get("valid", False),
        )

        # =====================================================
        # Successful validation
        # =====================================================

        if validation.get("valid"):

            return {
                "success": True,
                "attempts": attempt,
                "validation": validation,
                "patched_code": patched_code,
            }

        print(
            "[Remediation] Patch rejected:",
            validation.get("message", "Validation failed."),
        )

        # =====================================================
        # Local fallback
        # =====================================================

        print(
            "[Remediation] Trying local remediation fallback..."
        )

        local_patch = local_remediation(
            code,
            review,
        )

        if local_patch != code:

            try:

                local_validation = validator_agent(
                    local_patch
                )

            except Exception as e:

                local_validation = {
                    "valid": False,
                    "message": (
                        f"Validation error: {e}"
                    ),
                }

            print(
                "[Remediation] Local fallback validation:",
                local_validation.get("valid", False),
            )

            if local_validation.get("valid"):

                return {
                    "success": True,
                    "attempts": attempt,
                    "validation": local_validation,
                    "patched_code": local_patch,
                }

            print(
                "[Remediation] Local fallback rejected:",
                local_validation.get(
                    "message",
                    "Validation failed.",
                ),
            )

            validation = local_validation

        else:

            print(
                "[Remediation] Local fallback did not produce a new patch."
            )

        # =====================================================
        # Small delay before next attempt
        # =====================================================

        if attempt < max_attempts:
            time.sleep(1)

    # =========================================================
    # Remediation failed
    # =========================================================

    return {
        "success": False,
        "attempts": max_attempts,
        "validation": validation,
        "patched_code": code,
    }
