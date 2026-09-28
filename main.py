from typing import TypedDict

from langgraph.graph import StateGraph, END

from tools.dependency_scanner import scan_requirements
from tools.repository_scanner import scan_repository
from tools.patch_writer import write_patch

from agents.security_agent import security_agent
from agents.code_agent import code_agent
from agents.dependency_agent import dependency_agent
from agents.review_agent import review_agent
from agents.remediation_agent import remediation_agent


class SecurityState(TypedDict, total=False):
    repository_path: str
    files: list
    requirements: list
    results: list


def run_repository_scanner(state):
    """
    Scans the repository for Python files and project requirements.

    Args:
        state (SecurityState): The current graph state containing the repository path.

    Returns:
        SecurityState: Updated state containing lists of files and requirements.
    """
    files = scan_repository(
        state["repository_path"]
    )

    requirements = scan_requirements(
        state["repository_path"]
    )

    state["files"] = files
    state["requirements"] = requirements
    state["results"] = []

    print(
        f"Python files found: {len(files)}"
    )

    print(
        f"Dependencies found: {len(requirements)}"
    )

    return state


def run_file_analysis(state):
    """
    Executes security, code quality, and dependency checks for each file in state.

    Args:
        state (SecurityState): The current graph state containing scanned files.

    Returns:
        SecurityState: Updated state containing detailed analysis and patch results.
    """
    results = []

    for file_data in state["files"]:

        file_path = file_data["file"]
        code = file_data.get("code", "")

        if not code:
            continue

        print(
            f"\nAnalyzing: {file_path}"
        )

        # =========================================================
        # Security analysis
        # =========================================================

        security_findings = security_agent(
            code
        )

        # =========================================================
        # Code quality analysis
        # =========================================================

        code_findings = code_agent(
            code
        )

        # =========================================================
        # Dependency analysis
        # =========================================================

        dependency_findings = dependency_agent(
            code,
            state["requirements"],
            state["repository_path"]
        )

        if state["requirements"]:

            dependency_findings += (
                "\n\nProject requirements.txt:\n"
                + "\n".join(
                    state["requirements"]
                )
            )

        # =========================================================
        # Security review
        # =========================================================

        review = review_agent(
            security_findings,
            code_findings,
            dependency_findings
        )

        # =========================================================
        # Default values
        # =========================================================

        patched_code = code

        validation = {
            "valid": True,
            "message": "No security patch required."
        }

        remediation = None

        patch_write_result = {
            "success": False,
            "file": file_path,
            "backup": None,
            "message": "Patch writer not required."
        }

        # =========================================================
        # Determine whether patching is required
        # =========================================================

        patch_required = (
            "Decision: PATCH_REQUIRED" in review
        )

        if patch_required:

            print(
                "Security vulnerability detected."
            )

            print(
                "Starting autonomous remediation..."
            )

            # =====================================================
            # Autonomous remediation
            # =====================================================

            remediation = remediation_agent(
                code,
                review
            )

            patched_code = remediation[
                "patched_code"
            ]

            validation = remediation[
                "validation"
            ]

            if remediation["success"]:

                print(
                    "Remediation successful after "
                    f"{remediation['attempts']} "
                    "attempt(s)."
                )

                # =================================================
                # Write validated patch to repository
                # =================================================

                patch_write_result = write_patch(
                    file_path=file_path,
                    original_code=code,
                    patched_code=patched_code,
                    repository_root=state["repository_path"]
                )

                print(
                    "\n[Patch Writer]"
                )

                print(
                    patch_write_result["message"]
                )

                if patch_write_result["backup"]:

                    print(
                        "Backup:",
                        patch_write_result["backup"]
                    )

            else:

                print(
                    "Remediation failed after "
                    f"{remediation['attempts']} "
                    "attempt(s)."
                )

                patch_write_result = {
                    "success": False,
                    "file": file_path,
                    "backup": None,
                    "message": (
                        "Patch was not written because "
                        "remediation/validation failed."
                    )
                }

        else:

            print(
                "No security vulnerability detected. "
                "Patch skipped."
            )

        # =========================================================
        # Store complete result
        # =========================================================

        results.append({
            "file": file_path,
            "security_findings": security_findings,
            "code_findings": code_findings,
            "dependency_findings": dependency_findings,
            "review": review,
            "patched_code": patched_code,
            "validation": validation,
            "remediation": remediation,
            "patch_write": patch_write_result
        })

    state["results"] = results

    return state


# ================================================================
# LangGraph workflow
# ================================================================

graph = StateGraph(
    SecurityState
)

graph.add_node(
    "repository_scanner",
    run_repository_scanner
)

graph.add_node(
    "file_analysis",
    run_file_analysis
)

graph.set_entry_point(
    "repository_scanner"
)

graph.add_edge(
    "repository_scanner",
    "file_analysis"
)

graph.add_edge(
    "file_analysis",
    END
)

security_graph = graph.compile()


# ================================================================
# Main execution
# ================================================================

if __name__ == "__main__":

    result = security_graph.invoke({
        "repository_path": "."
    })

    results = result["results"]

    # ============================================================
    # Calculate scan summary
    # ============================================================

    total_files = len(results)

    vulnerabilities_found = 0
    vulnerabilities_fixed = 0
    remediation_attempts = 0
    patches_written = 0
    validation_failures = 0
    backups_created = 0

    for item in results:

        security_text = str(
            item["security_findings"]
        ).lower()

        remediation = item.get(
            "remediation"
        )

        patch_write = item.get(
            "patch_write",
            {}
        )

        # Count detected vulnerabilities
        if (
            "vulnerability:" in security_text
            or "cwe-" in security_text
        ):
            vulnerabilities_found += 1

        # Count remediation results
        if remediation:

            remediation_attempts += remediation.get(
                "attempts",
                0
            )

            if remediation.get(
                "success",
                False
            ):
                vulnerabilities_fixed += 1

        # Count successful patches
        if patch_write.get(
            "success",
            False
        ):
            patches_written += 1

        # Count validation failures
        validation = item.get(
            "validation",
            {}
        )

        if (
            validation.get("valid") is False
            and remediation
        ):
            validation_failures += 1

        # Count backups
        if patch_write.get(
            "backup"
        ):
            backups_created += 1

    # ============================================================
    # Final scan summary
    # ============================================================

    print(
        "\n\n========== SECURITY SCAN COMPLETE =========="
    )

    print(
        "\n========== SCAN SUMMARY =========="
    )

    print(
        f"Files scanned              : {total_files}"
    )

    print(
        f"Security vulnerabilities   : "
        f"{vulnerabilities_found}"
    )

    print(
        f"Vulnerabilities remediated : "
        f"{vulnerabilities_fixed}"
    )

    print(
        f"Remediation attempts       : "
        f"{remediation_attempts}"
    )

    print(
        f"Patches written            : "
        f"{patches_written}"
    )

    print(
        f"Validation failures        : "
        f"{validation_failures}"
    )

    print(
        f"Backups created            : "
        f"{backups_created}"
    )

    print(
        "----------------------------------------"
    )

    if (
        vulnerabilities_found > 0
        and vulnerabilities_fixed == vulnerabilities_found
        and validation_failures == 0
    ):

        print(
            "STATUS: SECURITY SCAN PASSED"
        )

    elif vulnerabilities_found == 0:

        print(
            "STATUS: NO SECURITY VULNERABILITIES FOUND"
        )

    else:

        print(
            "STATUS: REVIEW REQUIRED"
        )

    # ============================================================
    # Detailed results
    # ============================================================

    for item in results:

        print(
            "\n========================================"
        )

        print(
            "FILE:",
            item["file"]
        )

        print(
            "========================================"
        )

        print(
            "\n--- SECURITY ---"
        )

        print(
            item["security_findings"]
        )

        print(
            "\n--- CODE QUALITY ---"
        )

        print(
            item["code_findings"]
        )

        print(
            "\n--- DEPENDENCIES ---"
        )

        print(
            item["dependency_findings"]
        )

        print(
            "\n--- REVIEW ---"
        )

        print(
            item["review"]
        )

        print(
            "\n--- PATCH VALIDATION ---"
        )

        print(
            item["validation"]
        )

        if item["remediation"]:

            print(
                "\n--- REMEDIATION ---"
            )

            print(
                "Success:",
                item["remediation"]["success"]
            )

            print(
                "Attempts:",
                item["remediation"]["attempts"]
            )

        print(
            "\n--- PATCH WRITER ---"
        )

        print(
            item["patch_write"]["message"]
        )

        if item["patch_write"]["backup"]:

            print(
                "Backup:",
                item["patch_write"]["backup"]
            )

        if item["remediation"]:

            print(
                "\n--- PATCHED CODE ---"
            )

            print(
                item["patched_code"]
            )