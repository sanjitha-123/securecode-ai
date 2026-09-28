def review_agent(
    security_findings,
    code_findings,
    dependency_findings
):

    security_text = str(
        security_findings
    ).strip()

    has_security_vulnerability = (
        "vulnerability:" in security_text.lower()
        or "cwe-" in security_text.lower()
        or "security vulnerability" in security_text.lower()
    )

    if (
        "no known security vulnerability was detected"
        in security_text.lower()
        and not (
            "vulnerability:" in security_text.lower()
            or "cwe-" in security_text.lower()
        )
    ):
        has_security_vulnerability = False

    if has_security_vulnerability:

        decision = "PATCH_REQUIRED"

        reason = (
            "The Security Agent reported a potential "
            "security vulnerability. The Patch Agent "
            "should attempt remediation."
        )

    else:

        decision = "NO_PATCH_REQUIRED"

        reason = (
            "No confirmed security vulnerability was "
            "reported by the Security Agent."
        )

    return (
        "LOCAL REVIEW\n\n"
        "Decision: "
        + decision
        + "\n"
        "Reason: "
        + reason
        + "\n\n"
        "Security Findings:\n"
        + security_text
        + "\n\n"
        "Code Quality Findings:\n"
        + str(code_findings)
        + "\n\n"
        "Dependency Findings:\n"
        + str(dependency_findings)
    )