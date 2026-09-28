from pathlib import Path


def scan_repository(repository_path):

    repository = Path(repository_path)

    if not repository.exists():
        raise FileNotFoundError(
            f"Repository not found: {repository_path}"
        )

    python_files = []

    for file in repository.rglob("*.py"):

        if any(
            excluded in file.parts
            for excluded in [
                "venv",
                ".venv",
                "__pycache__",
                ".git",
                ".security_backups"
            ]
        ):
            continue

        if file.name in {
            "security_agent.py",
            "patch_agent.py"
        }:
            continue

        python_files.append(file)

    results = []

    for file in python_files:

        try:

            code = file.read_text(
                encoding="utf-8",
                errors="ignore"
            )

            results.append({
                "file": str(file),
                "code": code
            })

        except Exception as error:

            results.append({
                "file": str(file),
                "code": "",
                "error": str(error)
            })

    return results