from pathlib import Path


def scan_requirements(repository_path):

    requirements_file = (
        Path(repository_path) / "requirements.txt"
    )

    if not requirements_file.exists():
        return []

    dependencies = []

    try:
        content = requirements_file.read_text(
            encoding="utf-8",
            errors="ignore"
        )

    except OSError:
        return []

    for line in content.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        dependencies.append(line)

    return dependencies