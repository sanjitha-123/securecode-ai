import ast
import sys
from pathlib import Path


IMPORT_TO_PACKAGE = {
    "dotenv": "python-dotenv",
    "langchain_google_genai": "langchain-google-genai",
    "langchain_core": "langchain-core",
    "git": "gitpython",
}


LOCAL_PACKAGE_NAMES = {
    "agents",
    "tools",
}


def dependency_agent(
    code,
    requirements=None,
    repository_path="."
):

    try:
        tree = ast.parse(code)

    except SyntaxError as error:
        return (
            "Syntax error: "
            + str(error)
        )

    imported_modules = set()

    for node in ast.walk(tree):

        if isinstance(node, ast.Import):

            for name in node.names:

                imported_modules.add(
                    name.name.split(".")[0]
                )

        elif isinstance(node, ast.ImportFrom):

            if node.module:

                imported_modules.add(
                    node.module.split(".")[0]
                )

    if not imported_modules:

        return (
            "No Python dependencies detected."
        )

    standard_library = set(
        sys.stdlib_module_names
    )

    repository = Path(
        repository_path
    )

    local_modules = set(
        LOCAL_PACKAGE_NAMES
    )

    if repository.exists():

        for path in repository.rglob("*.py"):

            if any(
                part in {
                    "venv",
                    ".venv",
                    "__pycache__",
                    ".git",
                    ".security_backups"
                }
                for part in path.parts
            ):
                continue

            local_modules.add(
                path.stem
            )

    third_party_imports = []

    for module in sorted(
        imported_modules
    ):

        if (
            module not in standard_library
            and module not in local_modules
        ):

            third_party_imports.append(
                module
            )

    if not third_party_imports:

        return (
            "No third-party Python dependencies detected."
        )

    third_party_packages = []

    for module in third_party_imports:

        package = IMPORT_TO_PACKAGE.get(
            module,
            module
        )

        third_party_packages.append(
            package
        )

    result = (
        "Third-party dependencies detected: "
        + ", ".join(
            third_party_packages
        )
    )

    if requirements:

        required_packages = set()

        for requirement in requirements:

            package = requirement.strip()

            if (
                not package
                or package.startswith("#")
            ):
                continue

            for separator in [
                "==",
                ">=",
                "<=",
                "~=",
                ">",
                "<"
            ]:

                package = package.split(
                    separator
                )[0]

            package = package.split(
                "["
            )[0]

            package = package.strip().lower()

            if package:

                required_packages.add(
                    package
                )

        missing = []

        for package in third_party_packages:

            if (
                package.lower()
                not in required_packages
            ):

                missing.append(
                    package
                )

        if missing:

            result += (
                "\nPotentially undeclared dependencies: "
                + ", ".join(missing)
            )

        else:

            result += (
                "\nAll detected third-party dependencies "
                "are declared in requirements.txt."
            )

    else:

        result += (
            "\nrequirements.txt was not available "
            "for comparison."
        )

    return result