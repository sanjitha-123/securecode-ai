import os
import tempfile
from datetime import datetime


def write_patch(
    file_path,
    original_code,
    patched_code,
    repository_root="."
):

    try:

        if not patched_code or not patched_code.strip():

            return {
                "success": False,
                "file": file_path,
                "backup": None,
                "message": "Patch writer rejected empty patched code."
            }

        if not os.path.exists(file_path):

            return {
                "success": False,
                "file": file_path,
                "backup": None,
                "message": "Target file does not exist."
            }

        absolute_file = os.path.abspath(file_path)
        absolute_root = os.path.abspath(repository_root)

        try:
            common_path = os.path.commonpath(
                [absolute_file, absolute_root]
            )
        except ValueError:
            common_path = ""

        if common_path != absolute_root:

            return {
                "success": False,
                "file": file_path,
                "backup": None,
                "message": (
                    "Patch writer rejected the file because "
                    "it is outside the repository."
                )
            }

        backup_directory = os.path.join(
            absolute_root,
            ".security_backups"
        )

        os.makedirs(
            backup_directory,
            exist_ok=True
        )

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S_%f"
        )

        relative_file = os.path.relpath(
            absolute_file,
            absolute_root
        )

        safe_name = relative_file.replace(
            os.sep,
            "__"
        )

        backup_path = os.path.join(
            backup_directory,
            timestamp + "__" + safe_name
        )

        with open(
            absolute_file,
            "r",
            encoding="utf-8"
        ) as source_file:

            current_code = source_file.read()

        with open(
            backup_path,
            "w",
            encoding="utf-8"
        ) as backup_file:

            backup_file.write(current_code)

        directory = os.path.dirname(
            absolute_file
        )

        temp_path = None

        try:

            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".tmp",
                prefix=".security_patch_",
                dir=directory,
                delete=False,
                encoding="utf-8"
            ) as temp_file:

                temp_file.write(patched_code)
                temp_file.flush()
                os.fsync(temp_file.fileno())

                temp_path = temp_file.name

            os.replace(
                temp_path,
                absolute_file
            )

            temp_path = None

        finally:

            if temp_path and os.path.exists(temp_path):

                try:
                    os.remove(temp_path)
                except OSError:
                    pass

        return {
            "success": True,
            "file": file_path,
            "backup": backup_path,
            "message": (
                "Security patch successfully written "
                "and original file backed up."
            )
        }

    except Exception as error:

        return {
            "success": False,
            "file": file_path,
            "backup": None,
            "message": (
                "Patch writing failed: "
                + str(error)
            )
        }