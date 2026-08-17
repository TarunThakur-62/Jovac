import os


def get_permissions(file_path):

    try:
        mode = os.stat(file_path).st_mode
        return oct(mode & 0o777)

    except (FileNotFoundError, PermissionError):
        return None

