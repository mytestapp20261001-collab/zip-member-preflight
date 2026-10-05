"""Create two tiny synthetic ZIPs in a temporary directory; print their reports."""
import json
from pathlib import Path
import tempfile
import zipfile

from preflight import inspect_archive


def main():
    result = {}
    with tempfile.TemporaryDirectory(prefix="zip-preflight-demo-") as directory:
        for label, names in (("conflicting", ["Readme", "README", "assets", "assets/icon.txt"]),
                             ("adjusted", ["README.txt", "assets/icon.txt"])):
            path = Path(directory) / (label + ".zip")
            with zipfile.ZipFile(path, "w") as archive:
                for name in names:
                    archive.writestr(name, b"synthetic example")
            result[label] = inspect_archive(path)
        assert result["conflicting"]["status"] == "name_findings"
        assert result["adjusted"]["status"] == "no_name_findings"
        assert [(f["rule"], f["members"]) for f in result["conflicting"]["findings"]] == [
            ("FILE_DIRECTORY_CONFLICT", [2, 3]), ("ASCII_CASE_COLLISION", [0, 1])]
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))


if __name__ == "__main__":
    main()
