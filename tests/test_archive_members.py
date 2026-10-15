"""Small ZIP fixtures enforce nested real-dataset member selection contract."""
from __future__ import annotations

import io
import stat
import zipfile

import pytest

from networkpulse.evaluation.archive_members import archive_tree_summary, resolve_csv_member


def archive(entries: list[tuple[str, str]]) -> zipfile.ZipFile:
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as zf:
        for path, content in entries:
            zf.writestr(path, content)
    data.seek(0)
    return zipfile.ZipFile(data)


def test_root_and_nested_csv_member():
    with archive([("UNSW-NB15_1.csv", "a,b\n1,2\n")]) as zf:
        assert resolve_csv_member(zf, "UNSW-NB15_1.csv").filename == "UNSW-NB15_1.csv"
    with archive([("subfolder/TON/Network_dataset_23.csv", "a,b\n1,2\n")]) as zf:
        assert resolve_csv_member(zf, "Network_dataset_23.csv").filename == (
            "subfolder/TON/Network_dataset_23.csv"
        )
    with archive([("MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv", "Label\n")]) as zf:
        assert resolve_csv_member(zf, "Monday-WorkingHours.pcap_ISCX.csv").filename.startswith(
            "MachineLearningCVE/"
        )


def test_archive_tree_contains_nested_paths_without_traffic_data():
    with archive([("nested/data.csv", "private-flow"), ("other/deeper/file.zip", "x")]) as zf:
        tree = archive_tree_summary(zf)
    assert tree["entry_count"] == 2
    assert tree["file_count"] == 2
    assert tree["entries"][0]["path"] == "nested/data.csv"
    assert tree["embedded_zip_members"] == ["other/deeper/file.zip"]
    assert "private-flow" not in str(tree)


def test_missing_or_ambiguous_member_fails_closed():
    with archive([("a/Network_dataset_23.csv", ""), ("b/Network_dataset_23.csv", "")]) as zf:
        with pytest.raises(ValueError, match="Ambiguous"):
            resolve_csv_member(zf, "Network_dataset_23.csv")
    with archive([("a.csv", "")]) as zf:
        with pytest.raises(FileNotFoundError):
            resolve_csv_member(zf, "UNSW-NB15_1.csv")


@pytest.mark.parametrize("unsafe", [
    "../UNSW-NB15_1.csv",
    "/UNSW-NB15_1.csv",
    "a/../UNSW-NB15_1.csv",
    "a\\UNSW-NB15_1.csv",
])
def test_unsafe_member_anywhere_in_archive_is_rejected(unsafe):
    with archive([("UNSW-NB15_1.csv", ""), (unsafe, "")]) as zf:
        with pytest.raises(ValueError, match="Unsafe"):
            resolve_csv_member(zf, "UNSW-NB15_1.csv")


def test_duplicate_casefold_member_path_rejected():
    with archive([("a/UNSW-NB15_1.csv", ""), ("A/UNSW-NB15_1.csv", "")]) as zf:
        with pytest.raises(ValueError, match="Duplicate"):
            resolve_csv_member(zf, "UNSW-NB15_1.csv")


def test_symlink_entry_rejected():
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as zf:
        zf.writestr("UNSW-NB15_1.csv", "row")
        item = zipfile.ZipInfo("folder/link")
        item.create_system = 3
        item.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(item, "secret")
    data.seek(0)
    with zipfile.ZipFile(data) as zf:
        with pytest.raises(ValueError, match="symlink"):
            resolve_csv_member(zf, "UNSW-NB15_1.csv")


@pytest.mark.parametrize("bad_basename", ["../x.csv", "folder/x.csv", "x.txt", "a\\x.csv"])
def test_reject_unsafe_requested_names(bad_basename):
    with archive([("ok.csv", "")]) as zf:
        with pytest.raises(ValueError, match="safe CSV basename"):
            resolve_csv_member(zf, bad_basename)
