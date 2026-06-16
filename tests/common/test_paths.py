import os

from common.paths import REPO_ROOT


# REPO_ROOT resolves to a directory holding the expected top-level markers
def test_repo_root_contains_top_level_markers():
    assert os.path.isdir(os.path.join(REPO_ROOT, "labs"))
    assert os.path.isdir(os.path.join(REPO_ROOT, "common"))
    assert os.path.isfile(os.path.join(REPO_ROOT, "README.md"))
