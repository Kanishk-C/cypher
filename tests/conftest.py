import pytest
import tempfile
import shutil
import os


@pytest.fixture(scope="session")
def test_storage_dir():
    """Create temporary storage directory for tests."""
    tmpdir = tempfile.mkdtemp(prefix="cypher_test_")
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def clean_storage(test_storage_dir, monkeypatch):
    """Provide clean storage for each test."""
    monkeypatch.setattr(
        "src.data.database.get_storage_directory", lambda: test_storage_dir
    )
    # Clean between tests
    for item in os.listdir(test_storage_dir):
        path = os.path.join(test_storage_dir, item)
        if os.path.isfile(path):
            os.unlink(path)
    yield test_storage_dir
