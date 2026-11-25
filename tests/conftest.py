import os
import tempfile

import pytest

# 在导入应用前固定临时库
_TMP = tempfile.TemporaryDirectory()
os.environ["RPKI_DRILL_DB"] = os.path.join(_TMP.name, "test.db")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture()
def client():
    from app import store

    store.reset_db()
    with TestClient(app) as c:
        yield c
