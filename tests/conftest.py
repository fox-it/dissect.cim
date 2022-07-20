import gzip
import os

import pytest


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


def open_file_gz(name, mode="rb"):
    with gzip.GzipFile(absolute_path(name), mode) as f:
        yield f


@pytest.fixture
def index_bin():
    yield from open_file_gz("data/INDEX.BTR.gz")


@pytest.fixture
def objects_bin():
    yield from open_file_gz("data/OBJECTS.DATA.gz")


@pytest.fixture
def mappings_bin():
    yield from zip(*[open_file_gz(f"data/MAPPING{i}.MAP.gz") for i in range(1, 4)])
