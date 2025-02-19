from __future__ import annotations

import gzip
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def open_file_gz(name: str, mode: str = "rb") -> Iterator[gzip.GzipFile]:
    with gzip.GzipFile(absolute_path(name), mode) as f:
        yield f


@pytest.fixture
def index_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/INDEX.BTR.gz")


@pytest.fixture
def objects_bin() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/OBJECTS.DATA.gz")


@pytest.fixture
def mappings_bin() -> Iterator[list[BinaryIO]]:
    yield from zip(*[open_file_gz(f"_data/MAPPING{i}.MAP.gz") for i in range(1, 4)])
