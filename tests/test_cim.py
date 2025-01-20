from __future__ import annotations

from typing import BinaryIO

from dissect.cim.cim import CIM


def test_cim(index_bin: BinaryIO, objects_bin: BinaryIO, mappings_bin: list[BinaryIO]) -> None:
    repo = CIM(index_bin, objects_bin, mappings_bin)
    assert repo
