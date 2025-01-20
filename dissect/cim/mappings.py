from __future__ import annotations

from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO

from dissect.cim.c_cim import MAPPING_PAGE_ID_MASK, UNMAPPED_PAGE_VALUE, c_cim
from dissect.cim.exceptions import Error, UnmappedPageError

if TYPE_CHECKING:
    from dissect.cim.cim import CIM


class Mapping:
    """Provides forward and reverse lookup of physical and logical pages."""

    def __init__(self, cim: CIM, fh: BinaryIO):
        self.cim = cim
        self.mapping = cim.map_type(fh)

        if self.mapping.signature != 0xABCD:
            raise Error("Invalid mapping file!")

        self.get_entry = lru_cache(256)(self.get_entry)

    def __getitem__(self, k: int) -> MappingEntry:
        if not isinstance(k, int):
            raise TypeError("Invalid type")
        return self.get_entry(k)

    @cached_property
    def _reverse_map(self) -> dict[int, int]:
        reverse_map = {}
        for i in range(self.mapping.mapping_entry_count):
            pnum = self.get_entry(i).page_number

            if pnum == UNMAPPED_PAGE_VALUE:
                continue

            reverse_map[pnum] = i

        return reverse_map

    def get_entry(self, logical_num: int) -> MappingEntry:
        if logical_num > self.mapping.mapping_entry_count:
            raise IndexError(logical_num)

        try:
            entry = self.mapping.entries[logical_num]
        except Exception:
            raise UnmappedPageError(logical_num)

        return MappingEntry(entry)

    def reverse(self, physical_num: int) -> int:
        if physical_num in self._reverse_map:
            return self._reverse_map[physical_num]

        raise UnmappedPageError(physical_num)


class MappingEntry:
    def __init__(self, entry: int | c_cim.mapping_entry):
        self.entry = entry

        if isinstance(entry, int):
            self.page_number = entry & MAPPING_PAGE_ID_MASK
            self.page_crc = None
            self.free_space = None
            self.used_space = None
            self.first_id = None
            self.second_id = None
        else:
            self.page_number = entry.page_number & MAPPING_PAGE_ID_MASK
            self.page_crc = entry.page_crc
            self.free_space = entry.free_space
            self.used_space = entry.used_space
            self.first_id = entry.first_id
            self.second_id = entry.second_id

    @property
    def is_mapped(self) -> bool:
        return self.page_number != UNMAPPED_PAGE_VALUE
