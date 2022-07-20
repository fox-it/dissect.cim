from functools import lru_cache

from dissect.cim.c_cim import MAPPING_PAGE_ID_MASK, UNMAPPED_PAGE_VALUE
from dissect.cim.exceptions import Error, UnmappedPageError


class Mapping:
    """Provides forward and reverse lookup of physical and logical pages."""

    def __init__(self, cim, fh):
        self.cim = cim
        self.mapping = cim.map_type(fh)

        if self.mapping.signature != 0xABCD:
            raise Error("Invalid mapping file!")

        self._reverse_map = {}

    def __getitem__(self, k):
        if not isinstance(k, int):
            raise ValueError("Invalid type")
        return self.get_entry(k)

    def _generate_reverse_map(self):
        self._reverse_map = {}
        for i in range(self.mapping.mapping_entry_count):
            pnum = self.get_entry(i).page_number

            if pnum == UNMAPPED_PAGE_VALUE:
                continue

            self._reverse_map[pnum] = i

    @lru_cache(256)
    def get_entry(self, logical_num):
        if logical_num > self.mapping.mapping_entry_count:
            raise IndexError(logical_num)

        try:
            entry = self.mapping.entries[logical_num]
        except Exception:
            raise UnmappedPageError(logical_num)

        return MappingEntry(entry)

    def reverse(self, physical_num):
        if not self._reverse_map:
            self._generate_reverse_map()

        if physical_num in self._reverse_map:
            return self._reverse_map[physical_num]

        raise UnmappedPageError(physical_num)


class MappingEntry:
    def __init__(self, entry):
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
    def is_mapped(self):
        return self.page_number != UNMAPPED_PAGE_VALUE
