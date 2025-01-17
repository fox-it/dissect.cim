from __future__ import annotations

import hashlib
import string
from functools import lru_cache
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.cim.c_cim import (
    INDEX_PAGE_INVALID,
    INDEX_PAGE_INVALID2,
    INDEX_PAGE_SIZE,
    c_cim,
)
from dissect.cim.exceptions import ReferenceNotFoundError

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.cim.cim import CIM
    from dissect.cim.mappings import Mapping


class Index:
    def __init__(self, cim: CIM, fh: BinaryIO, mapping: Mapping):
        self.store = Store(cim, fh, mapping)

        self._lookup = lru_cache(1024)(self._lookup)

    def lookup(self, key: Key) -> list[Key]:
        return self._lookup(str(key), self.store.root_page)

    def _lookup(self, key: str, page: IndexPage) -> list[Key]:
        matches = []

        for i, page_key in enumerate(page.keys()):
            page_key_str = str(page_key)

            if key in page_key_str:
                matches.extend(self._lookup_left(key, page, i))
                matches.append(page_key)
                matches.extend(self._lookup_right(key, page, i))
                if i == page.count - 1:
                    break
                continue
            if key < page_key_str:
                matches.extend(self._lookup_left(key, page, i))
                break
            if key > page_key_str:
                if i == page.count - 1:
                    matches.extend(self._lookup_right(key, page, i))
                    break
                continue

        return matches

    def _lookup_left(self, key: str, page: IndexPage, i: int) -> list[Key]:
        return self._lookup_child(key, page, i, 0)

    def _lookup_right(self, key: str, page: IndexPage, i: int) -> list[Key]:
        return self._lookup_child(key, page, i, 1)

    def _lookup_child(self, key: str, page: IndexPage, i: int, direction: int) -> list[Key]:
        child_idx = page.child(i + direction)
        if child_idx in [INDEX_PAGE_INVALID, INDEX_PAGE_INVALID2]:
            return []

        child_page = self.store.page(child_idx)
        return self._lookup(key, child_page)


class Store:
    def __init__(self, cim: CIM, fh: BinaryIO, mapping: Mapping):
        self.cim = cim
        self.fh = fh
        self.map = mapping

        root_page_num = self.map.get_entry(0).used_space
        if root_page_num is None:
            root_page_num = self.page(0).page.root_page

        self.root_page = self.page(root_page_num)

    def page(self, logical_num: int) -> IndexPage:
        page_num = self.map.get_entry(logical_num).page_number
        buf = self.read_page(page_num)
        return IndexPage(self, buf, logical_num, page_num)

    def read_page(self, page_num: int) -> BytesIO:
        self.fh.seek(INDEX_PAGE_SIZE * page_num)
        return BytesIO(self.fh.read(INDEX_PAGE_SIZE))


class IndexPage:
    def __init__(self, store: Store, fh: BinaryIO, logical_num: int, page_num: int):
        self.store = store
        self.fh = fh
        self.logical_num = logical_num
        self.page_num = page_num

        start = fh.tell()
        self.page = c_cim.index_page(fh)
        self.data = fh.read(INDEX_PAGE_SIZE - (fh.tell() - start))

        self.count = self.page.record_count

        self.key = lru_cache(256)(self.key)

    def _string_part(self, idx: int) -> str:
        offset = self.page.string_table[idx]
        return self.data[offset : self.data.find(b"\x00", offset)].decode("utf8")

    def string(self, idx: int) -> str:
        parts = []
        part_count = self.page.string_definition_table[idx]

        for i in range(part_count):
            part_idx = self.page.string_definition_table[idx + 1 + i]
            parts.append(self._string_part(part_idx))

        return "/".join(parts)

    def key(self, idx: int) -> Key:
        str_idx = self.page.keys[idx]
        key_idx = self.string(str_idx)
        return Key(self.store.cim, key_idx)

    def keys(self) -> Iterator[Key]:
        for i in range(self.count):
            yield self.key(i)

    def child(self, idx: int) -> int:
        return self.page.children[idx]

    def children(self) -> list[int]:
        return self.page.children


class Key:
    def __init__(self, cim: CIM, *parts: str):
        self.cim = cim
        self.key = "/".join(parts).strip("/")

    def __repr__(self) -> str:
        return f"<Key {self.key}>"

    def __str__(self) -> str:
        return self.key

    def __getitem__(self, item: int) -> str:
        return self.parts()[item]

    def _hash(self, s: bytes) -> str:
        hash_object = hashlib.md5(s) if self.cim.type_xp else hashlib.sha256(s)
        return hash_object.hexdigest().upper()

    def _path(self, prefix: str, name: str | None = None) -> Key:
        if name is None:
            return Key(self.cim, self.key, prefix)

        if name.isupper() and all(c in string.hexdigits for c in name):
            digest = name
        else:
            digest = self._hash(name.upper().encode("utf-16-le"))

        return Key(self.cim, self.key, f"{prefix}_{digest}")

    def _data_part(self, idx: int) -> str:
        if not self.is_data_reference:
            raise ValueError(f"Key is not a data reference: {self}")

        return self.key.split(".")[idx]

    def parts(self) -> dict[str, str]:
        obj = {}
        for p in self.key.split("/"):
            prefix, digest = p.split("_")
            obj[prefix] = digest
        return obj

    def reference(self) -> Key | None:
        refs = self.references()
        if refs and len(refs) > 1:
            raise ValueError("Key returned more than one reference")
        return refs[0] if refs else None

    def references(self) -> list[Key]:
        return self.cim.index.lookup(self)

    def object(self) -> BytesIO:
        ref = self.reference()
        if not ref:
            raise ReferenceNotFoundError("Reference not found")
        return self.cim.objects.get(ref)

    def objects(self) -> Iterator[tuple[Key, BytesIO]]:
        for ref in self.references():
            yield ref, self.cim.objects.get(ref)

    @property
    def is_data_reference(self) -> bool:
        return "." in self.key

    @property
    def data_page(self) -> int:
        return int(self._data_part(1))

    @property
    def data_id(self) -> int:
        return int(self._data_part(2))

    @property
    def data_length(self) -> int:
        return int(self._data_part(3))

    def NS(self, name: str | None = None) -> Key:
        return self._path("NS", name)

    def CD(self, name: str | None = None) -> Key:
        return self._path("CD", name)

    def CI(self, name: str | None = None) -> Key:
        return self._path("CI", name)

    def IL(self, name: str | None = None) -> Key:
        return self._path("IL", name)
