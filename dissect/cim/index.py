import hashlib
import string
from functools import lru_cache, partial
from io import BytesIO

from dissect.cim.c_cim import c_cim, INDEX_PAGE_INVALID, INDEX_PAGE_INVALID2, INDEX_PAGE_SIZE
from dissect.cim.exceptions import ReferenceNotFoundError


class Index:
    def __init__(self, cim, fh, mapping):
        self.store = Store(cim, fh, mapping)

    def lookup(self, key):
        return self._lookup(str(key), self.store.root_page)

    @lru_cache(1024)
    def _lookup(self, key, page):
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

    def _lookup_left(self, key, page, i):
        return self._lookup_child(key, page, i, 0)

    def _lookup_right(self, key, page, i):
        return self._lookup_child(key, page, i, 1)

    def _lookup_child(self, key, page, i, direction):
        child_idx = page.child(i + direction)
        if child_idx in [INDEX_PAGE_INVALID, INDEX_PAGE_INVALID2]:
            return []

        child_page = self.store.page(child_idx)
        return self._lookup(key, child_page)


class Store:
    def __init__(self, cim, fh, mapping):
        self.cim = cim
        self.fh = fh
        self.map = mapping

        root_page_num = self.map.get_entry(0).used_space
        if root_page_num is None:
            root_page_num = self.page(0).page.root_page

        self.root_page = self.page(root_page_num)

    def page(self, logical_num):
        page_num = self.map.get_entry(logical_num).page_number
        buf = self.read_page(page_num)
        return IndexPage(self, buf, logical_num, page_num)

    def read_page(self, page_num):
        self.fh.seek(INDEX_PAGE_SIZE * page_num)
        return BytesIO(self.fh.read(INDEX_PAGE_SIZE))


class IndexPage:
    def __init__(self, store, fh, logical_num, page_num):
        self.store = store
        self.fh = fh
        self.logical_num = logical_num
        self.page_num = page_num

        start = fh.tell()
        self.page = c_cim.index_page(fh)
        self.data = fh.read(INDEX_PAGE_SIZE - (fh.tell() - start))

        self.count = self.page.record_count

    def _string_part(self, idx):
        offset = self.page.string_table[idx]
        return self.data[offset : self.data.find(b"\x00", offset)].decode("utf8")

    def string(self, idx):
        parts = []
        part_count = self.page.string_definition_table[idx]

        for i in range(part_count):
            part_idx = self.page.string_definition_table[idx + 1 + i]
            parts.append(self._string_part(part_idx))

        return "/".join(parts)

    @lru_cache(256)
    def key(self, idx):
        str_idx = self.page.keys[idx]
        key_idx = self.string(str_idx)
        return Key(self.store.cim, key_idx)

    def keys(self):
        for i in range(self.count):
            yield self.key(i)

    def child(self, idx):
        return self.page.children[idx]

    def children(self):
        return self.page.children


class Key:
    def __init__(self, cim, *parts):
        self.cim = cim
        self.key = "/".join(parts).strip("/")

    def __repr__(self):
        return f"<Key {self.key}>"

    def __str__(self):
        return self.key

    def __getattr__(self, attr):
        if len(attr) <= 2 and attr.isupper():
            return partial(self._path, attr)
        return object.__getattribute__(self, attr)

    def __getitem__(self, item):
        return self.parts()[item]

    def _hash(self, s):
        if self.cim.type_xp:
            hash_object = hashlib.md5(s)
        else:
            hash_object = hashlib.sha256(s)
        return hash_object.hexdigest().upper()

    def _path(self, prefix, name=None):
        if name is None:
            return Key(self.cim, self.key, prefix)

        if name.isupper() and all([c in string.hexdigits for c in name]):
            digest = name
        else:
            digest = self._hash(name.upper().encode("utf-16-le"))

        return Key(self.cim, self.key, f"{prefix}_{digest}")

    def _data_part(self, idx):
        if not self.is_data_reference:
            raise ValueError(f"Key is not a data reference: {self}")

        return self.key.split(".")[idx]

    def parts(self):
        obj = {}
        for p in self.key.split("/"):
            prefix, digest = p.split("_")
            obj[prefix] = digest
        return obj

    def reference(self):
        refs = self.references()
        if refs and len(refs) > 1:
            raise ValueError("Key returned more than one reference")
        return refs[0] if refs else refs

    def references(self):
        return self.cim.index.lookup(self)

    def object(self):
        ref = self.reference()
        if not ref:
            raise ReferenceNotFoundError("Reference not found")
        return self.cim.objects.get(ref)

    def objects(self):
        for ref in self.references():
            yield ref, self.cim.objects.get(ref)

    @property
    def is_data_reference(self):
        return "." in self.key

    @property
    def data_page(self):
        return int(self._data_part(1))

    @property
    def data_id(self):
        return int(self._data_part(2))

    @property
    def data_length(self):
        return int(self._data_part(3))
