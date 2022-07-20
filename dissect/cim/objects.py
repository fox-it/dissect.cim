from io import BytesIO

from dissect.cim.c_cim import c_cim, DATA_PAGE_SIZE
from dissect.cim.exceptions import Error


class Objects:
    def __init__(self, cim, fh, mapping):
        self.store = Store(cim, fh, mapping)

    def get(self, key):
        if not key.is_data_reference:
            raise ValueError(f"Key is not a data reference: {key}")

        page = self.store.page(key.data_page)

        buf = page.data(key)
        data_len = key.data_length
        cur_len = len(buf)

        if cur_len == data_len:
            return BytesIO(buf)

        read_list = [buf]
        cur_page = key.data_page + 1
        while cur_len < data_len:
            next_buf = self.store.logical_page(cur_page)
            if cur_len + len(next_buf) > data_len:
                # Last page containing partial data
                chunk_size = data_len - cur_len
                read_list.append(next_buf[:chunk_size])
                cur_len += chunk_size
            else:
                # Entire page is data
                read_list.append(next_buf)
                cur_len += len(next_buf)

            cur_page += 1

        return BytesIO(b"".join(read_list))


class Store:
    def __init__(self, cim, fh, mapping):
        self.cim = cim
        self.fh = fh
        self.map = mapping

    def page(self, logical_num):
        page_number = self.map.get_entry(logical_num).page_number
        buf = self.physical_page(page_number)
        return DataPage(self, BytesIO(buf), logical_num, page_number)

    def logical_page(self, logical_num):
        return self.physical_page(self.map.get_entry(logical_num).page_number)

    def physical_page(self, page_number):
        self.fh.seek(DATA_PAGE_SIZE * page_number)
        return self.fh.read(DATA_PAGE_SIZE)


class DataPage:
    def __init__(self, store, fh, logical_num, page_number):
        self.store = store
        self.fh = fh
        self.logical_num = logical_num
        self.page_number = page_number

        self.toc = TOC(fh)

    def data(self, key):
        target_id = key.data_id
        target_size = key.data_length

        for i in range(self.toc.count):
            entry = self.toc[i]
            if entry.record_id == target_id:
                if entry.size < target_size:
                    raise Error(f"Entry size is smaller than target size: {entry.size} < {target_size}")

                if entry.size > DATA_PAGE_SIZE - entry.offset:
                    pass

                self.fh.seek(entry.offset)
                return self.fh.read(entry.size)

        raise IndexError()

    def objects(self):
        pass


class TOC:
    def __init__(self, fh):
        self.fh = fh
        self.entries = []

        while True:
            e = c_cim.toc_entry(self.fh)
            if e.record_id == 0 and e.offset == 0 and e.size == 0 and e.crc == 0:
                break
            self.entries.append(e)

        self.count = len(self.entries)

    def __getitem__(self, k):
        return self.entries[k]
