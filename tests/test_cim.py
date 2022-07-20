from dissect.cim.cim import CIM


def test_cim(index_bin, objects_bin, mappings_bin):
    repo = CIM(index_bin, objects_bin, mappings_bin)
    assert repo
