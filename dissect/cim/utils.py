from collections import namedtuple

from dissect.cim.c_cim import c_cim
from dissect.cim.exceptions import Error


ObjectPath = namedtuple("ObjectPath", ["hostname", "namespace", "class_", "instance"])


def is_xp_mapping(h):
    if h.signature != 0xABCD:
        raise Error("Invalid mapping file signature")

    if h.mapping_entry_count < h.physical_page_count // 10:
        return True

    if hasattr(h, "first_id") and hasattr(h, "second_id"):
        if h.first_id - 1 != h.second_id:
            return True

    return False


def find_current_mapping(mappings):
    map_header = c_cim.mapping_header
    type_xp = None
    current = None
    max_version = 0

    for m in mappings:
        m.seek(0)
        mh = map_header(m)
        m.seek(0)

        if type_xp is None:
            type_xp = is_xp_mapping(mh)
            if type_xp:
                map_header = c_cim.mapping_header_xp
                mh = map_header(m)
                m.seek(0)

        if mh.version > max_version:
            current = m
            max_version = mh.version

    return type_xp, current


def parse_object_path(object_path, ns=None):
    """
    given a textual query string, parse it into an object path that we can query.

    supported schemas:
        cimv2 --> namespace
        //./root/cimv2 --> namespace
        //HOSTNAME/root/cimv2 --> namespace
        winmgmts://./root/cimv2 --> namespace
        Win32_Service --> class
        //./root/cimv2:Win32_Service --> class
        Win32_Service.Name='Beep' --> instance
        //./root/cimv2:Win32_Service.Name="Beep" --> instance

    we'd like to support this, but can't differentiate this
        from a class:
        //./root/cimv2/Win32_Service --> class

    Args:
        object_path (str): the textual query string.
        ns:

    Returns:
        ObjectPath: a path we can use to query.
    """
    o_object_path = object_path
    object_path = object_path.replace("\\", "/")

    if object_path.startswith("winmgmts:"):
        # winmgmts://./root/cimv2 --> namespace
        object_path = object_path[len("winmgmts:") :]

    hostname = "localhost"
    namespace = ns.name if ns else None
    instance = {}

    is_rooted = False
    if object_path.startswith("//"):
        is_rooted = True

        # //./root/cimv2 --> namespace
        # //HOSTNAME/root/cimv2 --> namespace
        # //./root/cimv2:Win32_Service --> class
        # //./root/cimv2:Win32_Service.Name="Beep" --> instance
        object_path = object_path[len("//") :]

        # ./root/cimv2 --> namespace
        # HOSTNAME/root/cimv2 --> namespace
        # ./root/cimv2:Win32_Service --> class
        # ./root/cimv2:Win32_Service.Name="Beep" --> instance
        hostname, _, object_path = object_path.partition("/")
        if hostname == ".":
            hostname = "localhost"

    # cimv2 --> namespace
    # Win32_Service --> class
    # Win32_Service.Name='Beep' --> instance
    # root/cimv2 --> namespace
    # root/cimv2 --> namespace
    # root/cimv2:Win32_Service --> class
    # root/cimv2:Win32_Service.Name="Beep" --> instance
    if ":" in object_path:
        namespace, _, object_path = object_path.partition(":")
    elif "." not in object_path:
        if is_rooted:
            ns = object_path.replace("/", "\\")
            return ObjectPath(hostname, ns, "", {})
        else:
            if ns is None:
                raise Error("Relative query but no namespace")

            try:
                # relative namespace
                ns.namespace(object_path)
                ns1 = ns.name.replace("/", "\\")
                ns2 = object_path.replace("/", "\\")
                return ObjectPath(hostname, ns1 + "\\" + ns2, "", {})
            except IndexError:
                try:
                    ns.class_(object_path)
                    namespace = ns.name
                except IndexError:
                    raise RuntimeError("Unknown ObjectPath schema: %s" % o_object_path)

    # Win32_Service --> class
    # Win32_Service.Name="Beep" --> instance
    if "." in object_path:
        object_path, _, keys = object_path.partition(".")
        if keys:
            for key in keys.split(","):
                k, _, v = key.partition("=")
                instance[k] = v.strip("\"'")
    class_name = object_path
    ns = namespace.replace("/", "\\")
    return ObjectPath(hostname, ns, class_name, instance)
