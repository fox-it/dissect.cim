from collections import namedtuple

from dissect import cstruct


cim_def = """
// Mapping

struct mapping_header {
    uint32  signature;
    uint32  version;
    uint32  first_id;
    uint32  second_id;
    uint32  physical_page_count;
    uint32  mapping_entry_count;
};

struct mapping_header_xp {
    uint32  signature;
    uint32  version;
    uint32  physical_page_count;
    uint32  mapping_entry_count;
};

struct mapping_entry {
    uint32  page_number;
    uint32  page_crc;
    uint32  free_space;
    uint32  used_space;
    uint32  first_id;
    uint32  second_id;
};

struct mapping {
    uint32  signature;
    uint32  version;
    uint32  first_id;
    uint32  second_id;
    uint32  physical_page_count;
    uint32  mapping_entry_count;
    mapping_entry entries[mapping_entry_count];
    uint32  free_dword_count;
    char    free[free_dword_count * 4];
};

struct mapping_xp {
    uint32  signature;
    uint32  version;
    uint32  physical_page_count;
    uint32  mapping_entry_count;
    uint32  entries[mapping_entry_count];
    uint32  free_dword_count;
    char    free[free_dword_count * 4];
    uint32  footer_signature;
};

// Objects

struct toc_entry {
    uint32  record_id;
    uint32  offset;
    uint32  size;
    uint32  crc;
};

// Index page

struct index_page {
    uint32  signature;
    uint32  logical_id;
    uint32  _pad;
    uint32  root_page;
    uint32  record_count;
    uint32  unk0[record_count];
    uint32  children[record_count + 1];
    uint16  keys[record_count];
    uint16  string_definition_table_size;
    uint16  string_definition_table[string_definition_table_size];
    uint16  string_table_size;
    uint16  string_table[string_table_size + 1];
};

// Classes

enum CIM_TYPES : uint8 {
    INT16 = 0x2,
    INT32 = 0x3,
    REAL32 = 0x4,
    REAL64 = 0x5,
    STRING = 0x8,
    BOOLEAN = 0xB,
    OBJECT = 0xD,
    INT8 = 0x10,
    UINT8 = 0x11,
    UINT16 = 0x12,
    UINT32 = 0x13,
    INT64 = 0x14,
    UINT64 = 0x15,
    DATETIME = 0x65,
    REFERENCE = 0x66,
    CHAR16 = 0x67
};

enum ARRAY_STATES : uint8 {
    NOT_ARRAY = 0x0,
    ARRAY = 0x20
};

enum BOOLEAN_STATES : uint16 {
    FALSE = 0x0,
    TRUE = 0xFFFF
};

enum DYNPROPS_STATES : uint8 {
    NO_DYNPROPS = 0x1,
    HAS_DYNPROPS = 0x2
};

enum BUILTIN_QUALIFIERS {
    PROP_QUALIFIER_KEY = 0x1,
    PROP_QUALIFIER_READ_ACCESS = 0x3,
    CLASS_QUALIFIER_PROVIDER = 0x6,
    CLASS_QUALIFIER_DYNAMIC = 0x7,
    PROP_QUALIFIER_TYPE = 0xA
};

enum BUILTIN_PROPERTIES {
    PRIMARY_KEY = 0x1,
    READ = 0x2,
    WRITE = 0x3,
    VOLATILE = 0x4,
    PROVIDER = 0x6,
    DYNAMIC = 0x7,
    TYPE = 0xA
};

struct cim_type {
    CIM_TYPES       type;
    ARRAY_STATES    array_state;
    uint16          unk;
};

struct property_reference {
    uint32  name_offset;
    uint32  property_offset;
};

struct class_definition_property {
    cim_type    type;
    uint16      index;
    uint32      offset;
    uint32      level;
};

struct qualifier_reference {
    uint32      key_reference;
    uint8       unk;
    cim_type    type;
    char        data[0];
};

struct class_name_record {
    uint32  size;
    char    data[size - 4];
};

struct class_definition_header {
    uint32  super_class_name_size;
    wchar   super_class_name[super_class_name_size];
    uint64  timestamp;
    uint32  data_len;
    uint8   unk0;
    uint32  class_name_offset;
    uint32  default_values_metadata_size;
    class_name_record   class_name;
};

struct class_instance_header {
    wchar   name_hash[0x40];
    uint64  ts1;
    uint64  ts2;
    uint32  data_size;
    uint32  class_name_offset;
    uint8   unk0;
    char    remaining_data[data_size - 9];
};

struct class_instance_xp_header {
    wchar   name_hash[0x20];
    uint64  ts1;
    uint64  ts2;
    uint32  data_size;
    uint32  class_name_offset;
    uint8   unk0;
    char    remaining_data[data_size - 9];
};
"""

c_cim = cstruct.cstruct()
c_cim.load(cim_def, compiled=True)

DATA_PAGE_SIZE = 0x2000

INDEX_PAGE_SIZE = 0x2000

INDEX_PAGE_INVALID = 0xFFFFFFFF
INDEX_PAGE_INVALID2 = 0x00000000

MAPPING_PAGE_ID_MASK = 0x3FFFFFFF
MAPPING_PAGE_UNAVAIL = 0xFFFFFFFF
MAPPING_FILE_CLEAN = 0x1
UNMAPPED_PAGE_VALUE = 0x3FFFFFFF

ROOT_NAMESPACE_NAME = "root"
SYSTEM_NAMESPACE_NAME = "__SystemClass"
NAMESPACE_CLASS_NAME = "__namespace"

ARRAY_STATES = c_cim.ARRAY_STATES
BOOLEAN_STATES = c_cim.BOOLEAN_STATES
DYNPROPS_STATES = c_cim.DYNPROPS_STATES

BUILTIN_QUALIFIERS = c_cim.BUILTIN_QUALIFIERS
BUILTIN_PROPERTIES = c_cim.BUILTIN_PROPERTIES

CIM_TYPES = c_cim.CIM_TYPES
CIM_TYPES_MAP = {
    CIM_TYPES.INT16: c_cim.int16,
    CIM_TYPES.INT32: c_cim.int32,
    CIM_TYPES.REAL32: c_cim.float,
    CIM_TYPES.REAL64: c_cim.double,
    CIM_TYPES.STRING: c_cim.uint32,
    CIM_TYPES.BOOLEAN: c_cim.BOOLEAN_STATES,
    CIM_TYPES.OBJECT: c_cim.uint32,
    CIM_TYPES.INT8: c_cim.int8,
    CIM_TYPES.UINT8: c_cim.uint8,
    CIM_TYPES.UINT16: c_cim.uint16,
    CIM_TYPES.UINT32: c_cim.uint32,
    CIM_TYPES.INT64: c_cim.int64,
    CIM_TYPES.UINT64: c_cim.uint64,
    CIM_TYPES.DATETIME: c_cim.uint32,
    CIM_TYPES.REFERENCE: c_cim.uint32,
    CIM_TYPES.CHAR16: c_cim.wchar,
}

ClassDefinitionPropertyState = namedtuple("ClassDefinitionPropertyState", ["is_inherited", "has_default_value"])
ClassInstancePropertyState = namedtuple("ClassInstancePropertyState", ["use_default_value", "is_initialized"])
