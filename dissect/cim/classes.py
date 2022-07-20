from io import BytesIO

from dissect.util.ts import wintimestamp

from dissect.cim.c_cim import (
    c_cim,
    ARRAY_STATES,
    BOOLEAN_STATES,
    BUILTIN_PROPERTIES,
    BUILTIN_QUALIFIERS,
    CIM_TYPES,
    CIM_TYPES_MAP,
    DYNPROPS_STATES,
    ClassDefinitionPropertyState,
    ClassInstancePropertyState,
)
from dissect.cim.exceptions import Error


class QualifierReference:
    def __init__(self, fh):
        self.fh = fh
        self.qualifier_reference = c_cim.qualifier_reference(fh)
        self.key_reference = self.qualifier_reference.key_reference
        self.type = self.qualifier_reference.type

        if self.type.array_state == ARRAY_STATES.ARRAY:
            ctype = c_cim.uint32
        else:
            ctype = CIM_TYPES_MAP[self.type.type]
        self.data = fh.read(len(ctype))
        self.value = ctype(self.data)

    def __repr__(self):
        return "<QualifierReference>"

    @classmethod
    def read_list(cls, fh):
        res = []
        length = c_cim.uint32(fh)
        end = fh.tell() + length
        while fh.tell() + 9 <= end:
            res.append(cls(fh))
        return res

    @property
    def is_builtin_key(self):
        return self.key_reference & 0x80000000 > 0

    @property
    def key(self):
        return self.key_reference & 0x7FFFFFFF


class PropertyReference:
    def __init__(self, fh):
        self.fh = fh
        self.property_reference = c_cim.property_reference(fh)
        self.name_offset = self.property_reference.name_offset
        self.property_offset = self.property_reference.property_offset

    def __repr__(self):
        return "<PropertyReference>"

    @classmethod
    def read_list(cls, fh):
        length = c_cim.uint32(fh)
        return [cls(fh) for _ in range(length)]

    @property
    def is_builtin_property(self):
        return self.name_offset & 0x80000000 > 0

    @property
    def builtin_property_name(self):
        if not self.is_builtin_property:
            raise ValueError("Not a builtin")
        key = self.name_offset & 0x7FFFFFFF
        return BUILTIN_PROPERTIES(key).name


class PropertyStates:
    def __init__(self, fh, bit_tuple, num_properties):
        self.fh = fh
        self.bit_tuple = bit_tuple
        self.num_properties = num_properties
        self.entries = c_cim.uint8[self._property_state_length()](fh)

    def __getitem__(self, idx):
        if idx > self.num_properties:
            raise IndexError("Invalid property index")

        byte_of_state = self.entries[idx // 4]
        rotations = idx % 4
        state_flags = (byte_of_state >> (2 * rotations)) & 0x3
        return self.bit_tuple(state_flags & 0b10 > 0, state_flags & 0b01 == 0)

    def _property_state_length(self):
        required_bits = 2 * self.num_properties
        delta_to_nearest_byte = (8 - required_bits) % 8
        total_bits = required_bits + delta_to_nearest_byte
        total_bytes = total_bits // 8
        return total_bytes


class PropertyDefaultValues:
    def __init__(self, fh, properties):
        self.fh = fh
        self.properties = properties
        self.state = PropertyStates(fh, ClassDefinitionPropertyState, len(properties))
        self.default_values = []

        for prop in self.properties:
            self.default_values.append(prop.ctype(fh))


class ClassDefinitionProperty:
    def __init__(self, data, propref):
        self._data = data
        self._propref = propref

        buf = data.open()
        buf.seek(propref.property_offset)
        self.property = c_cim.class_definition_property(buf)
        self.qualifier_references = QualifierReference.read_list(buf)

        if propref.is_builtin_property:
            self.name = propref.builtin_property_name
        else:
            self.name = data.get_string(propref.name_offset)
        self.type = self.property.type

        if self.type.array_state == ARRAY_STATES.ARRAY:
            self.ctype = c_cim.uint32
        else:
            self.ctype = CIM_TYPES_MAP[self.type.type]

        self.index = self.property.index
        self.offset = self.property.offset
        self.level = self.property.level

        self.qualifiers = {}
        for q_ref in self.qualifier_references:
            qualifier = Qualifier(data, q_ref)
            self.qualifiers[qualifier.key] = qualifier


class ClassInstanceProperty:
    def __init__(self, class_instance, prop, value, state):
        self.class_instance = class_instance
        self._prop = prop
        self._value = value
        self.state = state

    @property
    def type(self):
        return self._prop.type

    @property
    def qualifiers(self):
        return self._prop.qualifiers

    @property
    def name(self):
        return self._prop.name

    @property
    def index(self):
        return self._prop.index

    @property
    def offset(self):
        return self._prop.offset

    @property
    def level(self):
        return self._prop.level

    @property
    def is_inherited(self):
        return self._prop.is_inherited

    @property
    def has_default_value(self):
        return self._prop.has_default_value

    @property
    def default_value(self):
        return self._prop.default_value

    @property
    def is_initialized(self):
        return self.state.is_initialized

    @property
    def is_default_value(self):
        if self.is_initialized:
            return self.state.use_default_value
        return False

    @property
    def value(self):
        if not self.is_initialized:
            raise ValueError("Property is not initialized")
        return self._value


class ClassDefinition:
    def __init__(self, cim, fh):
        self.cim = cim
        self.fh = fh
        self.header = c_cim.class_definition_header(fh)

        self.qualifier_references = QualifierReference.read_list(fh)
        self.property_references = PropertyReference.read_list(fh)

        self.default_values_data = fh.read(self.header.default_values_metadata_size)
        self.property_data = DataRegion(fh)
        self.method_data = DataRegion(fh)

    @property
    def qualifiers(self):
        qualifiers = {}
        for ref in self.qualifier_references:
            qualifier = Qualifier(self.property_data, ref)
            qualifiers[qualifier.key] = qualifier
        return qualifiers

    @property
    def properties(self):
        properties = {}
        for ref in self.property_references:
            prop = ClassDefinitionProperty(self.property_data, ref)
            properties[prop.name] = prop
        return properties

    @property
    def keys(self):
        keys = []
        for prop_name, prop in self.properties.items():
            for k, v in prop.qualifiers.items():
                if k == BUILTIN_QUALIFIERS.PROP_QUALIFIER_KEY.name and v.value is True:
                    keys.append(prop_name)
        return keys

    @property
    def class_name(self):
        return self.property_data.get_string(self.header.class_name_offset)

    @property
    def super_class_name(self):
        return self.header.super_class_name

    @property
    def timestamp(self):
        return wintimestamp(self.header.timestamp)


class ClassInstance:
    def __init__(self, cim, class_, fh):
        self.cim = cim
        self.class_ = class_
        self.fh = fh

        self.header = c_cim.class_instance_xp_header(fh) if self.cim.type_xp else c_cim.class_instance_header(fh)

        self.name_hash = self.header.name_hash
        self.ts1 = wintimestamp(self.header.ts1)
        self.ts2 = wintimestamp(self.header.ts2)

        buf = BytesIO(self.header.remaining_data)
        self.property_states = PropertyStates(buf, ClassInstancePropertyState, len(class_.properties))

        self.toc = []
        for p in sorted(class_.properties.values(), key=lambda p: p.index):
            self.toc.append(p.ctype(buf))

        self.qualifier_references = QualifierReference.read_list(buf)
        self.dynprops = Dynprops(buf)
        self.data = DataRegion(buf)

        self._properties = None

    @property
    def class_name(self):
        return self.data.get_string(0)

    @property
    def qualifiers(self):
        qualifiers = {}
        for ref in self.qualifier_references:
            qualifier = Qualifier(self.data, ref)
            qualifiers[qualifier.key] = qualifier
        return qualifiers

    @property
    def properties(self):
        if self._properties is None:
            properties = {}
            for prop in self.class_.properties.values():
                state = self.property_states[prop.index]

                value = None
                if state.is_initialized:
                    if state.use_default_value:
                        value = prop.default_value
                    else:
                        value = self.data.get_value(self.toc[prop.index], prop.type)

                properties[prop.name] = ClassInstanceProperty(self, prop, value, state)
            self._properties = properties
        return self._properties

    @property
    def key(self):
        key = InstanceKey()
        for prop_name in self.class_.class_definition.keys:
            key[prop_name] = self.properties[prop_name].value
        return key


class InstanceKey(dict):
    def __getattr__(self, key):
        return self[key]

    def __setattr__(self, key, value):
        self[key] = value

    def __str__(self):
        if len(self) == 0:
            return "default"
        return ";".join([f"{key}={value}" for key, value in self.items()])


class Qualifier:
    def __init__(self, data, qualref):
        self._data = data
        self._qualref = qualref

        if qualref.is_builtin_key:
            self.key = BUILTIN_QUALIFIERS(qualref.key).name
        else:
            self.key = data.get_string(qualref.key)
        self.value = data.get_value(qualref.value, qualref.type)


class Dynprops:
    def __init__(self, fh):
        self.fh = fh
        self.dynprops_state = DYNPROPS_STATES._read(fh)
        self.dynprops = None

        if self.has_dynprops:
            c_cim.uint32(fh)
            c_cim.uint32(fh)

    @property
    def has_dynprops(self):
        return self.dynprops_state == DYNPROPS_STATES.HAS_DYNPROPS


class DynpropQualifier:
    def __init__(self, fh):
        self.fh = fh


class DataRegion:
    def __init__(self, fh):
        self.fh = fh
        self.size = c_cim.uint32(fh) & 0x7FFFFFFF
        self.data = fh.read(self.size)

    def open(self):
        return BytesIO(self.data)

    def get_string(self, offset):
        encoding_flag = self.data[offset]

        if encoding_flag == 0:
            data_str = c_cim.char[None](self.data[offset + 1 :]).decode("latin1")
        elif encoding_flag == 1:
            data_str = c_cim.wchar[None](self.data[offset + 1 :])
        else:
            raise Error(f"Invalid encoding flag encountered ({encoding_flag})")

        return data_str

    def get_array(self, offset, item_type):
        ctype = CIM_TYPES_MAP[item_type.type]

        buf = self.open()
        buf.seek(offset)
        size = c_cim.uint32(buf)
        return ctype[size](buf)

    def get_value(self, value, value_type):
        if value_type.array_state == ARRAY_STATES.ARRAY:
            return self.get_array(value, value_type)

        t = value_type.type
        if t in (CIM_TYPES.STRING, CIM_TYPES.REFERENCE, CIM_TYPES.DATETIME):
            return self.get_string(value)
        elif t == CIM_TYPES.BOOLEAN:
            return value == BOOLEAN_STATES.TRUE
        else:
            ValueError("Unknown value type")
