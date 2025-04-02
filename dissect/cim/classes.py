from __future__ import annotations

from functools import cached_property
from io import BytesIO
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.util.ts import wintimestamp

from dissect.cim.c_cim import (
    ARRAY_STATES,
    BOOLEAN_STATES,
    BUILTIN_PROPERTIES,
    BUILTIN_QUALIFIERS,
    CIM_TYPES,
    CIM_TYPES_MAP,
    DYNPROPS_STATES,
    CimType,
    ClassDefinitionPropertyState,
    ClassInstancePropertyState,
    c_cim,
)
from dissect.cim.exceptions import Error

if TYPE_CHECKING:
    from datetime import datetime

    from dissect.cim.cim import CIM, Class, Property


class QualifierReference:
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.qualifier_reference = c_cim.qualifier_reference(fh)
        self.key_reference = self.qualifier_reference.key_reference
        self.type = self.qualifier_reference.type

        ctype = c_cim.uint32 if self.type.array_state == ARRAY_STATES.ARRAY else CIM_TYPES_MAP[self.type.type]
        self.data = fh.read(len(ctype))
        self.value: CimType | BOOLEAN_STATES = ctype(self.data)

    def __repr__(self) -> str:
        return "<QualifierReference>"

    @classmethod
    def read_list(cls, fh: BinaryIO) -> list[QualifierReference]:
        res = []
        length = c_cim.uint32(fh)
        end = fh.tell() + length
        while fh.tell() + 9 <= end:
            res.append(cls(fh))
        return res

    @property
    def is_builtin_key(self) -> bool:
        return self.key_reference & 0x80000000 > 0

    @property
    def key(self) -> bool:
        return self.key_reference & 0x7FFFFFFF


class PropertyReference:
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.property_reference = c_cim.property_reference(fh)
        self.name_offset = self.property_reference.name_offset
        self.property_offset = self.property_reference.property_offset

    def __repr__(self) -> str:
        return "<PropertyReference>"

    @classmethod
    def read_list(cls, fh: BinaryIO) -> list[PropertyReference]:
        length = c_cim.uint32(fh)
        return [cls(fh) for _ in range(length)]

    @property
    def is_builtin_property(self) -> bool:
        return self.name_offset & 0x80000000 > 0

    @property
    def builtin_property_name(self) -> str:
        if not self.is_builtin_property:
            raise ValueError("Not a builtin")
        key = self.name_offset & 0x7FFFFFFF
        return BUILTIN_PROPERTIES(key).name


class PropertyStates:
    def __init__(
        self, fh: BinaryIO, state_cls: ClassDefinitionPropertyState | ClassInstancePropertyState, num_properties: int
    ):
        self.fh = fh
        self.state_cls = state_cls
        self.num_properties = num_properties
        self.entries = c_cim.uint8[self._property_state_length()](fh)

    def __getitem__(self, idx: int) -> ClassDefinitionPropertyState | ClassInstancePropertyState:
        if idx > self.num_properties:
            raise IndexError("Invalid property index")

        byte_of_state = self.entries[idx // 4]
        rotations = idx % 4
        state_flags = (byte_of_state >> (2 * rotations)) & 0x3
        return self.state_cls(state_flags & 0b10 > 0, state_flags & 0b01 == 0)

    def _property_state_length(self) -> int:
        required_bits = 2 * self.num_properties
        delta_to_nearest_byte = (8 - required_bits) % 8
        total_bits = required_bits + delta_to_nearest_byte
        return total_bits // 8


class PropertyDefaultValues:
    def __init__(self, fh: BinaryIO, properties: list[Property]):
        self.fh = fh
        self.properties = properties
        self.state = PropertyStates(fh, ClassDefinitionPropertyState, len(properties))
        self.default_values = []

        for prop in self.properties:
            self.default_values.append(prop.ctype(fh))


class ClassDefinitionProperty:
    def __init__(self, data: DataRegion, propref: PropertyReference):
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

        self.qualifiers: dict[str, Qualifier] = {}
        for q_ref in self.qualifier_references:
            qualifier = Qualifier(data, q_ref)
            self.qualifiers[qualifier.key] = qualifier


class ClassInstanceProperty:
    def __init__(
        self,
        class_instance: ClassInstance,
        prop: Property,
        value: CimType | list[CimType],
        state: ClassDefinitionPropertyState | ClassInstancePropertyState,
    ):
        self.class_instance = class_instance
        self._prop = prop
        self._value = value
        self.state = state

    @property
    def type(self) -> c_cim.cim_type:
        return self._prop.type

    @property
    def qualifiers(self) -> dict[str, Qualifier]:
        return self._prop.qualifiers

    @property
    def name(self) -> str:
        return self._prop.name

    @property
    def index(self) -> int:
        return self._prop.index

    @property
    def offset(self) -> int:
        return self._prop.offset

    @property
    def level(self) -> int:
        return self._prop.level

    @property
    def is_inherited(self) -> bool:
        return self._prop.is_inherited

    @property
    def has_default_value(self) -> bool:
        return self._prop.has_default_value

    @property
    def default_value(self) -> CimType | list[CimType]:
        return self._prop.default_value

    @property
    def is_initialized(self) -> bool:
        return self.state.is_initialized

    @property
    def is_default_value(self) -> bool:
        if self.is_initialized:
            return self.state.use_default_value
        return False

    @property
    def value(self) -> CimType | list[CimType]:
        if not self.is_initialized:
            raise ValueError("Property is not initialized")
        return self._value


class ClassDefinition:
    def __init__(self, cim: CIM, fh: BinaryIO):
        self.cim = cim
        self.fh = fh
        self.header = c_cim.class_definition_header(fh)

        self.qualifier_references = QualifierReference.read_list(fh)
        self.property_references = PropertyReference.read_list(fh)

        self.default_values_data = fh.read(self.header.default_values_metadata_size)
        self.property_data = DataRegion(fh)
        self.method_data = DataRegion(fh)

    @property
    def qualifiers(self) -> dict[str, Qualifier]:
        qualifiers = {}
        for ref in self.qualifier_references:
            qualifier = Qualifier(self.property_data, ref)
            qualifiers[qualifier.key] = qualifier
        return qualifiers

    @property
    def properties(self) -> dict[str, ClassDefinitionProperty]:
        properties = {}
        for ref in self.property_references:
            prop = ClassDefinitionProperty(self.property_data, ref)
            properties[prop.name] = prop
        return properties

    @property
    def keys(self) -> list[str]:
        keys = []
        for prop_name, prop in self.properties.items():
            for k, v in prop.qualifiers.items():
                if k == BUILTIN_QUALIFIERS.PROP_QUALIFIER_KEY.name and v.value is True:
                    keys.append(prop_name)
        return keys

    @property
    def class_name(self) -> str:
        return self.property_data.get_string(self.header.class_name_offset)

    @property
    def super_class_name(self) -> str:
        return self.header.super_class_name

    @property
    def timestamp(self) -> datetime:
        return wintimestamp(self.header.timestamp)


class ClassInstance:
    def __init__(self, cim: CIM, class_: Class, fh: BinaryIO):
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

    @property
    def class_name(self) -> str:
        return self.data.get_string(0)

    @property
    def qualifiers(self) -> dict[str, Qualifier]:
        qualifiers = {}
        for ref in self.qualifier_references:
            qualifier = Qualifier(self.data, ref)
            qualifiers[qualifier.key] = qualifier
        return qualifiers

    @cached_property
    def properties(self) -> dict[str, ClassInstanceProperty]:
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

        return properties

    @property
    def key(self) -> InstanceKey:
        key = InstanceKey()
        for prop_name in self.class_.class_definition.keys:
            key[prop_name] = self.properties[prop_name].value
        return key


class InstanceKey(dict):
    """A dictionary subclass that allows for attribute-style access and assignment.

    Is represented as a string in the format "key1=value1;key2=value2" or "default" if empty.

    Example:

        >>> d = InstanceKey()
        >>> d.foo = "bar"
        >>> d.foo
        "bar"
    """

    def __getattr__(self, key: str) -> Any:
        return self[key]

    def __setattr__(self, key: str, value: Any):
        self[key] = value

    def __str__(self) -> str:
        if len(self) == 0:
            return "default"
        return ";".join([f"{key}={value}" for key, value in self.items()])


class Qualifier:
    def __init__(self, data: DataRegion, qualref: QualifierReference):
        self._data = data
        self._qualref = qualref

        if qualref.is_builtin_key:
            self.key = BUILTIN_QUALIFIERS(qualref.key).name
        else:
            self.key = data.get_string(qualref.key)
        self.value = data.get_value(qualref.value, qualref.type)


class Dynprops:
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.dynprops_state = DYNPROPS_STATES._read(fh)
        self.dynprops = None

        if self.has_dynprops:
            c_cim.uint32(fh)
            c_cim.uint32(fh)

    @property
    def has_dynprops(self) -> bool:
        return self.dynprops_state == DYNPROPS_STATES.HAS_DYNPROPS


class DynpropQualifier:
    def __init__(self, fh: BinaryIO):
        self.fh = fh


class DataRegion:
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.size = c_cim.uint32(fh) & 0x7FFFFFFF
        self.data = fh.read(self.size)

    def open(self) -> BytesIO:
        return BytesIO(self.data)

    def get_string(self, offset: int) -> str:
        encoding_flag = self.data[offset]

        if encoding_flag == 0:
            data_str = c_cim.char[None](self.data[offset + 1 :]).decode("latin1")
        elif encoding_flag == 1:
            data_str = c_cim.wchar[None](self.data[offset + 1 :])
        else:
            raise Error(f"Invalid encoding flag encountered ({encoding_flag})")

        return data_str

    def get_array(self, offset: int, item_type: c_cim.cim_type) -> list[CimType]:
        ctype = CIM_TYPES_MAP[item_type.type]

        buf = self.open()
        buf.seek(offset)
        size = c_cim.uint32(buf)
        return ctype[size](buf)

    def get_value(self, value: CimType | BOOLEAN_STATES, value_type: c_cim.cim_type) -> CimType | list[CimType]:
        if value_type.array_state == ARRAY_STATES.ARRAY:
            return self.get_array(value, value_type)

        t = value_type.type
        if t in (CIM_TYPES.STRING, CIM_TYPES.REFERENCE, CIM_TYPES.DATETIME):
            return self.get_string(value)

        if t in (
            CIM_TYPES.INT8,
            CIM_TYPES.UINT8,
            CIM_TYPES.INT16,
            CIM_TYPES.UINT16,
            CIM_TYPES.INT32,
            CIM_TYPES.UINT32,
            CIM_TYPES.INT64,
            CIM_TYPES.UINT64,
        ):
            return value

        if t == CIM_TYPES.BOOLEAN:
            return value == BOOLEAN_STATES.TRUE

        raise ValueError("Unknown value type")
