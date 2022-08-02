import struct

from typing import cast, Optional, Union

from qtoggleserver.core import ports as core_ports
from qtoggleserver.core.typing import NullablePortValue, PortValue
from qtoggleserver.lib import polled

from . import constants
from .client import BaseModbusClient


TYPE_MAPPING = {
    constants.MODBUS_TYPE_COIL: core_ports.TYPE_BOOLEAN,
    constants.MODBUS_TYPE_DISCRETE_INPUT: core_ports.TYPE_BOOLEAN,
    constants.MODBUS_TYPE_INPUT_REGISTER: core_ports.TYPE_NUMBER,
    constants.MODBUS_TYPE_HOLDING_REGISTER: core_ports.TYPE_NUMBER,
}

WRITABLE_MAPPING = {
    constants.MODBUS_TYPE_COIL: True,
    constants.MODBUS_TYPE_DISCRETE_INPUT: False,
    constants.MODBUS_TYPE_INPUT_REGISTER: False,
    constants.MODBUS_TYPE_HOLDING_REGISTER: True,
}

STRUCT_TYPE_MAPPING = {
    'b': int,
    'B': int,
    '?': bool,
    'h': int,
    'H': int,
    'i': int,
    'I': int,
    'l': int,
    'L': int,
    'q': int,
    'Q': int,
    'n': int,
    'N': int,
    'e': float,
    'f': float,
    'd': float,
}


class ModbusClientPort(polled.PolledPort):
    DEFAULT_VALUE_FMT = '>h'

    def __init__(
        self,
        *,
        id: str,
        modbus_type: str,
        address: Union[int, str],
        length: int = 1,
        writable: Optional[bool] = None,
        register_group_fmt: Optional[str] = None,
        value_fmt: str = DEFAULT_VALUE_FMT,
        **kwargs
    ) -> None:
        if isinstance(address, str):
            address = int(address, base=0)

        # These will directly determine the port type & writable attributes
        self._type: str = TYPE_MAPPING[modbus_type]
        self._writable: bool = writable if writable is not None else WRITABLE_MAPPING[modbus_type]

        self._modbus_type: str = modbus_type
        self._address: int = address
        self._length: int = length
        self._register_group_fmt: str = register_group_fmt if register_group_fmt else f'>{"H" * length}'
        self._value_fmt: str = value_fmt

        super().__init__(id=id, **kwargs)

    def get_peripheral(self) -> BaseModbusClient:
        return cast(BaseModbusClient, super().get_peripheral())

    async def read_value(self) -> NullablePortValue:
        client = self.get_peripheral()

        group_fmt = self._register_group_fmt
        value_fmt = self._value_fmt
        values = []
        if self._modbus_type in (constants.MODBUS_TYPE_COIL, constants.MODBUS_TYPE_DISCRETE_INPUT):
            group_fmt = value_fmt = '?'
            if self._modbus_type == constants.MODBUS_TYPE_COIL:
                value = client.get_last_coil_value(self._address)
            else:
                value = client.get_last_discrete_input_value(self._address)
            values = [value] if value is not None else None
        elif self._modbus_type == constants.MODBUS_TYPE_INPUT_REGISTER:
            values = client.get_last_input_register_values(self._address, self._length)
        elif self._modbus_type == constants.MODBUS_TYPE_HOLDING_REGISTER:
            values = client.get_last_holding_register_values(self._address, self._length)

        if values is None:
            return

        value_bytes = struct.pack(group_fmt, *values)
        value = struct.unpack(value_fmt, value_bytes)[0]

        return value

    async def write_value(self, value: PortValue) -> None:
        client = self.get_peripheral()

        if self._modbus_type == constants.MODBUS_TYPE_COIL:
            await client.write_coil_value(self._address, value)
        elif self._modbus_type == constants.MODBUS_TYPE_HOLDING_REGISTER:
            value_bytes = struct.pack(self._value_fmt, *self._adapt_value_to_fmt(value))
            values = list(struct.unpack(self._register_group_fmt, value_bytes))
            await client.write_holding_register_values(self._address, values)

    def _adapt_value_to_fmt(self, value: PortValue) -> list:
        type_ = STRUCT_TYPE_MAPPING.get(self._value_fmt[1], int)
        return [type_(value)]
