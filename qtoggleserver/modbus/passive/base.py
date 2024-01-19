import abc
import asyncio
import logging
import math

from typing import Any, List, Optional, Union

from pymodbus import Framer, bit_read_message, bit_write_message, register_read_message, register_write_message
from pymodbus.client.base import ModbusBaseClient as InternalModbusBaseClient

from qtoggleserver.utils import logging as logging_utils


class InternalPassiveException(Exception):
    pass


class InvalidModbusFrame(InternalPassiveException):
    pass


class InternalPassiveClient(InternalModbusBaseClient, logging_utils.LoggableMixin, metaclass=abc.ABCMeta):
    MODBUS_FUNC_READ_COILS = 0x01
    MODBUS_FUNC_READ_DISCRETE_INPUTS = 0x02
    MODBUS_FUNC_READ_HOLDING_REGISTERS = 0x03
    MODBUS_FUNC_READ_INPUT_REGISTERS = 0x04
    MODBUS_FUNC_WRITE_SINGLE_COIL = 0x05
    MODBUS_FUNC_WRITE_SINGLE_REGISTER = 0x6
    MODBUS_FUNC_WRITE_MULTIPLE_COILS = 0x15
    MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS = 0x16

    ALL_FUNCTIONS = {
        MODBUS_FUNC_READ_COILS,
        MODBUS_FUNC_READ_DISCRETE_INPUTS,
        MODBUS_FUNC_READ_HOLDING_REGISTERS,
        MODBUS_FUNC_READ_INPUT_REGISTERS,
        MODBUS_FUNC_WRITE_SINGLE_COIL,
        MODBUS_FUNC_WRITE_SINGLE_REGISTER,
        MODBUS_FUNC_WRITE_MULTIPLE_COILS,
        MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS,
    }
    WATCHED_FUNCTIONS = {
        MODBUS_FUNC_READ_COILS,
        MODBUS_FUNC_READ_DISCRETE_INPUTS,
        MODBUS_FUNC_READ_HOLDING_REGISTERS,
        MODBUS_FUNC_READ_INPUT_REGISTERS,
    }

    def __init__(self, logger: logging.Logger) -> None:
        self._coil_values: dict[int, bool] = {}
        self._discrete_input_values: dict[int, bool] = {}
        self._holding_register_values: dict[int, int] = {}
        self._input_register_values: dict[int, int] = {}
        self._run_task: Optional[asyncio.Task] = None

        self._last_read_coils_request: Optional[dict[str, Any]] = None
        self._last_read_discrete_inputs_request: Optional[dict[str, Any]] = None
        self._last_read_holding_registers_request: Optional[dict[str, Any]] = None
        self._last_read_input_registers_request: Optional[dict[str, Any]] = None

        InternalModbusBaseClient.__init__(self, framer=Framer.RTU)
        logging_utils.LoggableMixin.__init__(self, 'passive', logger)

    @abc.abstractmethod
    async def run(self) -> None:
        pass

    async def _run(self) -> None:
        try:
            await self.run()
        finally:
            self._run_task = None

    async def connect(self) -> None:
        if not self._run_task:
            self._run_task = asyncio.create_task(self._run())

    def close(self, reconnect: bool = False) -> None:
        if self._run_task:
            self._run_task.cancel()
            self._run_task = None

    @property
    def connected(self) -> bool:
        return bool(self._run_task)

    def get_coil_value(self, address: int) -> bool:
        return self._coil_values.get(address)

    def set_coil_value(self, address: int, value: bool) -> None:
        self._coil_values[address] = value

    def get_discrete_input_value(self, address: int) -> bool:
        return self._discrete_input_values.get(address)

    def set_discrete_input_value(self, address: int, value: bool) -> None:
        self._discrete_input_values[address] = value

    def get_input_register_value(self, address: int) -> int:
        return self._input_register_values.get(address)

    def set_input_register_value(self, address: int, value: int) -> None:
        self._input_register_values[address] = value

    def get_holding_register_value(self, address: int) -> int:
        return self._holding_register_values.get(address)

    def set_holding_register_value(self, address: int, value: int) -> None:
        self._holding_register_values[address] = value

    async def read_coils(
        self, address: int, count: int = 1, slave: int = 0, **kwargs
    ) -> bit_read_message.ReadCoilsResponse:
        return bit_read_message.ReadCoilsResponse(
            values=[self.get_coil_value(address + i) for i in range(count)]
        )

    async def read_discrete_inputs(
        self, address: int, count: int = 1, slave: int = 0, **kwargs
    ) -> bit_read_message.ReadDiscreteInputsResponse:
        return bit_read_message.ReadDiscreteInputsResponse(
            values=[self.get_discrete_input_value(address + i) for i in range(count)]
        )

    async def read_input_registers(
        self, address: int, count: int = 1, slave: int = 0, **kwargs
    ) -> register_read_message.ReadInputRegistersResponse:
        return register_read_message.ReadInputRegistersResponse(
            values=[self.get_input_register_value(address + i) for i in range(count)]
        )

    async def read_holding_registers(
        self, address: int, count: int = 1, slave: int = 0, **kwargs
    ) -> register_read_message.ReadHoldingRegistersResponse:
        return register_read_message.ReadHoldingRegistersResponse(
            values=[self.get_holding_register_value(address + i) for i in range(count)]
        )

    async def write_coil(
        self, address: int, value: bool, slave: int = 0, **kwargs
    ) -> bit_write_message.WriteSingleCoilResponse:
        raise InternalPassiveException('Operation not supported in passive mode')

    async def write_coils(
        self, address: int, values: List[bool], slave: int = 0, **kwargs
    ) -> bit_write_message.WriteMultipleCoilsResponse:
        raise InternalPassiveException('Operation not supported in passive mode')

    async def write_register(
        self, address: int, value: Union[int, float, str], slave: int = 0, **kwargs
    ) -> register_write_message.WriteSingleRegisterResponse:
        raise InternalPassiveException('Operation not supported in passive mode')

    async def write_registers(
        self,
        address: int,
        values: List[Union[int, float, str]],
        slave: int = 0,
        **kwargs,
    ) -> register_write_message.WriteMultipleRegistersResponse:
        raise InternalPassiveException('Operation not supported in passive mode')

    def process_read_coils_request(self, data: bytes) -> None:
        self._last_read_coils_request = {
            'address': int.from_bytes(data[:2], byteorder='big', signed=False),
            'count': int.from_bytes(data[2:4], byteorder='big', signed=False),
        }
        self.debug(
            'read coils request (address = %d, count = %d)',
            self._last_read_coils_request['address'],
            self._last_read_coils_request['count'],
        )

    def process_read_discrete_inputs_request(self, data: bytes) -> None:
        self._last_read_discrete_inputs_request = {
            'address': int.from_bytes(data[:2], byteorder='big', signed=False),
            'count': int.from_bytes(data[2:4], byteorder='big', signed=False),
        }
        self.debug(
            'read discrete inputs request (address = %d, count = %d)',
            self._last_read_discrete_inputs_request['address'],
            self._last_read_discrete_inputs_request['count'],
        )

    def process_read_holding_registers_request(self, data: bytes) -> None:
        self._last_read_holding_registers_request = {
            'address': int.from_bytes(data[:2], byteorder='big', signed=False),
            'count': int.from_bytes(data[2:4], byteorder='big', signed=False),
        }
        self.debug(
            'read holding registers request (address = %d, count = %d)',
            self._last_read_holding_registers_request['address'],
            self._last_read_holding_registers_request['count'],
        )

    def process_read_input_registers_request(self, data: bytes) -> None:
        self._last_read_input_registers_request = {
            'address': int.from_bytes(data[:2], byteorder='big', signed=False),
            'count': int.from_bytes(data[2:4], byteorder='big', signed=False),
        }
        self.debug(
            'read input registers request (address = %d, count = %d)',
            self._last_read_input_registers_request['address'],
            self._last_read_input_registers_request['count'],
        )

    def process_read_coils_response(self, data: bytes) -> None:
        if not self._last_read_coils_request:
            self.warning('ignoring read coils response without request')
            return

        if len(data) < 1:
            raise InvalidModbusFrame('Data too short (%s bytes)', len(data))
        byte_count = data[0]
        if len(data) != byte_count + 1:
            raise InvalidModbusFrame('Unexpected number of data bytes (%s != %s)', len(data), byte_count)
        expected_byte_count = math.ceil(self._last_read_coils_request['count'] / 8)
        if expected_byte_count != byte_count:
            self.warning('ignoring read coils response with different address count')
            return

        bits = int.from_bytes(data[1:], byteorder='little', signed=False)
        bit_string = f'{bits:b}'
        values = [b == '1' for b in reversed(bit_string)]
        for i, v in enumerate(values):
            self.set_coil_value(self._last_read_coils_request['address'] + i, v)

        self.debug('read coils response (values = [%s])', ', '.join(str(v).lower() for v in values))

        self._last_read_coils_request = None

    def process_read_discrete_inputs_response(self, data: bytes) -> None:
        if not self._last_read_discrete_inputs_request:
            self.warning('ignoring read discrete inputs response without request')
            return

        if len(data) < 1:
            raise InvalidModbusFrame('Data too short (%s bytes)', len(data))
        byte_count = data[0]
        if len(data) != byte_count + 1:
            raise InvalidModbusFrame('Unexpected number of data bytes (%s != %s)', len(data), byte_count)
        expected_byte_count = math.ceil(self._last_read_discrete_inputs_request['count'] / 8)
        if expected_byte_count != byte_count:
            self.warning('ignoring read discrete inputs response with different address count')
            return

        bits = int.from_bytes(data[1:], byteorder='little', signed=False)
        bit_string = f'{bits:b}'
        values = [b == '1' for b in reversed(bit_string)]
        for i, v in enumerate(values):
            self.set_discrete_input_value(self._last_read_discrete_inputs_request['address'] + i, v)

        self.debug('read discrete inputs response (values = [%s])', ', '.join(str(v).lower() for v in values))

        self._last_read_discrete_inputs_request = None

    def process_read_holding_registers_response(self, data: bytes) -> None:
        if not self._last_read_holding_registers_request:
            self.warning('ignoring read holding registers response without request')
            return

        if len(data) < 1:
            raise InvalidModbusFrame('Data too short (%s bytes)', len(data))
        byte_count = data[0]
        if len(data) != byte_count + 1:
            raise InvalidModbusFrame('Unexpected number of data bytes (%s != %s)', len(data), byte_count)
        expected_byte_count = self._last_read_holding_registers_request['count'] * 2
        if expected_byte_count != byte_count:
            self.warning('ignoring read holding registers response with different address count')
            return

        values = []
        for i in range(self._last_read_holding_registers_request['count']):
            value = int.from_bytes(data[i * 2 + 1: i * 2 + 3], byteorder='big', signed=False)
            values.append(value)
            self.set_holding_register_value(self._last_read_holding_registers_request['address'] + i, value)

        self.debug('read holding registers response (values = [%s])', ', '.join(f'0x{v:04X}' for v in values))

        self._last_read_holding_registers_request = None

    def process_read_input_registers_response(self, data: bytes) -> None:
        if not self._last_read_input_registers_request:
            self.warning('ignoring read input registers response without request')
            return

        if len(data) < 1:
            raise InvalidModbusFrame('Data too short (%s bytes)', len(data))
        byte_count = data[0]
        if len(data) != byte_count + 1:
            raise InvalidModbusFrame('Unexpected number of data bytes (%s != %s)', len(data), byte_count)
        expected_byte_count = self._last_read_input_registers_request['count'] * 2
        if expected_byte_count != byte_count:
            self.warning('ignoring read input registers response with different address count')
            return

        values = []
        for i in range(self._last_read_input_registers_request['count']):
            value = int.from_bytes(data[i * 2 + 1: i * 2 + 3], byteorder='big', signed=False)
            values.append(value)
            self.set_input_register_value(self._last_read_input_registers_request['address'] + i, value)

        self.debug('read input registers response (values = [%s])', ', '.join(f'0x{v:04X}' for v in values))

        self._last_read_input_registers_request = None

    @staticmethod
    def compute_crc(data: bytes) -> bytes:
        crc = 0xFFFF
        for b in data:
            crc = (crc ^ b) & 0xFFFF

            for i in range(8, 0, -1):
                if (crc & 0x0001) != 0:
                    crc >>= 1
                    crc ^= 0xA001
                else:
                    crc >>= 1

        return crc.to_bytes(2, byteorder='little', signed=False)
