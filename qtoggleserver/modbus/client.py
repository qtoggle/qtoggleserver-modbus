import abc
import asyncio

from typing import Any, Dict, Optional, List, Tuple, Type, Union

from pymodbus.client.asynchronous import schedulers
from pymodbus.client.asynchronous.async_io import ModbusClientProtocol
from pymodbus.client.asynchronous.tcp import AsyncModbusTCPClient
from pymodbus.client.sync import BaseModbusClient as BasePyModbusClient
from pymodbus.factory import ClientDecoder
from pymodbus.transaction import ModbusRtuFramer
from serial_asyncio import create_serial_connection

from qtoggleserver.core import ports as core_ports
from qtoggleserver.lib import polled
from qtoggleserver.utils import json as json_utils

from . import constants
from .base import BaseModbus


class BaseModbusClient(polled.PolledPeripheral, BaseModbus, metaclass=abc.ABCMeta):
    DEFAULT_POLL_INTERVAL = 5

    def __init__(self, **kwargs) -> None:
        polled.PolledPeripheral.__init__(self, **kwargs)
        BaseModbus.__init__(self, **kwargs)

        self._values_by_type_and_address: Dict[str, Dict[int, Any]] = {}
        self._lengths_by_type_and_address: Dict[str, Dict[int, int]] = {}
        for port_detail in self.port_details.values():
            address = port_detail['address']
            # Convert string numbers (e.g. hex) to integer
            if isinstance(address, str):
                address = int(address, base=0)
            lengths_by_address = self._lengths_by_type_and_address.setdefault(port_detail['modbus_type'], {})
            length = port_detail.get('length', 1)
            lengths_by_address[address] = length

        # Merge intersecting address spaces
        for modbus_type, lengths_by_address in self._lengths_by_type_and_address.items():
            lengths_by_address_items = list(lengths_by_address.items())
            i = 0
            while i < len(lengths_by_address_items) - 1:
                j = i + 1
                while j < len(lengths_by_address_items):
                    address1, length1 = lengths_by_address_items[i]
                    address2, length2 = lengths_by_address_items[j]
                    merged = self._try_merge_address_length(address1, length1, address2, length2)
                    if merged:
                        lengths_by_address_items[i] = merged
                        lengths_by_address_items.pop(j)
                    else:
                        j += 1
                i += 1

            self._lengths_by_type_and_address[modbus_type] = dict(lengths_by_address_items)

        self._pymodbus_client: Optional[BasePyModbusClient] = None

    @abc.abstractmethod
    async def make_pymodbus_client(self) -> BasePyModbusClient:
        raise NotImplementedError()

    def _try_merge_address_length(
        self,
        address1: int,
        length1: int,
        address2: int,
        length2: int
    ) -> Optional[Tuple[int, int]]:
        end1 = address1 + length1
        end2 = address2 + length2
        if address1 <= address2:
            if end1 >= address2:
                if end1 <= end2:  # address1, address2, end1, end2
                    return address1, end2
                else:  # address1, address2, end2, end1
                    return address1, end1
        else:  # address1 > address2
            if end2 >= address1:
                if end2 <= end1:  # address2, address1, end2, end1
                    return address2, end1
                else:  # address2, address1, end1, end2
                    return address2, end2

    async def make_port_args(self) -> List[Union[Dict[str, Any], Type[core_ports.BasePort]]]:
        from .ports import ModbusClientPort

        port_args = []
        for id_, details in self.port_details.items():
            port_args.append({
                'driver': ModbusClientPort,
                'id': id_,
                **details
            })

        return port_args

    async def handle_enable(self) -> None:
        self.info('connecting to unit')
        self._pymodbus_client = await self.make_pymodbus_client()
        await super().handle_enable()

    async def handle_disable(self) -> None:
        await super().handle_disable()
        self.info('disconnecting from unit')
        self._pymodbus_client.close()
        self._pymodbus_client = None

    async def poll(self) -> None:
        for modbus_type, lengths_by_address in self._lengths_by_type_and_address.items():
            for address, length in lengths_by_address.items():
                if modbus_type == constants.MODBUS_TYPE_COIL:
                    self.debug('reading %d coils at %04X', length, address)
                    result = await self._pymodbus_client.read_coils(address, count=length, unit=self.unit_id)
                    values = result.bits
                    values_str = ', '.join(str(v) for v in values).lower()
                    self.debug('read coil values (%s) at %04X', values_str, address)
                elif modbus_type == constants.MODBUS_TYPE_DISCRETE_INPUT:
                    self.debug('reading %d discrete inputs at %04X', length, address)
                    result = await self._pymodbus_client.read_discrete_inputs(address, count=length, unit=self.unit_id)
                    values = result.bits
                    values_str = ', '.join(str(v) for v in values).lower()
                    self.debug('read discrete input values (%s) at %04X', values_str, address)
                elif modbus_type == constants.MODBUS_TYPE_INPUT_REGISTER:
                    self.debug('reading %d input registers at %04X', length, address)
                    result = await self._pymodbus_client.read_input_registers(address, count=length, unit=self.unit_id)
                    values = result.registers
                    values_str = ', '.join(str(v) for v in values)
                    self.debug('read input registers values (%s) at %04X', values_str, address)
                elif modbus_type == constants.MODBUS_TYPE_HOLDING_REGISTER:
                    self.debug('reading %d holding registers at %04X', length, address)
                    result = await self._pymodbus_client.read_holding_registers(
                        address, count=length, unit=self.unit_id
                    )
                    values = result.registers
                    values_str = ', '.join(str(v) for v in values)
                    self.debug('read holding registers values (%s) at %04X', values_str, address)
                else:
                    continue

                if result.function_code >= 0x80:
                    raise Exception(f'Got Modbus error code {result.function_code}')

                for i in range(length):
                    self._values_by_type_and_address.setdefault(modbus_type, {})[address + i] = values[i]

    def get_last_coil_value(self, address: int) -> Optional[bool]:
        values_by_address = self._values_by_type_and_address.get(constants.MODBUS_TYPE_COIL, {})
        return values_by_address.get(address)

    def get_last_discrete_input_value(self, address: int) -> Optional[bool]:
        values_by_address = self._values_by_type_and_address.get(constants.MODBUS_TYPE_DISCRETE_INPUT, {})
        return values_by_address.get(address)

    def get_last_input_register_values(self, address: int, length: int) -> Optional[List[int]]:
        values_by_address = self._values_by_type_and_address.get(constants.MODBUS_TYPE_INPUT_REGISTER, {})
        values = []
        for i in range(length):
            value = values_by_address.get(address + i)
            if value is None:  # a single None value in the list makes the entire result None
                return
            values.append(value)

        return values

    def get_last_holding_register_values(self, address: int, length: int) -> Optional[List[int]]:
        values_by_address = self._values_by_type_and_address.get(constants.MODBUS_TYPE_HOLDING_REGISTER, {})
        values = []
        for i in range(length):
            value = values_by_address.get(address + i)
            if value is None:  # a single None value in the list makes the entire result None
                return
            values.append(value)

        return values

    async def write_coil_value(self, address: int, value: bool) -> None:
        self.debug('writing coil value %s to %04X', json_utils.dumps(value), address)
        if self.use_single_functions:
            await self._pymodbus_client.write_coil(address, value, unit=self.unit_id)
        else:
            await self._pymodbus_client.write_coils(address, [value], unit=self.unit_id)

        self._values_by_type_and_address[constants.MODBUS_TYPE_COIL][address] = value

    async def write_holding_register_values(self, address: int, values: List[int]) -> None:
        values_str = ', '.join(['%04X' % v for v in values])
        self.debug('writing holding register values %s to %04X', values_str, address)
        if self.use_single_functions:
            for value in values:
                await self._pymodbus_client.write_register(address, value, unit=self.unit_id)
        else:
            await self._pymodbus_client.write_registers(address, values, unit=self.unit_id)

        for i, value in enumerate(values):
            self._values_by_type_and_address[constants.MODBUS_TYPE_HOLDING_REGISTER][address + i] = value


class ModbusSerialClient(BaseModbusClient):
    DEFAULT_METHOD = 'ascii'
    DEFAULT_SERIAL_BAUD = 9600
    DEFAULT_SERIAL_STOPBITS = 1
    DEFAULT_SERIAL_BYTESIZE = 8
    DEFAULT_SERIAL_PARITY = 'N'

    def __init__(
        self,
        *,
        serial_port: str,
        serial_baud: int = DEFAULT_SERIAL_BAUD,
        serial_stopbits: int = DEFAULT_SERIAL_STOPBITS,
        serial_bytesize: int = DEFAULT_SERIAL_BYTESIZE,
        serial_parity: int = DEFAULT_SERIAL_PARITY,
        **kwargs
    ) -> None:
        self.serial_port: str = serial_port
        self.serial_baud: int = serial_baud
        self.serial_stopbits: int = serial_stopbits
        self.serial_bytesize: int = serial_bytesize
        self.serial_parity: int = serial_parity

        kwargs.setdefault('method', self.DEFAULT_METHOD)

        super().__init__(**kwargs)

    async def make_pymodbus_client(self) -> BasePyModbusClient:
        loop = asyncio.get_event_loop()
        coro = create_serial_connection(
            loop, self._make_protocol,
            self.serial_port,
            baudrate=self.serial_baud,
            stopbits=self.serial_stopbits,
            bytesize=self.serial_bytesize,
            parity=self.serial_parity,
            timeout=self.timeout,
        )

        _, protocol = await coro

        return protocol

    @staticmethod
    def _make_protocol() -> ModbusClientProtocol:
        return ModbusClientProtocol(framer=ModbusRtuFramer(ClientDecoder()))


class ModbusTcpClient(BaseModbusClient):
    DEFAULT_METHOD = 'socket'
    DEFAULT_TCP_PORT = 502

    def __init__(
        self,
        *,
        tcp_host: str,
        tcp_port: int = DEFAULT_TCP_PORT,
        **kwargs
    ) -> None:
        self.tcp_host: str = tcp_host
        self.tcp_port: int = tcp_port

        kwargs.setdefault('method', self.DEFAULT_METHOD)
        super().__init__(**kwargs)

    async def make_pymodbus_client(self) -> BasePyModbusClient:
        framer = self.FRAMERS_BY_METHOD[self.method]
        _, client = AsyncModbusTCPClient(
            scheduler=schedulers.ASYNC_IO,
            host=self.tcp_host,
            port=self.tcp_port,
            framer=framer
        )

        client = await client

        for _ in range(self.timeout * 10):
            if client.protocol:
                break
            await asyncio.sleep(0.1)
        else:
            raise TimeoutError('Timeout connecting to Modbus device')

        return client.protocol
