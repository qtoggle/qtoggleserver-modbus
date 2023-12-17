import abc
import asyncio

from typing import List, Optional, Union

from pymodbus import Framer, bit_read_message, bit_write_message, register_read_message, register_write_message
from pymodbus.client.base import ModbusBaseClient as InternalModbusBaseClient


class InternalPassiveException(Exception):
    pass


class InternalPassiveClient(InternalModbusBaseClient, metaclass=abc.ABCMeta):
    def __init__(self) -> None:
        self._coil_values: dict[int, bool] = {}
        self._discrete_input_values: dict[int, bool] = {}
        self._holding_register_values: dict[int, int] = {}
        self._input_register_values: dict[int, int] = {}
        self._run_task: Optional[asyncio.Task] = None

        super().__init__(framer=Framer.RTU)

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
