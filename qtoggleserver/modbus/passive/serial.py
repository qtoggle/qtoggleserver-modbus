import asyncio
import binascii
import logging

import serial

from .base import InternalPassiveClient, InternalPassiveException


class InvalidIpv4Packet(InternalPassiveException):
    pass


class InvalidModbusFrame(InternalPassiveException):
    pass


class InternalSerialClient(InternalPassiveClient):
    def __init__(
        self,
        *,
        serial_port: str,
        serial_baud: int,
        serial_stopbits: int,
        serial_bytesize: int,
        serial_parity: str,
        unit_id: int,
        timeout: int,
        logger: logging.Logger,
    ) -> None:
        self.serial_port: str = serial_port
        self.serial_baud: int = serial_baud
        self.serial_stopbits: int = serial_stopbits
        self.serial_bytesize: int = serial_bytesize
        self.serial_parity: str = serial_parity
        self.unit_id: int = unit_id
        self.timeout: int = timeout

        super().__init__(logger)
        self.set_logger_name('passive_serial')

    def make_serial(self) -> serial.Serial:
        return serial.Serial(
            port=self.serial_port,
            baudrate=self.serial_baud,
            stopbits=self.serial_stopbits,
            bytesize=self.serial_bytesize,
            parity=self.serial_parity,
            timeout=self.timeout,
            write_timeout=self.timeout,
        )

    async def run(self) -> None:
        while True:
            try:
                ser = self.make_serial()
                buffer = b''
                for _ in range(self.timeout * 10):
                    buffer += ser.read_all()
                    await asyncio.sleep(0.1)
                if buffer:
                    self.debug('sniffed %d bytes' % len(buffer))
                    while True:
                        consumed_bytes = self._process_modbus_data(buffer)
                        if not consumed_bytes:
                            break
                        buffer = buffer[consumed_bytes:]

            except asyncio.CancelledError:
                self.debug('task stopped')
                break

    def _process_modbus_data(self, buffer: bytes) -> int:
        if len(buffer) < 5:
            return 0

        unit_id = buffer[0]
        if unit_id != self.unit_id:
            return 0

        function = buffer[1]
        if function not in self.WATCHED_FUNCTIONS:
            return 0

        # Try to see if we've got a response
        byte_count = buffer[2]
        if len(buffer) >= byte_count + 5:
            crc = buffer[byte_count + 3:byte_count + 5]
            if self.compute_crc(buffer[:byte_count + 3]) == crc:
                frame = buffer[:byte_count + 5]
                self._process_modbus_response(frame)
                return len(frame)

        # Try to see if we've got a request
        if len(buffer) >= 8:
            crc = buffer[6:8]
            if self.compute_crc(buffer[:6]) == crc:
                frame = buffer[0:8]
                self._process_modbus_request(frame)
                return len(frame)

        return 0

    def _process_modbus_request(self, frame: bytes) -> None:
        self.debug('got Modbus request: %s', binascii.hexlify(frame).decode())

        function = frame[1]
        data = frame[2:-2]
        if function == self.MODBUS_FUNC_READ_COILS:
            self.process_read_coils_request(data)
        elif function == self.MODBUS_FUNC_READ_DISCRETE_INPUTS:
            self.process_read_discrete_inputs_request(data)
        elif function == self.MODBUS_FUNC_READ_HOLDING_REGISTERS:
            self.process_read_holding_registers_request(data)
        elif function == self.MODBUS_FUNC_READ_INPUT_REGISTERS:
            self.process_read_input_registers_request(data)

    def _process_modbus_response(self, frame: bytes) -> None:
        self.debug('got Modbus response: %s', binascii.hexlify(frame).decode())

        function = frame[1]
        data = frame[2:-2]
        if function == self.MODBUS_FUNC_READ_COILS:
            self.process_read_coils_response(data)
        elif function == self.MODBUS_FUNC_READ_DISCRETE_INPUTS:
            self.process_read_discrete_inputs_response(data)
        elif function == self.MODBUS_FUNC_READ_HOLDING_REGISTERS:
            self.process_read_holding_registers_response(data)
        elif function == self.MODBUS_FUNC_READ_INPUT_REGISTERS:
            self.process_read_input_registers_response(data)
