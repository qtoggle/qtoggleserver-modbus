import asyncio
import binascii
import fcntl
import logging
import math
import os
import re
import subprocess

from typing import Any, Optional
from shutil import which

from qtoggleserver.utils import logging as logging_utils

from .base import InternalPassiveClient, InternalPassiveException


class InvalidIpv4Packet(InternalPassiveException):
    pass


class InvalidModbusFrame(InternalPassiveException):
    pass


class InternalTcpDumpClient(InternalPassiveClient, logging_utils.LoggableMixin):
    _WORD_HEX_REGEX = re.compile(r'\s[a-f0-9]{2,4}')
    _MODBUS_FUNC_READ_COILS = 1
    _MODBUS_FUNC_READ_DISCRETE_INPUTS = 2
    _MODBUS_FUNC_READ_HOLDING_REGISTERS = 3
    _MODBUS_FUNC_READ_INPUT_REGISTERS = 4

    _WATCHED_FUNCTIONS = {
        _MODBUS_FUNC_READ_COILS,
        _MODBUS_FUNC_READ_DISCRETE_INPUTS,
        _MODBUS_FUNC_READ_HOLDING_REGISTERS,
        _MODBUS_FUNC_READ_INPUT_REGISTERS,
    }

    def __init__(
        self,
        *,
        port: int,
        iface: Optional[str] = None,
        unit_id: int = 0,
        master_ip: Optional[str] = None,
        slave_ip: Optional[str] = None,
        tcpdump: Optional[str] = None,
        logger: logging.Logger,
    ) -> None:
        self.port: int = port
        self.iface: str = iface or 'any'
        self.unit_id: int = unit_id
        self.master_ip: Optional[str] = master_ip
        self.slave_ip: Optional[str] = slave_ip
        self.tcpdump: Optional[str] = tcpdump
        self.logger = logger

        if not any((self.master_ip, self.slave_ip)):
            raise ValueError('Either `master_ip` or `slave_ip` must be set')

        self.buffer: bytes = b''
        self.last_read_coils_request: Optional[dict[str, Any]] = None
        self.last_read_discrete_inputs_request: Optional[dict[str, Any]] = None
        self.last_read_holding_registers_request: Optional[dict[str, Any]] = None
        self.last_read_input_registers_request: Optional[dict[str, Any]] = None

        InternalPassiveClient.__init__(self)
        logging_utils.LoggableMixin.__init__(self, 'tcpdump', logger)

    @staticmethod
    def find_tcpdump() -> Optional[str]:
        return which('tcpdump')

    def make_tcpdump_cmd(self) -> list[str]:
        tcpdump = self.tcpdump or self.find_tcpdump()
        if not tcpdump:
            raise RuntimeError('tcpdump command not found')

        return [tcpdump, '-Xni', self.iface, 'port', str(self.port)]

    async def run(self) -> None:
        cmd = self.make_tcpdump_cmd()
        self.debug('running command "%s"', ' '.join(cmd))
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        ) as proc:
            # Set non-blocking read mode
            fd = proc.stdout.fileno()  # noqa
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            line = ''
            try:
                while True:
                    exit_code = proc.poll()
                    if exit_code is not None:
                        self.debug('tcpdump exited with code %s', exit_code)
                        break
                    try:
                        output = proc.stdout.read()
                    except TypeError:
                        # Sometimes the `read()` implementation raises `TypeError: can't concat NoneType to bytes`
                        output = None
                    if not output:
                        await asyncio.sleep(0.1)
                        continue
                    parts = output.split('\n')
                    line += parts.pop(0)
                    self._parse_line(line)
                    for line in parts[:-1]:
                        if line:
                            self._parse_line(line)
                    line = parts[-1]
            except asyncio.CancelledError:
                self.debug('stopping tcpdump process')
                proc.kill()

    def _parse_line(self, line: str) -> None:
        # Each `line` starts with a timestamp or contains something like:
        #     [tab]0x0080:  5375 6e2c 2031 3020 4465 6320 3230 3233  Sun,.10.Dec.2023
        if line.startswith('\t'):
            for word_hex in self._WORD_HEX_REGEX.findall(line):
                # Our `word_hex` looks like: ` 6e2c`, containing two bytes. We push each byte in network byte order.
                if len(word_hex) == 5:
                    self.buffer += bytes([int(word_hex[:3], 16), int(word_hex[3:], 16)])
                else:
                    self.buffer += bytes([int(word_hex[:3], 16)])
        elif self.buffer:
            try:
                self._process_packet(self.buffer)
            except Exception:
                self.error('failed to parse IP packet', exc_info=True)

            self.buffer = b''

    def _process_packet(self, data: bytes) -> None:
        # Validate IPv4 header
        if len(data) < 40:
            raise InvalidIpv4Packet('Packet too short (%s bytes)', len(data))
        if data[0] >> 4 != 4:
            raise InvalidIpv4Packet('Wrong IPv4 version (%s)', data[0] >> 4)

        ip_packet = data
        ip_header_length = (ip_packet[0] & 0x0F) * 4
        ip_source = f'{ip_packet[12]}.{ip_packet[13]}.{ip_packet[14]}.{ip_packet[15]}'
        ip_dest = f'{ip_packet[16]}.{ip_packet[17]}.{ip_packet[18]}.{ip_packet[19]}'

        tcp_packet = ip_packet[ip_header_length:]
        # tcp_source_port = (tcp_packet[0] << 8) + tcp_packet[1]
        # tcp_dest_port = (tcp_packet[2] << 8) + tcp_packet[3]
        tcp_header_length = (tcp_packet[12] >> 4) * 4

        # if self.port not in (tcp_source_port, tcp_dest_port):
        #     self.debug('ignoring message on port %s', self.port)
        #     return

        modbus_frame = tcp_packet[tcp_header_length:]
        if not modbus_frame:
            # Ignore packet with empty TCP data
            return

        is_request = (
            (self.master_ip and self.master_ip == ip_source) or
            (self.slave_ip and self.slave_ip == ip_dest)
        )
        if is_request:
            self._process_modbus_request(modbus_frame)
        else:
            self._process_modbus_response(modbus_frame)

    def _process_modbus_request(self, frame: bytes) -> None:
        self.debug('got Modbus request: %s', binascii.hexlify(frame).decode())
        if len(frame) < 5:
            raise InvalidModbusFrame('Frame too short (%s bytes)', len(frame))

        unit_id = frame[0]
        function = frame[1]
        data = frame[2:-2]
        crc = frame[-2:]
        if crc != self._compute_crc(frame[:-2]):
            raise InvalidModbusFrame('CRC verification failed')
        if function not in self._WATCHED_FUNCTIONS:
            self.debug('ignoring Modbus function %s', function)
        if self.unit_id and self.unit_id != unit_id:
            self.debug('ignoring Modbus slave address %s', unit_id)
        if function == self._MODBUS_FUNC_READ_COILS:
            self._process_read_coils_request(data)
        if function == self._MODBUS_FUNC_READ_DISCRETE_INPUTS:
            self._process_read_discrete_inputs_request(data)
        if function == self._MODBUS_FUNC_READ_HOLDING_REGISTERS:
            self._process_read_holding_registers_request(data)
        if function == self._MODBUS_FUNC_READ_INPUT_REGISTERS:
            self._process_read_input_registers_request(data)

    def _process_modbus_response(self, frame: bytes) -> None:
        self.debug('got Modbus response: %s', binascii.hexlify(frame).decode())
        if len(frame) < 5:
            raise InvalidModbusFrame('Frame too short (%s bytes)', len(frame))

        unit_id = frame[0]
        function = frame[1]
        data = frame[2:-2]
        crc = frame[-2:]
        if crc != self._compute_crc(frame[:-2]):
            raise InvalidModbusFrame('CRC verification failed')
        if function not in self._WATCHED_FUNCTIONS:
            self.debug('ignoring Modbus function %s', function)
        if self.unit_id and self.unit_id != unit_id:
            self.debug('ignoring Modbus unit ID %s', unit_id)
        if function == self._MODBUS_FUNC_READ_COILS:
            self._process_read_coils_response(data)
        if function == self._MODBUS_FUNC_READ_DISCRETE_INPUTS:
            self._process_read_discrete_inputs_response(data)
        if function == self._MODBUS_FUNC_READ_HOLDING_REGISTERS:
            self._process_read_holding_registers_response(data)
        if function == self._MODBUS_FUNC_READ_INPUT_REGISTERS:
            self._process_read_input_registers_response(data)

    @staticmethod
    def _compute_crc(data: bytes) -> bytes:
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

    def _process_read_coils_request(self, data: bytes) -> None:
        self.last_read_coils_request = {
            'address': int.from_bytes(data[:2], byteorder='big', signed=False),
            'count': int.from_bytes(data[2:4], byteorder='big', signed=False),
        }
        self.debug(
            'read coils request (address = %d, count = %d)',
            self.last_read_coils_request['address'],
            self.last_read_coils_request['count'],
        )

    def _process_read_discrete_inputs_request(self, data: bytes) -> None:
        self.last_read_discrete_inputs_request = {
            'address': int.from_bytes(data[:2], byteorder='big', signed=False),
            'count': int.from_bytes(data[2:4], byteorder='big', signed=False),
        }
        self.debug(
            'read discrete inputs request (address = %d, count = %d)',
            self.last_read_discrete_inputs_request['address'],
            self.last_read_discrete_inputs_request['count'],
        )

    def _process_read_holding_registers_request(self, data: bytes) -> None:
        self.last_read_holding_registers_request = {
            'address': int.from_bytes(data[:2], byteorder='big', signed=False),
            'count': int.from_bytes(data[2:4], byteorder='big', signed=False),
        }
        self.debug(
            'read holding registers request (address = %d, count = %d)',
            self.last_read_holding_registers_request['address'],
            self.last_read_holding_registers_request['count'],
        )

    def _process_read_input_registers_request(self, data: bytes) -> None:
        self.last_read_input_registers_request = {
            'address': int.from_bytes(data[:2], byteorder='big', signed=False),
            'count': int.from_bytes(data[2:4], byteorder='big', signed=False),
        }
        self.debug(
            'read input registers request (address = %d, count = %d)',
            self.last_read_input_registers_request['address'],
            self.last_read_input_registers_request['count'],
        )

    def _process_read_coils_response(self, data: bytes) -> None:
        if not self.last_read_coils_request:
            self.warning('ignoring read coils response without request')
            return

        if len(data) < 1:
            raise InvalidModbusFrame('Data too short (%s bytes)', len(data))
        byte_count = data[0]
        if len(data) != byte_count + 1:
            raise InvalidModbusFrame('Unexpected number of data bytes (%s != %s)', len(data), byte_count)
        expected_byte_count = math.ceil(self.last_read_coils_request['count'] / 8)
        if expected_byte_count != byte_count:
            self.warning('ignoring read coils response with different address count')
            return

        bits = int.from_bytes(data[1:], byteorder='little', signed=False)
        bit_string = f'{bits:b}'
        values = [b == '1' for b in reversed(bit_string)]
        for i, v in enumerate(values):
            self.set_coil_value(self.last_read_coils_request['address'] + i, v)

        self.debug('read coils response (values = [%s])', ', '.join(str(v).lower() for v in values))

        self.last_read_coils_request = None

    def _process_read_discrete_inputs_response(self, data: bytes) -> None:
        if not self.last_read_discrete_inputs_request:
            self.warning('ignoring read discrete inputs response without request')
            return

        if len(data) < 1:
            raise InvalidModbusFrame('Data too short (%s bytes)', len(data))
        byte_count = data[0]
        if len(data) != byte_count + 1:
            raise InvalidModbusFrame('Unexpected number of data bytes (%s != %s)', len(data), byte_count)
        expected_byte_count = math.ceil(self.last_read_discrete_inputs_request['count'] / 8)
        if expected_byte_count != byte_count:
            self.warning('ignoring read discrete inputs response with different address count')
            return

        bits = int.from_bytes(data[1:], byteorder='little', signed=False)
        bit_string = f'{bits:b}'
        values = [b == '1' for b in reversed(bit_string)]
        for i, v in enumerate(values):
            self.set_discrete_input_value(self.last_read_discrete_inputs_request['address'] + i, v)

        self.debug('read discrete inputs response (values = [%s])', ', '.join(str(v).lower() for v in values))

        self.last_read_discrete_inputs_request = None

    def _process_read_holding_registers_response(self, data: bytes) -> None:
        if not self.last_read_holding_registers_request:
            self.warning('ignoring read holding registers response without request')
            return

        if len(data) < 1:
            raise InvalidModbusFrame('Data too short (%s bytes)', len(data))
        byte_count = data[0]
        if len(data) != byte_count + 1:
            raise InvalidModbusFrame('Unexpected number of data bytes (%s != %s)', len(data), byte_count)
        expected_byte_count = self.last_read_holding_registers_request['count'] * 2
        if expected_byte_count != byte_count:
            self.warning('ignoring read holding registers response with different address count')
            return

        values = []
        for i in range(self.last_read_holding_registers_request['count']):
            value = int.from_bytes(data[i * 2 + 1: i * 2 + 3], byteorder='big', signed=False)
            values.append(value)
            self.set_holding_register_value(self.last_read_holding_registers_request['address'] + i, value)

        self.debug('read holding registers response (values = [%s])', ', '.join(f'0x{v:04X}' for v in values))

        self.last_read_holding_registers_request = None

    def _process_read_input_registers_response(self, data: bytes) -> None:
        if not self.last_read_input_registers_request:
            self.warning('ignoring read input registers response without request')
            return

        if len(data) < 1:
            raise InvalidModbusFrame('Data too short (%s bytes)', len(data))
        byte_count = data[0]
        if len(data) != byte_count + 1:
            raise InvalidModbusFrame('Unexpected number of data bytes (%s != %s)', len(data), byte_count)
        expected_byte_count = self.last_read_input_registers_request['count'] * 2
        if expected_byte_count != byte_count:
            self.warning('ignoring read input registers response with different address count')
            return

        values = []
        for i in range(self.last_read_input_registers_request['count']):
            value = int.from_bytes(data[i * 2 + 1: i * 2 + 3], byteorder='big', signed=False)
            values.append(value)
            self.set_input_register_value(self.last_read_input_registers_request['address'] + i, value)

        self.debug('read input registers response (values = [%s])', ', '.join(f'0x{v:04X}' for v in values))

        self.last_read_input_registers_request = None
