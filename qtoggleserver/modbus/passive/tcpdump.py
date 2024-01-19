import asyncio
import binascii
import fcntl
import logging
import os
import re
import subprocess

from typing import Optional
from shutil import which

from .base import InternalPassiveClient, InternalPassiveException, InvalidModbusFrame


class InvalidIpv4Packet(InternalPassiveException):
    pass


class InternalTcpDumpClient(InternalPassiveClient):
    _WORD_HEX_REGEX = re.compile(r'\s[a-f0-9]{2,4}')

    def __init__(
        self,
        *,
        port: int,
        iface: Optional[str] = None,
        unit_id: int = 0,
        master_ip: Optional[str] = None,
        slave_ip: Optional[str] = None,
        master_port: Optional[int] = None,
        slave_port: Optional[int] = None,
        tcpdump: Optional[str] = None,
        logger: logging.Logger,
    ) -> None:
        self.port: int = port
        self.iface: str = iface or 'any'
        self.unit_id: int = unit_id
        self.master_ip: Optional[str] = master_ip
        self.slave_ip: Optional[str] = slave_ip
        self.master_port: Optional[int] = master_port
        self.slave_port: Optional[int] = slave_port
        self.tcpdump: Optional[str] = tcpdump
        self.logger = logger

        if not any((self.master_ip, self.slave_ip, self.master_port, self.slave_port)):
            raise ValueError('Either `master_ip`, `slave_ip`, `master_port` or `slave_port` must be set')

        self.buffer: bytes = b''

        super().__init__(logger)
        self.set_logger_name('passive_tcpdump')

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
        tcp_source_port = (tcp_packet[0] << 8) + tcp_packet[1]
        tcp_dest_port = (tcp_packet[2] << 8) + tcp_packet[3]
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
            (self.slave_ip and self.slave_ip == ip_dest) or
            (self.master_port and self.master_port == tcp_source_port) or
            (self.slave_port and self.slave_port == tcp_dest_port)
        ) or False
        is_response = (
            (self.master_ip and self.master_ip == ip_dest) or
            (self.slave_ip and self.slave_ip == ip_source) or
            (self.master_port and self.master_port == tcp_dest_port) or
            (self.slave_port and self.slave_port == tcp_source_port)
        ) or False
        if is_request:
            self._process_modbus_request(modbus_frame)
        elif is_response:
            self._process_modbus_response(modbus_frame)

    def _process_modbus_request(self, frame: bytes) -> None:
        self.debug('got Modbus request: %s', binascii.hexlify(frame).decode())
        if len(frame) < 5:
            raise InvalidModbusFrame('Frame too short (%s bytes)', len(frame))

        unit_id = frame[0]
        function = frame[1]
        data = frame[2:-2]
        crc = frame[-2:]
        if crc != self.compute_crc(frame[:-2]):
            raise InvalidModbusFrame('CRC verification failed')
        if function not in self.WATCHED_FUNCTIONS:
            self.debug('ignoring Modbus function %s', function)
            return
        if self.unit_id and self.unit_id != unit_id:
            self.debug('ignoring Modbus slave address %s', unit_id)
            return
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
        if len(frame) < 5:
            raise InvalidModbusFrame('Frame too short (%s bytes)', len(frame))

        unit_id = frame[0]
        function = frame[1]
        data = frame[2:-2]
        crc = frame[-2:]
        if crc != self.compute_crc(frame[:-2]):
            raise InvalidModbusFrame('CRC verification failed')
        if function not in self.WATCHED_FUNCTIONS:
            self.debug('ignoring Modbus function %s', function)
            return
        if self.unit_id and self.unit_id != unit_id:
            self.debug('ignoring Modbus unit ID %s', unit_id)
            return
        if function == self.MODBUS_FUNC_READ_COILS:
            self.process_read_coils_response(data)
        elif function == self.MODBUS_FUNC_READ_DISCRETE_INPUTS:
            self.process_read_discrete_inputs_response(data)
        elif function == self.MODBUS_FUNC_READ_HOLDING_REGISTERS:
            self.process_read_holding_registers_response(data)
        elif function == self.MODBUS_FUNC_READ_INPUT_REGISTERS:
            self.process_read_input_registers_response(data)
