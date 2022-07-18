import logging

from typing import Any, Dict

from pymodbus.framer.ascii_framer import ModbusAsciiFramer
from pymodbus.framer.binary_framer import ModbusBinaryFramer
from pymodbus.framer.rtu_framer import ModbusRtuFramer
from pymodbus.framer.socket_framer import ModbusSocketFramer


class BaseModbus:
    DEFAULT_TIMEOUT = 10  # Seconds
    DEFAULT_UNIT_ID = 0

    FRAMERS_BY_METHOD = {
        'ascii': ModbusAsciiFramer,
        'rtu': ModbusRtuFramer,
        'binary': ModbusBinaryFramer,
        'socket': ModbusSocketFramer,
    }

    def __init__(
        self,
        *,
        method: str,
        unit_id: int = DEFAULT_UNIT_ID,
        timeout: int = DEFAULT_TIMEOUT,
        use_single_functions: bool = False,
        ports: Dict[str, Dict[str, Any]],
        **kwargs
    ) -> None:
        self.method: str = method
        self.unit_id: int = unit_id
        self.timeout: int = timeout
        self.use_single_functions: bool = use_single_functions
        self.port_details: Dict[str, Dict[str, Any]] = ports

        # TODO: use a common way of adjusting default logging settings from addons
        logging.getLogger('pymodbus').setLevel(logging.INFO)
