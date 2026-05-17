import logging

from typing import Any

from pymodbus import FramerType


class BaseModbus:
    DEFAULT_TIMEOUT = 10  # seconds
    DEFAULT_UNIT_ID = 1

    FRAMERS_BY_METHOD = {
        "ascii": FramerType.ASCII,
        "rtu": FramerType.RTU,
        "socket": FramerType.SOCKET,
    }

    def __init__(
        self,
        *,
        method: str,
        unit_id: int = DEFAULT_UNIT_ID,
        timeout: int = DEFAULT_TIMEOUT,
        use_single_functions: bool = False,
        ports: dict[str, dict[str, Any]],
        **kwargs,
    ) -> None:
        self.method: str = method
        self.unit_id: int = unit_id
        self.timeout: int = timeout
        self.use_single_functions: bool = use_single_functions
        self.port_details: dict[str, dict[str, Any]] = ports

        # TODO: use a common way of adjusting default logging settings from addons
        logging.getLogger("pymodbus").setLevel(logging.INFO)
