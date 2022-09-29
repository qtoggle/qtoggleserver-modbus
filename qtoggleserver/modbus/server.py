from qtoggleserver.peripherals import Peripheral

from .base import BaseModbus


class BaseModbusServer(BaseModbus, Peripheral):
    def __init__(
        self,
        *,
        identity_vendor_name: str = '',
        identity_product_code: str = '',
        identity_major_minor_revision: str = '',
        identity_vendor_url: str = '',
        identity_product_name: str = '',
        identity_model_name: str = '',
        identity_user_application_name: str = '',
        **kwargs,
    ) -> None:
        self.identity_vendor_name: str = identity_vendor_name
        self.identity_product_code: str = identity_product_code
        self.identity_major_minor_revision: str = identity_major_minor_revision
        self.identity_vendor_url: str = identity_vendor_url
        self.identity_product_name: str = identity_product_name
        self.identity_model_name: str = identity_model_name
        self.identity_user_application_name: str = identity_user_application_name

        super().__init__(**kwargs)

    # async def make_port_args(self) -> list[Union[dict[str, Any], type[core_ports.BasePort]]]:
    #     port_args = []
    #     for id_, details in self.port_details.items():
    #         port_args.append({
    #             'driver': ...,
    #             'id': id_,
    #             **details
    #         })
    #
    #     return port_args

    # async def write_port_value(
    #     self,
    #     port: core_ports.BasePort,
    #     request_details: dict[str, Any],
    #     context: dict[str, Any]
    # ) -> None:
    # ...
