# from typing import Any, Dict, Optional, List, Type, Union

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

    # async def make_port_args(self) -> List[Union[Dict[str, Any], Type[core_ports.BasePort]]]:
    #     from .ports import GenericHTTPPort
    #
    #     port_args = []
    #     for id_, details in self.port_details.items():
    #         port_args.append({
    #             'driver': GenericHTTPPort,
    #             'id': id_,
    #             **details
    #         })
    #
    #     return port_args

    # async def poll(self) -> None:
    #     self.debug('read request %s %s', self.read_details['method'], self.read_details['url'])
    #
    #     async with aiohttp.ClientSession() as session:
    #         request_params = await self.prepare_request(self.read_details, {})
    #         async with session.request(**request_params) as response:
    #             data = await response.read()
    #
    #             self.last_response_body = data.decode()
    #             self.last_response_status = response.status
    #             self.last_response_headers = dict(response.headers)
    #
    #             # Attempt to decode JSON but don't worry at all if that is not possible
    #             try:
    #                 self.last_response_json = json_utils.loads(self.last_response_body)
    #
    #             except Exception:
    #                 self.last_response_json = None

    # async def write_port_value(
    #     self,
    #     port: core_ports.BasePort,
    #     request_details: Dict[str, Any],
    #     context: Dict[str, Any]
    # ) -> None:
    #
    #     details = request_details
    #     for k, v in self.write_details.items():
    #         details.setdefault(k, v)
    #
    #     self.debug('write request %s %s', details['method'], details['url'])
    #
    #     context = dict(context, **(await self.get_placeholders_context(port)))
    #
    #     async with aiohttp.ClientSession() as session:
    #         request_params = await self.prepare_request(details, context)
    #         async with session.request(**request_params) as response:
    #             try:
    #                 await response.read()
    #
    #             except Exception as e:
    #                 self.error('write request failed: %s', e, exc_info=True)
    #
    #     await self.poll()
