## About

This is an addon for [qToggleServer](https://github.com/qtoggle/qtoggleserver).

With this addon you can read and control Modbus-enabled devices (such as energy meters) via qToggleServer. You can also
configure a Modbus server so that your qToggleServer behaves like a Modbus device itself.


## Install

Install using pip:

    pip install qtoggleserver-modbus


## Usage

### Serial Client

##### `qtoggleserver.conf:`
``` ini
...
peripherals = [
    ...
    {
        driver = "qtoggleserver.modbus.ModbusSerialClient"
        method = rtu                    # `ascii` (default), `rtu` or `binary`
        serial_port = "/dev/ttyUSB0"
        serial_baud = 9600              # this is the default
        serial_stopbits = 1             # this is the default
        serial_bytesize = 8             # this is the default
        serial_parity = N               # `N`, `E` or `O`
        # see below for common parameters
    }
    ...
]
...
```

### Serial Server

##### `qtoggleserver.conf:`
``` ini
...
peripherals = [
    ...
    {
        driver = "qtoggleserver.modbus.ModbusSerialServer"
        method = rtu                    # `ascii` (default), `rtu` or `binary`
        serial_port = "/dev/ttyUSB0"
        serial_baud = 9600              # this is the default
        serial_stopbits = 1             # this is the default
        serial_bytesize = 8             # this is the default
        serial_parity = N               # `N`, `E` or `O`
        # see below for common parameters
    }
    ...
]
...
```

### TCP Client

##### `qtoggleserver.conf:`
``` ini
...
peripherals = [
    ...
    {
        driver = "qtoggleserver.modbus.ModbusTcpClient"
        method = socket                 # `socket` (default), `ascii`, `rtu` or `binary`
        tcp_host = "192.168.0.2"        # IP or hostname of the Modbus device
        tcp_port = 502                  # Modbus device TCP port
        # see below for common parameters
    }
    ...
]
...
```

### TCP Server

##### `qtoggleserver.conf:`
``` ini
...
peripherals = [
    ...
    {
        driver = "qtoggleserver.modbus.ModbusTcpServer"
        method = socket                 # `socket` (default), `ascii`, `rtu` or `binary`
        tcp_address = "0.0.0.0"         # binds on all interfaces by default
        tcp_port = 502                  # Modbus device TCP port
        # see below for common parameters
    }
    ...
]
...
```

### Common Parameters

The following parameters are common to all types of Modbus clients and servers:

##### `qtoggleserver.conf:`
``` ini
...
peripherals = [
    ...
    {
        ...
        name = "mydevice"  # an optional name of your choice
        timeout = 5        # in seconds, this is the default
        unit_id = 0           # slave unit id, this is the default
        ports = {
            "port_id1" = {
                modbus_type = coil          # `coil`, discrete_input`, `input_register` or `holding_register`
                address = 1234              # Modbus port address (from `0000` to `9999`)
                # number of successive registers mapped to the port, starting at `address` (defaults to `1`)
                length = 2
                writable = false            # by default is `null`, inferred from `modbus_type`
                # `struct` format to use to group multiple register values into a byte array (defaults to `>h`)
                register_group_fmt = ">hh"
                # `struct` format to use to map register byte array to port value (defaults to `>h`)
                value_fmt = ">i"
            }
            ...
        }
        ...
    }
    ...
]
...
```

### Common Client Parameters

The following parameters are common to all types of Modbus clients:

##### `qtoggleserver.conf:`
``` ini
...
peripherals = [
    ...
    {
        ...
        use_single_functions = false  # set to `true` to use single Modbus access functions instead of multi ones
        ...
    }
    ...
]
...
```

### Common Server Parameters

The following parameters are common to all types of Modbus servers:

##### `qtoggleserver.conf:`
``` ini
...
peripherals = [
    ...
    {
        ...
        identity_vendor_name = "My Vendor"
        identity_product_code = "PROD1234"
        identity_major_minor_revision = "3.14.15"
        identity_vendor_url = "https://example.com"
        identity_product_name = "My Product"
        identity_model_name = "My Model"
        identity_user_application_name = "My Custom Model"
        ...
    }
    ...
]
...
```
