
# wdk-serial-port

A Rust based serial port interface library for my Ferrum Windows kernel driver development.

To install this crate:
```
cargo add wdk-serial-port --git https://github.com/GameGuyThrowaway/wdk-serial-port.git
```

This crate gives easy access to serial ports from a KMDF driver. It lets users list serial ports, open serial ports with
a baud rate, write to serial ports, and asynchronously read back from serial ports. All in a (hopefully) safe way.

This crate was designed strictly for my use in the Rust based Ferrum kernel driver for Windows. As such, it doesn't
exactly have a standardized use, and is instead optimized for how I use it. However with some simple changes, I'm sure
it may be useful to someone else trying to work with serial ports from the kernel.

My understanding of the Windows kernel is lacking, and I am rather inexperienced with low level
multi-threaded/asynchronous systems. In this project, I opted to attempt to try to be as memory safe as possible by
using Rust, and by following in the footsteps of others with seemingly more experience. For example, many of the memory
concurrency practices were based on https://github.com/0xflux/Sanctum, a project by the developer of the crate I use for
most concurrency, wdk-mutex.

## Features

* Listing all connected serial ports
* Opening serial ports (and specifying a baud rate)
* Writing synchronously to serial ports via IRPs
* Reading data asynchronously via callbacks and IRPs
    * Just pass a callback, and the library will automatically call your function when new data is received on the port.
    * It even stores the new data over multiple calls until your callback is able to fully process it, and no longer
      needs it.
* Configuring serial port parameters via IOCTLs

## TODO/Limitations

* Com ports being removed from the system have unknown behavior.
    * All testing has been done in a 24H2 VM with a virtual serial port that does not disconnect.
    * I expect to test on a live machine soon, and to ensure proper safe behavior with port disconnects.
* Documentation could be better.
* Currently there is a fixed limit on the number of opened com ports at once.
    * This is because of the nature of the memory safety, and using global mutex pointers to handle multi threaded
      access to serial ports.
* There is no automated testing of this code.
    * However I don't see much room for unit tests, and integration/system tests would either be very complex with an
      actual serial port, or presumably not very useful with a mock serial port.
* This code is potentially unsafe.
    * Being a novice kernel developer, I'm not extremely experienced with writing safe production code, and don't know
      what to look out for, and how systems behave in the Windows kernel.
    * I don't recommend this for use in production environments until further analysis is done.

# Examples

TODO: Link the Ferrum driver once it is published.

## Printing all available com ports' paths on the system

```rust
fn list_ports() {
    match wdk_serial_port::list_com_ports() {
        Ok(ports) => {
            for mut port_info in ports {
                println!("Found Port @ `{}`", port_info.path);
            }
        }
        Err(status) => {
            println!("Failed to get Ports: {:08X}", status)
        }
    }
}
```

## Connecting to a com port, and writing data to it

This example opens a com port at 115_200 baud, sends "Hello World\n" to it, and then closes it.

```rust
use wdk_serial_port::{
    port::GlobalSerialPorts,
    port_info::SerialPortInfo
};

fn write_string(port_info: &mut SerialPortInfo) {
    match port_info.open(115_200) {
        Ok(identifier) => {
            println!("Port Opening @ {identifier}");

            let mutex_ptr = GlobalSerialPorts::get_port(identifier).unwrap();
            let mut port_locked = unsafe { (*mutex_ptr).lock().unwrap() };

            match port_locked.write_blocking(b"Hello World\n") {
                Ok(len) => {
                    println!("Wrote {len} bytes");
                }
                Err(e) => println!("Failed to write any data: {:?}", e),
            }

            GlobalSerialPorts::close_port(identifier);
            println!("Port Closed");
        }
        Err(err) => {
            println!("Failed to Open Port: {:?}", err);
        }
    }
}
```

## Connecting to a com port, and echoing data

This example connects to a com port at 115_200 baud, and starts the asynchronous read handler.

This handler will call the callback when new data is received. It passes not just the new data, but all data received
since the com port was opened. The return value of the callback specifies to drain N elements starting from index 0.

In this example, the callback drains the entire read buffer after echoing its contents back to the port.

```rust
use wdk_serial_port::{
    port::{GlobalSerialPorts, SerialPort},
    port_info::SerialPortInfo
};

fn read_async(port_info: &mut SerialPortInfo) {
    match port_info.open(115_200) {
        Ok(identifier) => {
            println!("Port Opening @");

            let mutex_ptr = GlobalSerialPorts::get_port(identifier).unwrap();
            let mut port_locked = unsafe { (*mutex_ptr).lock().unwrap() };

            match port_locked.start_async_read_system(serial_read_handler) {
                Ok(_) => println!("Started Async Read System"),
                Err(e) => println!("Failed to start Async Read System: {:?}", e),
            }

            // Don't close the port until you're done reading.
            // GlobalSerialPorts::close_port(identifier);
        }
        Err(err) => {
            println!("Failed to Open Port: {:?}", err);
        }
    }
}

fn serial_read_handler(port: &mut SerialPort) -> usize {
    use alloc::string::String;

    let data = port.get_read_buf();

    println!("Serial Read: {:?} | {}", data, String::from_utf8_lossy(&data));

    match port.write_blocking(data) {
        Ok(len) => println!("Wrote {len} bytes"),
        Err(e) => println!("Failed to write any data: {:?}", e),
    }

    data.len()
}
```


## Connecting to a com port, and loop sending a message

This example connects to a com port at 115_200 baud, and uses the hardware flush callback to know exactly when a message
has sent. Then it repeats that message upon its completion.

```rust
use wdk_serial_port::{
    port::{GlobalSerialPorts, SerialPort},
    port_info::SerialPortInfo
};

fn loop_write(port_info: &mut SerialPortInfo) {
    match port_info.open(115_200) {
        Ok(identifier) => {
            println!("Port Opening @");

            let mutex_ptr = GlobalSerialPorts::get_port(identifier).unwrap();
            let mut port_locked = unsafe { (*mutex_ptr).lock().unwrap() };

            match port_locked.set_flush_callback(flush_callback) {
                Ok(_) => println!("Started Async Read System"),
                Err(e) => println!("Failed to start Async Read System: {:?}", e),
            }

            match port.write_blocking(b"Hello World!") {
                Ok(len) => println!("Initially Wrote {len} bytes"),
                Err(e) => println!("Failed to initially write any data: {:?}", e),
            }

            // Don't close the port until you're done with the async flush
            // callback system.
            // GlobalSerialPorts::close_port(identifier);
        }
        Err(err) => {
            println!("Failed to Open Port: {:?}", err);
        }
    }
}

fn flush_callback(port: SerialPortIdentifier) {
    let mutex_ptr = GlobalSerialPorts::get_port(identifier).unwrap();
    let port_locked = unsafe { (*mutex_ptr).lock().unwrap() };

    match port_locked.write_blocking(b"Hello World!") {
        Ok(len) => println!("Wrote {len} bytes"),
        Err(e) => println!("Failed to write any data: {:?}", e),
    }
}
```

