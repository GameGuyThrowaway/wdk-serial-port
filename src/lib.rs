//!
//! This is a serial port library, wrapping all commonly used serial port
//! behavior over an easy to use set of functions and data structures.
//!
//! We take advantage of the SerCx2 framework to standardize all devices in the
//! SerialPorts class.
//!
#![no_std]
use core::{alloc::Layout, ptr::null_mut};

extern crate alloc;

use alloc::vec::Vec;
use wdk::nt_success;
use wdk_sys::{
    ntddk::{ExFreePool, IoGetDeviceInterfaces},
    GUID, NTSTATUS, PDEVICE_OBJECT, PZZWSTR,
};

mod misc;
pub mod port;
pub mod port_info;

use port_info::SerialPortInfo;

/// Used because the WdkAllocator does not use layouts in deallocation, but the
/// trait requires them.
/// As an aside, it's also worth noting that the allocator doesn't use alignment
/// either (because ExAllocatePool2 doesn't use it either).
static DEALLOC_LAYOUT: Layout = Layout::new::<u8>();

/// GUID_DEVINTERFACE_COMPORT
///
/// GUID_DEVCLASS_PORTS is no longer used for port enumeration, as I realized
/// that the DEVINTERFACE class was more fitting. Seemingly all devices
/// implement GUID_DEVINTERFACE_COMPORT, while only a subset of those work with
/// GUID_DEVCLASS_PORTS.
const COMPORT_CLASS_GUID: GUID = GUID {
    Data1: 0x86E0D1E0,
    Data2: 0x8089,
    Data3: 0x11D0,
    Data4: [0x9C, 0xE4, 0x08, 0x00, 0x3E, 0x30, 0x1F, 0x73],
};

/// GUID_DEVINTERFACE_USB_DEVICE
const USB_CLASS_GUID: GUID = GUID {
    Data1: 0xA5DCBF10,
    Data2: 0x6530,
    Data3: 0x11D2,
    Data4: [0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED],
};

///
/// `list_com_ports` iterates over all available devices in the SerialPorts
/// class, returning a list of their data represented as SerialPortInfo.
///
/// # Return value:
///
/// * `Ok(Vec<SerialPortInfo>)` - The list of all ports' info, if successful.
/// * `Err(NTSTATUS)` - Otherwise, with the status of the failed
///   IoGetDeviceInterfaces call.
///
pub fn list_com_ports() -> Result<Vec<SerialPortInfo>, NTSTATUS> {
    let device: PDEVICE_OBJECT = null_mut();
    let mut symbolic_link_list: PZZWSTR = null_mut();

    // SAFETY: This is safe because:
    //         1. `device` is allowed to be null.
    //         2. `symbolic_link_list` is allowed to be null.
    let interfaces_status = unsafe {
        IoGetDeviceInterfaces(
            &COMPORT_CLASS_GUID,
            device,
            0,
            &mut symbolic_link_list as *mut PZZWSTR,
        )
    };

    if !nt_success(interfaces_status) {
        return Err(interfaces_status);
    }

    let symbolic_list = SerialPortInfo::from_wstr_array(symbolic_link_list);

    // SAFETY: This is safe because:
    //         1. `symbolic_link_list` is not freed anywhere else.
    unsafe {
        ExFreePool(symbolic_link_list as *mut _);
    }

    Ok(symbolic_list)
}

///
/// `list_usb_ports` iterates over all available devices in the USB Devices
/// class, returning a list of their data represented as SerialPortInfo.
///
/// Be careful using this function. While `list_com_ports` returns device info
/// that should always be safe to open, most USB device are not com devices,
/// and so may have undefined behavior to com requests. Be sure to check the
/// device's VID/PID, or find it in the Registry to verify that it is a virtual
/// com device.
///
/// # Return value:
///
/// * `Ok(Vec<SerialPortInfo>)` - The list of all ports' info, if successful.
/// * `Err(NTSTATUS)` - Otherwise, with the status of the failed
///   IoGetDeviceInterfaces call.
///
pub fn list_usb_ports() -> Result<Vec<SerialPortInfo>, NTSTATUS> {
    let device: PDEVICE_OBJECT = null_mut();
    let mut symbolic_link_list: PZZWSTR = null_mut();

    // SAFETY: This is safe because:
    //         1. `device` is allowed to be null.
    //         2. `symbolic_link_list` is allowed to be null.
    let interfaces_status = unsafe {
        IoGetDeviceInterfaces(
            &USB_CLASS_GUID,
            device,
            0,
            &mut symbolic_link_list as *mut PZZWSTR,
        )
    };

    if !nt_success(interfaces_status) {
        return Err(interfaces_status);
    }

    let symbolic_list = SerialPortInfo::from_wstr_array(symbolic_link_list);

    // SAFETY: This is safe because:
    //         1. `symbolic_link_list` is not freed anywhere else.
    unsafe {
        ExFreePool(symbolic_link_list as *mut _);
    }

    Ok(symbolic_list)
}
