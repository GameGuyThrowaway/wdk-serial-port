//!
//! This is a serial port library, wrapping all commonly used serial port
//! behavior over an easy to use set of functions and data structures.
//!
//! We take advantage of the SerCx2 framework to standardize all devices in the
//! Ports class.
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

use port_info::PortInfo;

/// Used because the WdkAllocator does not use layouts in deallocation, but the
/// trait requires them.
/// As an aside, it's also worth noting that the allocator doesn't use alignment
/// either (because ExAllocatePool2 doesn't use it either).
static DEALLOC_LAYOUT: Layout = Layout::new::<u8>();

const PORT_CLASS_GUID: GUID = GUID {
    Data1: 0x4d36e978,
    Data2: 0xe325,
    Data3: 0x11ce,
    Data4: [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18],
};

///
/// `list_ports` iterates over all available devices in the Ports class,
/// returning a list of their symbolic names in a Vector, for ease of use.
///
/// # Return value:
///
/// * `Ok(Vec<PortInfo>)` - The list of all ports' info, if successful.
/// * `Err(NTSTATUS)` - Otherwise, with the status of the failed
///   IoGetDeviceInterfaces call.
///
pub fn list_ports() -> Result<Vec<PortInfo>, NTSTATUS> {
    let device: PDEVICE_OBJECT = null_mut();
    let mut symbolic_link_list: PZZWSTR = null_mut();

    // SAFETY: This is safe because:
    //         1. `device` is allowed to be null.
    //         2. `symbolic_link_list` is allowed to be null.
    let interfaces_status = unsafe {
        IoGetDeviceInterfaces(
            &PORT_CLASS_GUID,
            device,
            0,
            &mut symbolic_link_list as *mut PZZWSTR,
        )
    };

    if !nt_success(interfaces_status) {
        return Err(interfaces_status);
    }

    let symbolic_list = PortInfo::from_wstr_array(symbolic_link_list);

    // SAFETY: This is safe because:
    //         1. `symbolic_link_list` is not freed anywhere else.
    unsafe {
        ExFreePool(symbolic_link_list as *mut _);
    }

    Ok(symbolic_list)
}
