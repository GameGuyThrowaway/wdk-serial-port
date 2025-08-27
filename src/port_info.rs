//!
//! Defines a PortInfo class, and associated data structures. Used to represent
//! a port before it is opened for reading/writing.
//!

use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::null_mut,
    slice::from_raw_parts,
};

use alloc::{string::String, vec::Vec};
use wdk::nt_success;
use wdk_alloc::WdkAllocator;
use wdk_mutex::errors::DriverMutexError;
use wdk_sys::{
    ntddk::{
        memcpy, IoGetRelatedDeviceObject, ObReferenceObjectByHandle, RtlInitUnicodeString, ZwClose,
        ZwCreateFile,
    }, IoFileObjectType, FILE_ATTRIBUTE_NORMAL, FILE_OPEN, FILE_READ_DATA, FILE_WRITE_DATA, GENERIC_READ, GENERIC_WRITE, HANDLE, IO_STATUS_BLOCK, NTSTATUS, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, OBJ_KERNEL_HANDLE, PFILE_OBJECT, PVOID, PZZWSTR, UNICODE_STRING, _MODE::KernelMode
};

use crate::{
    port::{NewPortErr, Port, PortIdentifier},
    DEALLOC_LAYOUT,
};

#[derive(Debug)]
pub enum OpenPortErr {
    #[allow(dead_code)]
    FailedToCreateHandle(NTSTATUS),
    #[allow(dead_code)]
    FailedToGetObjectFromHandle(NTSTATUS),
    #[allow(dead_code)]
    FailedToMakePort(NewPortErr),
    #[allow(dead_code)]
    FailedToCreateMutex(DriverMutexError),
}

///
/// Represents a possible port to open, and its identifying information, as well
/// as any necessary information to open the port.
///
pub struct PortInfo {
    /// The String form of the path, used for easy comparison.
    pub path: String,

    /// The underlying UNICODE_STRING, used to open a handle to the port.
    /// The underlying buffer must have no other references, and must have been
    /// allocated with WdkAllocator.
    unicode_path: UNICODE_STRING,
}

impl PortInfo {
    ///
    /// `new` is a constructor for a PortInfo instance.
    ///
    /// # Arguments
    ///
    /// * `path` - The string form of the absolute port path.
    /// * `unicode_path` - The unicode form of the absolute port path. This must
    ///   have no other references, and have been allocated via WdkAllocator.
    ///   It is taken by this function, and will be released upon the PortInfo
    ///   dropping.
    ///
    /// # Return value:
    ///
    /// * `PortInfo` - The new PortInfo instance
    ///
    pub fn new(path: String, unicode_path: UNICODE_STRING) -> Self {
        Self { path, unicode_path }
    }

    ///
    /// `from_wstr_array` takes a PZZWSTR from a successful
    /// IoGetDeviceInterfaces call, and converts it into a Vec<PortInfo>.
    ///
    /// # Arguments
    ///
    /// * `wstr_array` - The PZZWSTR from IoGetDeviceInterfaces, guaranteeing it
    ///   is a pointer to "a buffer that contains a list of Unicode strings.
    ///   Each Unicode string in the list is null-terminated; the end of the
    ///   whole list is marked by an additional null character"(MSDN).
    ///
    /// # Return value:
    ///
    /// * `Vec<PortInfo>` - The list of PortInfos extracted from the wstr array.
    ///
    pub fn from_wstr_array(wstr_array: PZZWSTR) -> Vec<PortInfo> {
        let mut list = Vec::new();

        let mut start = wstr_array;
        if start.is_null() {
            return list;
        }

        loop {
            let mut end = start;

            // SAFETY: This is safe because:
            //         1. `start`, and thus `end` are non null.
            //         2. `end` is a pointer to a null terminated unicode 
            //            string.
            unsafe {
                while *end != 0 {
                    end = end.add(1);
                }
            }

            let length = (end as usize - start as usize) / size_of::<u16>();
            if length == 0 {
                break;
            }

            // SAFETY: This is safe because:
            //         1. `length` is less than i32::MAX, as it is less than half of
            //            usize::MAX. Also the max length of a string returned by
            //            IoGetDeviceInterfaces is probably <256.
            //         2. `start` is non null.
            //         3. TODO: verify start's alignment.
            let slice = unsafe { from_raw_parts(start, length) };
            let path = String::from_utf16_lossy(slice);
            let mut unicode_path = UNICODE_STRING::default();

            let string_layout = Layout::from_size_align((length + 1) * 2, 1).unwrap();

            // SAFETY: This is safe because:
            //         The result pointer is compared against null.
            let string_clone = unsafe { WdkAllocator.alloc(string_layout) as *mut u16 };

            if !string_clone.is_null() {
                // SAFETY: This is safe because:
                //         1. `string_clone` is a verified valid pointer to a buffer
                //            of length == MaxCount.
                //         2. `start` is a verified valid pointer to a buffer of
                //            length > MaxCount.
                unsafe {
                    memcpy(
                        string_clone as *mut _,
                        start as *const _,
                        (length as u64 + 1) * 2,
                    );
                }

                // SAFETY: This is safe because:
                //         1. `string_clone` points to the start of a null
                //            terminated, never prematurely freed wide string, >0
                //            WCHARs long.
                //         2. `unicode_path` is a valid unicode string.
                unsafe {
                    RtlInitUnicodeString(&mut unicode_path, string_clone);
                }

                list.push(PortInfo::new(path, unicode_path));
            }

            // SAFETY: This is safe because:
            //         1. The last string is a single null byte, making it have
            //            length = 0, which would break above. Therefore there still
            //            are strings to follow, and we have access to at least the
            //            next byte.
            unsafe {
                start = end.add(1);
            }
        }

        list
    }

    ///
    /// `open_port` uses the information stored in a PortInfo to open read/write
    /// access to that port.
    ///
    /// Specifically, this function opens a file handle to the port path, and
    /// then gets the file object, and the associated device object for the
    /// port. The device object being necessary to send IRPs (and thus IOCTLs).
    ///
    /// The created port is then placed in the global port array, and its
    /// identifier is returned. To get the port, use the `GlobalPorts::get_port`
    /// function, and to close the port, use the `GlobalPorts::close_port`
    /// function.
    ///
    /// # Arguments:
    ///
    /// * `baud_rate` - The baud rate to open the port with.
    ///
    /// # Return value:
    ///
    /// * `Ok(PortIdentifier)` - The port identifier, if successful
    /// * `Err(OpenPortErr)` - Otherwise
    ///
    pub fn open(&mut self, baud_rate: u32) -> Result<PortIdentifier, OpenPortErr> {
        let mut attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            ObjectName: &mut self.unicode_path,
            Attributes: OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            ..Default::default()
        };

        let mut io_status = IO_STATUS_BLOCK::default();

        let mut file_handle: HANDLE = null_mut();
        // SAFETY: This is safe because:
        //         1. `handle` is allowed to be a null handle.
        //         2. `attributes` is a valid OBJECT_ATTRIBUTES.
        //         3. `io_status` is a valid IO_STATUS_BLOCK.
        //         4. AllocationSize is allowed to be null.
        //         5. EaBuffer is allowed to be null.
        let create_file_status = unsafe {
            ZwCreateFile(
                &mut file_handle,
                GENERIC_READ | GENERIC_WRITE,
                &mut attributes,
                &mut io_status,
                null_mut(),
                FILE_ATTRIBUTE_NORMAL,
                0,
                FILE_OPEN,
                0,
                null_mut(),
                0,
            )
        };

        if !nt_success(create_file_status) || file_handle.is_null() {
            return Err(OpenPortErr::FailedToCreateHandle(create_file_status));
        }

        let mut file_object: PFILE_OBJECT = null_mut();
        let file_object_ptr: *mut PFILE_OBJECT = &mut file_object;

        // SAFETY: This is safe because:
        //         1. `handle` is guaranteed to be a valid HANDLE by
        //            ZwCreateFile returning SUCCESS.
        //         2. `file_object` is allowed to be null.
        //         3. HandleInformation is allowed to be null.
        let ob_ref_status = unsafe {
            ObReferenceObjectByHandle(
                file_handle,
                FILE_READ_DATA | FILE_WRITE_DATA,
                *IoFileObjectType,
                KernelMode as i8,
                file_object_ptr as *mut PVOID,
                null_mut(),
            )
        };

        if !nt_success(ob_ref_status) || file_object.is_null() {
            // SAFETY: This is safe because:
            //         1. `handle` is guaranteed to be a valid HANDLE by
            //            ZwCreateFile returning SUCCESS.
            unsafe {
                let _ = ZwClose(file_handle);
            }
            return Err(OpenPortErr::FailedToGetObjectFromHandle(ob_ref_status));
        }

        // SAFETY: This is safe because:
        //         1. `file_object` is guaranteed to be a valid FILE_OBJECT
        //            pointer by ObReferenceObjectByHandle returning SUCCESS.
        let device_object = unsafe { IoGetRelatedDeviceObject(file_object) };

        Port::new(device_object, file_object, file_handle, baud_rate)
            .map_err(|e| OpenPortErr::FailedToMakePort(e))
    }
}

impl Drop for PortInfo {
    ///
    /// `drop` cleans up all stored data held by the PortInfo, freeing any in
    /// use memory.
    ///
    fn drop(&mut self) {
        // SAFETY: This is safe because:
        //         1. `unicode_path.Buffer` was allocated via WdkAllocator,
        //            and has no other references, as guaranteed by the
        //            invariant defined at both the field, and the constructor.
        unsafe {
            WdkAllocator.dealloc(self.unicode_path.Buffer as *mut _, DEALLOC_LAYOUT);
        }
    }
}
