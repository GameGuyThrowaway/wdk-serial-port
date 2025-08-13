use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
    ptr::null_mut,
    slice,
    sync::atomic::{AtomicPtr, Ordering},
};

use alloc::{boxed::Box, vec::Vec};
use wdk::nt_success;
use wdk_alloc::WdkAllocator;
use wdk_mutex::kmutex::KMutex;
use wdk_sys::{
    ntddk::{
        IoBuildDeviceIoControlRequest, IoBuildSynchronousFsdRequest, IofCallDriver,
        KeInitializeEvent, KeWaitForSingleObject, ObfDereferenceObject, ZwClose,
    },
    BOOLEAN, DO_DIRECT_IO, HANDLE, IO_STATUS_BLOCK, IRP_MJ_READ, IRP_MJ_WRITE, KEVENT, NTSTATUS,
    PDEVICE_OBJECT, PFILE_OBJECT, STATUS_PENDING, STATUS_SUCCESS, _DEVICE_OBJECT,
    _EVENT_TYPE::NotificationEvent,
    _IRP,
    _KWAIT_REASON::Executive,
    _MODE::KernelMode,
};

use ioctl::{
    IOCTL_SERIAL_GET_COMMSTATUS, IOCTL_SERIAL_SET_BAUD_RATE, IOCTL_SERIAL_SET_CHARS,
    IOCTL_SERIAL_SET_DTR, IOCTL_SERIAL_SET_HANDFLOW, IOCTL_SERIAL_SET_LINE_CONTROL,
    IOCTL_SERIAL_SET_RTS, IOCTL_SERIAL_SET_TIMEOUTS, IOCTL_SERIAL_SET_WAIT_MASK,
    IOCTL_SERIAL_WAIT_ON_MASK, SERIAL_CHARS, SERIAL_DTR_CONTROL, SERIAL_EV_RXCHAR, SERIAL_HANDFLOW,
    SERIAL_LINE_CONTROL, SERIAL_RTS_CONTROL, SERIAL_STATUS, SERIAL_TIMEOUTS, SERIAL_XOFF_CONTINUE,
};

use crate::{misc::IoSetCompletionRoutine, DEALLOC_LAYOUT};

mod ioctl;

/// One for keyboard, one for mouse, one for com0com, and 2 extras.
const MAX_OPEN_PORTS: usize = 5;
/// A global array of open ports, used for thread safe access to ports.
static OPEN_PORTS: [AtomicPtr<KMutex<Port>>; MAX_OPEN_PORTS] = [
    AtomicPtr::new(null_mut()),
    AtomicPtr::new(null_mut()),
    AtomicPtr::new(null_mut()),
    AtomicPtr::new(null_mut()),
    AtomicPtr::new(null_mut()),
];
/// The ordering to use when loading/storing in the OPEN_PORTS array.
const PORT_ORDERING: Ordering = Ordering::SeqCst;

pub struct GlobalPorts {}

impl GlobalPorts {
    ///
    /// Finds the next available atomic ptr for use, and inserts the data at that
    /// place, returning the place's identifier.
    ///
    /// Returns None if the port couldn't be inserted.
    ///
    fn add_port(port: *mut KMutex<Port>) -> Option<PortIdentifier> {
        for port_idx in 0..MAX_OPEN_PORTS {
            let ptr = OPEN_PORTS[port_idx].load(PORT_ORDERING);
            if ptr.is_null() {
                OPEN_PORTS[port_idx].store(port, PORT_ORDERING);
                return Some(PortIdentifier::from_port_idx(port_idx));
            }
        }
        None
    }

    ///
    /// Attempts to locate a port by its identifier.
    ///
    /// Returns a pointer to the port's mutex. Returns None if it cannot be
    /// found. If Some is returned, the pointer is guaranteed to be non null.
    ///
    pub fn get_port(id: PortIdentifier) -> Option<*mut KMutex<Port>> {
        if id.port_idx >= MAX_OPEN_PORTS {
            return None;
        }

        let port = OPEN_PORTS[id.port_idx].load(PORT_ORDERING);
        if port.is_null() {
            return None;
        }

        Some(port)
    }

    ///
    /// Attempts to close a port by its identifier.
    ///
    /// TODO: Should I add a status return in case the port wasn't found or
    /// couldn't be locked?
    ///
    pub fn close_port(identifier: PortIdentifier) {
        if identifier.port_idx >= MAX_OPEN_PORTS {
            return;
        }

        if let Some(mutex_ptr) = GlobalPorts::get_port(identifier) {
            OPEN_PORTS[identifier.port_idx].store(null_mut(), PORT_ORDERING);
            let mutex = unsafe { &*mutex_ptr };
            let port = mutex.lock().unwrap();
            port.close();
            let _ = unsafe { Box::from_raw(mutex_ptr) };
        }
    }

    ///
    /// Attempts to close all open ports. Typically used when the driver is
    /// exiting.
    ///
    pub fn close_all_ports() {
        for idx in 0..MAX_OPEN_PORTS {
            GlobalPorts::close_port(PortIdentifier::from_port_idx(idx));
        }
    }
}

///
/// Holds the key to access ports via GlobalPorts::get_port. This identifier
/// is unique to each Port, easily comparable, and easily copyable.
///
/// ASIDE:
///
/// This data structure can likely be removed if the method of safe concurrency
/// is changed (if `OPEN_PORTS`) is removed.
///
/// Technically GlobalPorts and PortIdentifier could be represented as traits
/// with implementations, however given their limited and coupled uses, that
/// seems unnecessarily complex.
///
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PortIdentifier {
    /// The underlying data used to identify and reference a port. This is used
    /// for this specific GlobalPorts implementation.
    port_idx: usize,
}

impl PortIdentifier {
    ///
    /// Creates a new PortIdentifier from the underlying identifier data.
    ///
    fn from_port_idx(port_idx: usize) -> Self {
        Self { port_idx }
    }
}

///
/// Represents an opened port, and any underlying data necessary to use the
/// port.
///
pub struct Port {
    /// Must be a pointer to a valid DEVICE_OBJECT.
    device_object: PDEVICE_OBJECT,
    /// Must be a pointer to a valid FILE_OBJECT.
    file_object: PFILE_OBJECT,
    /// Must be a valid HANDLE on the file located at the port's path.
    file_handle: HANDLE,
    /// The port's baud rate.
    #[allow(dead_code)]
    baud_rate: u32,
    /// The function called when an async read is completed. It is set by
    /// calling `start_async_read_system`. When this value is Some, it means the
    /// async read system has started. Otherwise it has not started yet.
    async_read_callback: Option<AsyncReadCallback>,
    /// The buffer used to store data until the callback fully processes it.
    /// This buffer basically holds context for when the callback can't entirely
    /// finish processing.
    read_buffer: Vec<u8>,
    /// An identifier used to retrieve the port from the GlobalPorts manager.
    /// This value should always be Some(PortIdentifier), outside of
    /// construction.
    identifier: Option<PortIdentifier>,
}

/// Start the read buffer at a capacity big enough for 99% of transfers.
const READ_BUFFER_CAPACITY: usize = 1024;

#[derive(Debug)]
pub enum NewPortErr {
    #[allow(dead_code)]
    FailedToInit(SendIRPErr),
    FailedToAddToPortArray,
}

impl Port {
    ///
    /// `new` is a constructor for a Port instance. It automatically inits the
    /// port after construction, prior to returning, using the provided baud
    /// rate. Also puts the port in a mutex, and in the GlobalPorts manager, for
    /// safe support of the async features. Returns the identifier needed to
    /// retrieve a specific port from the GlobalPorts manager.
    ///
    /// # Arguments
    ///
    /// * `device_object` - A valid DEVICE_OBJECT pointer.
    /// * `file_object` - A valid FILE_OBJECT pointer.
    /// * `file_handle` - A valid HANDLE to the file.
    /// * `baud_rate` - The baud rate to open the port with.
    ///
    /// # Return value:
    ///
    /// * `Some(PortIdentifier)` - The port identifier, upon success.
    /// * `Err(NewPortErr)` - Otherwise.
    ///
    pub fn new(
        device_object: PDEVICE_OBJECT,
        file_object: PFILE_OBJECT,
        file_handle: HANDLE,
        baud_rate: u32,
    ) -> Result<PortIdentifier, NewPortErr> {
        let port = Self {
            device_object,
            file_object,
            file_handle,
            baud_rate,
            async_read_callback: None,
            read_buffer: Vec::with_capacity(READ_BUFFER_CAPACITY),
            identifier: None,
        };

        let mutex = Box::new(KMutex::new(port).unwrap());
        let mutex_ptr = Box::into_raw(mutex);

        if let Some(identifier) = GlobalPorts::add_port(mutex_ptr) {
            let mutex_ptr = GlobalPorts::get_port(identifier).unwrap();
            if mutex_ptr.is_null() {
                // impossible in theory
                return Err(NewPortErr::FailedToAddToPortArray);
            }

            let mut port = unsafe { (*mutex_ptr).lock().unwrap() };
            port.identifier = Some(identifier);
            port.init(baud_rate)
                .map_err(|e| NewPortErr::FailedToInit(e))?;

            Ok(identifier)
        } else {
            let _ = unsafe { Box::from_raw(mutex_ptr) };
            Err(NewPortErr::FailedToAddToPortArray)
        }
    }

    ///
    /// `close` cleans up all stored data held by the Port, freeing any in use
    /// memory. The caller is required to immediately dispose of the port after
    /// calling this function. This function is internal, and only for use by
    /// `GlobalPorts::close_port`.
    ///
    fn close(&self) {
        // SAFETY: This is safe because:
        //         1. `file_object` is guaranteed to be a valid FILE_OBJECT
        //            pointer by ObReferenceObjectByHandle returning SUCCESS.
        //         2. We dereference the object as many times as we had
        //            referenced it.
        unsafe {
            ObfDereferenceObject(self.file_object as *mut _);
        }

        // SAFETY: This is safe because:
        //         1. `file_handle` is guaranteed to be a valid HANDLE.
        unsafe {
            let _ = ZwClose(self.file_handle);
        }
    }
}

#[derive(Debug)]
pub enum SendIRPErr {
    IRPBuildError,
    #[allow(dead_code)]
    WaitError(NTSTATUS),
    #[allow(dead_code)]
    CallDriverError(NTSTATUS),

    // Async Only Errors
    FailedToCloneData,
    FailedToCreateIoStatus,
    FailedToCreateContext,
}

impl Port {
    ///
    /// `write_blocking` writes some data on a port, blocking until the write
    /// completes.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to write.
    ///
    /// # Return value:
    ///
    /// * `Ok(usize)` - The length of data writte, if successful.
    /// * `Err(PortWriteErr)` - Otherwise.
    ///
    pub fn write_blocking(&self, data: &[u8]) -> Result<usize, SendIRPErr> {
        let mut event = KEVENT::default();
        let mut io_status = IO_STATUS_BLOCK::default();

        // SAFETY: This is safe because:
        //         1. `event` is guaranteed to be a valid KEVENT.
        unsafe {
            KeInitializeEvent(&mut event, NotificationEvent, false as u8);
        }

        // SAFETY: This is safe because:
        //         1. `device_object` is guaranteed to be a valid PDEVICE_OBJECT
        //            by the invariant in the field definition.
        //         2. Buffer is a pointer to a buffer with len = Length.
        //         3. StartingOffset is allowed to be null.
        //         4. `event` is a valid initialized KEVENT.
        //         5. `io_status` is a valid IO_STATUS_BLOCK.
        //         6. `data` will live longer than this request (event is waited
        //            before returning).
        let irp = unsafe {
            IoBuildSynchronousFsdRequest(
                IRP_MJ_WRITE,
                self.device_object,
                data.as_ptr() as *mut _,
                data.len() as u32,
                null_mut(),
                &mut event,
                &mut io_status,
            )
        };

        if irp.is_null() {
            return Err(SendIRPErr::IRPBuildError);
        }

        // SAFETY: This is safe because:
        //         1. `device_object` is guaranteed to be a valid PDEVICE_OBJECT
        //            by the invariant in the field definition.
        //         2. `irp` is guaranteed to be a valid IRP because it isn't
        //            null, and was returned by IoBuildSynchronousFsdRequest.
        let driver_call_status = unsafe { IofCallDriver(self.device_object, irp) };
        if driver_call_status == STATUS_PENDING {
            // SAFETY: This is safe because:
            //         1. `event` is a valid KEVENT.
            //         2. Timeout is allowed to be null.
            let wait_status = unsafe {
                KeWaitForSingleObject(
                    &mut event as *mut KEVENT as *mut _,
                    Executive,
                    KernelMode as i8,
                    false as u8,
                    null_mut(),
                )
            };

            if !nt_success(wait_status) {
                return Err(SendIRPErr::WaitError(wait_status));
            }
        }

        if nt_success(driver_call_status) {
            Ok(io_status.Information as usize)
        } else {
            Err(SendIRPErr::CallDriverError(driver_call_status))
        }
    }

    ///
    /// `read_blocking` reads some data from a port, appending it to the end of
    /// the read_buffer, blocking until exactly `len` bytes are read.
    ///
    /// # Arguments
    ///
    /// * `len` - The number of bytes to read.
    ///
    /// # Return value:
    ///
    /// * `Ok()` - Upon success.
    /// * `Err(PortWriteErr)` - Otherwise.
    ///
    fn read_blocking(&mut self, len: usize) -> Result<(), SendIRPErr> {
        let mut event = KEVENT::default();
        let mut io_status = IO_STATUS_BLOCK::default();

        // SAFETY: This is safe because:
        //         1. `event` is guaranteed to be a valid KEVENT.
        unsafe {
            KeInitializeEvent(&mut event, NotificationEvent, false as u8);
        }

        let prev_end = self.read_buffer.len();
        let new_end = prev_end + len;
        self.read_buffer.resize(new_end, 0);

        let data = &mut self.read_buffer[prev_end..new_end];

        // SAFETY: This is safe because:
        //         1. `device_object` is guaranteed to be a valid PDEVICE_OBJECT
        //            by the invariant in the field definition.
        //         2. Buffer is a pointer to a buffer with len = Length.
        //         3. StartingOffset is allowed to be null.
        //         4. `event` is a valid initialized KEVENT.
        //         5. `io_status` is a valid IO_STATUS_BLOCK.
        //         6. `data` will live longer than this request (event is waited
        //            before returning).
        let irp = unsafe {
            IoBuildSynchronousFsdRequest(
                IRP_MJ_READ,
                self.device_object,
                data.as_ptr() as *mut _,
                len as u32,
                null_mut(),
                &mut event,
                &mut io_status,
            )
        };

        if irp.is_null() {
            return Err(SendIRPErr::IRPBuildError);
        }

        // SAFETY: This is safe because:
        //         1. `device_object` is guaranteed to be a valid PDEVICE_OBJECT
        //            by the invariant in the field definition.
        //         2. `irp` is guaranteed to be a valid IRP because it isn't
        //            null, and was returned by IoBuildSynchronousFsdRequest.
        let driver_call_status = unsafe { IofCallDriver(self.device_object, irp) };
        if driver_call_status == STATUS_PENDING {
            // SAFETY: This is safe because:
            //         1. `event` is a valid KEVENT.
            //         2. Timeout is allowed to be null.
            let wait_status = unsafe {
                KeWaitForSingleObject(
                    &mut event as *mut KEVENT as *mut _,
                    Executive,
                    KernelMode as i8,
                    false as u8,
                    null_mut(),
                )
            };

            if !nt_success(wait_status) {
                return Err(SendIRPErr::WaitError(wait_status));
            }
        }

        if nt_success(driver_call_status) {
            Ok(())
        } else {
            Err(SendIRPErr::CallDriverError(driver_call_status))
        }
    }

    ///
    /// `send_ioctl` writes an IOCTL request to the port, blocking until the
    /// request completes.
    ///
    /// # Arguments
    ///
    /// * `control_code` - The IOCTL control code for the request.
    /// * `input_data` - The data to be sent alongside the request.
    /// * `output_data` - The buffer to receive data on. Make sure the length
    ///   is correct, or there may be unexpected side effects.
    ///
    /// # Return value:
    ///
    /// * `Ok(NTSTATUS)` - The ioctl status/response, if successful.
    /// * `Err(PortWriteErr)` - Otherwise.
    ///
    fn send_ioctl_blocking(
        &self,
        control_code: u32,
        input_data: &[u8],
        output_data: &mut [u8],
    ) -> Result<NTSTATUS, SendIRPErr> {
        let mut event = KEVENT::default();
        let mut io_status = IO_STATUS_BLOCK::default();

        // SAFETY: This is safe because:
        //         1. `event` is guaranteed to be a valid KEVENT.
        unsafe {
            KeInitializeEvent(&mut event, NotificationEvent, false as u8);
        }

        // SAFETY: This is safe because:
        //         1. `device_object` is guaranteed to be a valid PDEVICE_OBJECT
        //            by the invariant in the field definition.
        //         2. OutputBuffer is allowed to be null.
        //         3. `event` is a valid initialized KEVENT.
        //         4. `io_status` is a valid IO_STATUS_BLOCK.
        //         5. `data` will live longer than this request (event is waited
        //            before returning).
        let irp = unsafe {
            IoBuildDeviceIoControlRequest(
                control_code,
                self.device_object,
                input_data.as_ptr() as *mut _,
                input_data.len() as u32,
                output_data.as_mut_ptr() as *mut _,
                output_data.len() as u32,
                false as u8,
                &mut event,
                &mut io_status,
            )
        };

        if irp.is_null() {
            return Err(SendIRPErr::IRPBuildError);
        }

        // SAFETY: This is safe because:
        //         1. `device_object` is guaranteed to be a valid PDEVICE_OBJECT
        //            by the invariant in the field definition.
        //         2. `irp` is guaranteed to be a valid IRP because it isn't
        //            null, and was returned by IoBuildSynchronousFsdRequest.
        let driver_call_status = unsafe { IofCallDriver(self.device_object, irp) };
        if driver_call_status == STATUS_PENDING {
            // SAFETY: This is safe because:
            //         1. `event` is a valid KEVENT.
            //         2. Timeout is allowed to be null.
            let wait_status = unsafe {
                KeWaitForSingleObject(
                    &mut event as *mut KEVENT as *mut _,
                    Executive,
                    KernelMode as i8,
                    false as u8,
                    null_mut(),
                )
            };

            if !nt_success(wait_status) {
                return Err(SendIRPErr::WaitError(wait_status));
            }
        }

        if nt_success(driver_call_status) {
            // SAFETY: This is safe because:
            //         1. I am not interpreting the union as a pointer, but
            //            rather a status. So either the status is meaningless,
            //            which the caller should know from the IOCTL
            //            documentation, in which case this is safe, or the
            //            status is accurate, in which case this is safe.
            let status = unsafe { io_status.__bindgen_anon_1.Status };
            Ok(status)
        } else {
            Err(SendIRPErr::CallDriverError(driver_call_status))
        }
    }

    ///
    /// `send_ioctl_async` writes an IOCTL request to the port asynchronously.
    /// As such, it instantly returns, and the provided completion_routine is
    /// called upon ioctl completion.
    ///
    /// # Arguments
    ///
    /// * `control_code` - The IOCTL control code for the request.
    /// * `input_data` - The data to be sent alongside the request.
    /// * `output_data_len` - The size of the output buffer to be allocated, and
    ///   thus the maximum amount of return data possible.
    /// * `completion_routine` - The function called when the IOCTL finishes.
    ///
    /// # Return value:
    ///
    /// * `Ok()` - Upon success.
    /// * `Err(PortWriteErr)` - Otherwise.
    ///
    fn send_ioctl_async(
        &self,
        control_code: u32,
        input_data: &[u8],
        output_data_len: usize,
        completion_routine: Option<AsyncIOCTLCallback>,
    ) -> Result<(), SendIRPErr> {
        let io_layout = Layout::new::<IO_STATUS_BLOCK>();
        // SAFETY: This is safe because:
        //         The result pointer is compared against null.
        let io_status = unsafe { WdkAllocator.alloc(io_layout) as *mut IO_STATUS_BLOCK };

        if io_status.is_null() {
            return Err(SendIRPErr::FailedToCreateIoStatus);
        }

        let data_layout = Layout::from_size_align(input_data.len(), 1).unwrap();
        // SAFETY: This is safe because:
        //         The result pointer is compared against null.
        let data_clone = unsafe { WdkAllocator.alloc(data_layout) };

        if data_clone.is_null() {
            // SAFETY: This is safe because:
            //         1. `io_status` is a valid WdkAllocator allocated pool,
            //            with no dangling pointers.
            unsafe {
                WdkAllocator.dealloc(io_status as *mut _, DEALLOC_LAYOUT);
            }
            return Err(SendIRPErr::FailedToCloneData);
        }

        let context_layout = Layout::new::<AsyncIOCTLContext>();
        // SAFETY: This is safe because:
        //         The result pointer is compared against null.
        let context = unsafe { WdkAllocator.alloc(context_layout) as *mut AsyncIOCTLContext };

        if context.is_null() {
            // SAFETY: This is safe because:
            //         1. `io_status` is a valid WdkAllocator allocated pool,
            //            with no dangling pointers.
            //         2. `data_clone` is a valid WdkAllocator allocated pool,
            //            with no dangling pointers.
            unsafe {
                WdkAllocator.dealloc(io_status as *mut _, DEALLOC_LAYOUT);
                WdkAllocator.dealloc(data_clone, DEALLOC_LAYOUT);
            }
            return Err(SendIRPErr::FailedToCreateContext);
        }

        // SAFETY: This is safe because:
        //         We have proven that `context` is not null, and we are
        //         guaranteed that if it is not, it is the size of an
        //         AsyncIOCTLContext.
        unsafe {
            (*context).identifier = self.identifier.unwrap();
            (*context).input_data = data_clone;
            (*context).io_status = io_status;
            (*context).completion_routine = completion_routine;
        }

        // SAFETY: This is safe because:
        //         1. `device_object` is guaranteed to be a valid PDEVICE_OBJECT
        //            by the invariant in the field definition.
        //         2. OutputBuffer is allowed to be null.
        //         3. `event` is allowed to be null.
        //         4. `io_status` is a valid IO_STATUS_BLOCK, with a lifetime
        //            ending in the request's completion routine.
        //         5. `data_clone` is a buffer with length `data.len()`, and a
        //            lifetime ending in the request's completion routine.
        let irp = unsafe {
            IoBuildDeviceIoControlRequest(
                control_code,
                self.device_object,
                data_clone as *mut _,
                input_data.len() as u32,
                null_mut(),
                output_data_len as u32,
                false as u8,
                null_mut(),
                io_status,
            )
        };

        if irp.is_null() {
            // SAFETY: This is safe because:
            //         1. `io_status` is a valid WdkAllocator allocated pool,
            //            with no dangling pointers.
            //         2. `data_clone` is a valid WdkAllocator allocated pool,
            //            with no dangling pointers.
            unsafe {
                WdkAllocator.dealloc(io_status as *mut _, DEALLOC_LAYOUT);
                WdkAllocator.dealloc(data_clone, DEALLOC_LAYOUT);
                WdkAllocator.dealloc(context as *mut _, DEALLOC_LAYOUT);
            }
            return Err(SendIRPErr::IRPBuildError);
        }

        // SAFETY: This is safe because:
        //         1. `irp` is a valid pointer to a valid IRP.
        //         2. `CompletionRoutine` is either None, or contains a
        //            guaranteed safe function.
        unsafe {
            IoSetCompletionRoutine(
                irp,
                Some(async_ioctl_completion_routine),
                context as *mut _,
                true as BOOLEAN,
                true as BOOLEAN,
                true as BOOLEAN,
            );
        }

        // SAFETY: This is safe because:
        //         1. `device_object` is guaranteed to be a valid PDEVICE_OBJECT
        //            by the invariant in the field definition.
        //         2. `irp` is guaranteed to be a valid IRP because it isn't
        //            null, and was returned by IoBuildDeviceIoControlRequest.
        let driver_call_status = unsafe { IofCallDriver(self.device_object, irp) };
        if !nt_success(driver_call_status) {
            // SAFETY: This is safe because:
            //         1. `io_status` is a valid WdkAllocator allocated pool,
            //            with no dangling pointers.
            //         2. `data_clone` is a valid WdkAllocator allocated pool,
            //            with no dangling pointers.
            unsafe {
                WdkAllocator.dealloc(io_status as *mut _, DEALLOC_LAYOUT);
                WdkAllocator.dealloc(data_clone, DEALLOC_LAYOUT);
                WdkAllocator.dealloc(context as *mut _, DEALLOC_LAYOUT);
            }
            return Err(SendIRPErr::CallDriverError(driver_call_status));
        }

        Ok(())
    }

    ///
    /// `init` sets the default port configuration, as well as the
    /// caller-defined baud rate.
    ///
    /// Specifically, it sets the baud rate, stop bits, parity, byte size,
    /// xon/xoff/error/break/evt/eof characters, xon/xoff limits, timeouts, RTS,
    /// DTR, and handshake flow control.
    ///
    /// The default values were taken from identifying what the Arduino Legacy
    /// IDE's Serial Monitor set when connecting.
    ///
    /// TODO: research into potentially better default values, or attempting to
    /// use IOCTL_SERIAL_APPLY_DEFAULT_CONFIGURATION before using these values.
    ///
    /// # Arguments
    ///
    /// * `baud_rate` - The baud rate to set the port as operating at.
    ///
    /// # Return value:
    ///
    /// * `Ok()` - Upon success.
    /// * `Err(PortWriteErr)` - Otherwise.
    ///
    fn init(&self, baud_rate: u32) -> Result<(), SendIRPErr> {
        self.send_ioctl_blocking(
            IOCTL_SERIAL_SET_BAUD_RATE,
            &baud_rate.to_le_bytes(),
            &mut [],
        )?;

        let line_control = SERIAL_LINE_CONTROL {
            StopBits: 0,
            Parity: 0,
            WordLength: 8,
        };
        let chars = SERIAL_CHARS {
            EofChar: 0x00,
            ErrorChar: 0x00,
            BreakChar: 0x00,
            EventChar: 0x00,
            XonChar: 0x11,
            XoffChar: 0x13,
        };
        let handflow = SERIAL_HANDFLOW {
            ControlHandShake: SERIAL_DTR_CONTROL,
            FlowReplace: SERIAL_RTS_CONTROL | SERIAL_XOFF_CONTINUE,
            XonLimit: 2048,
            XoffLimit: 512,
        };
        let timeouts = SERIAL_TIMEOUTS {
            ReadIntervalTimeout: 0,
            ReadTotalTimeoutMultiplier: 0,
            ReadTotalTimeoutConstant: 0,
            WriteTotalTimeoutMultiplier: 0,
            WriteTotalTimeoutConstant: 0,
        };

        self.send_ioctl_blocking(IOCTL_SERIAL_SET_RTS, &[], &mut [])?;
        self.send_ioctl_blocking(IOCTL_SERIAL_SET_DTR, &[], &mut [])?;
        self.send_ioctl_blocking(
            IOCTL_SERIAL_SET_LINE_CONTROL,
            &line_control.to_bytes(),
            &mut [],
        )?;
        self.send_ioctl_blocking(IOCTL_SERIAL_SET_CHARS, &chars.to_bytes(), &mut [])?;
        self.send_ioctl_blocking(IOCTL_SERIAL_SET_HANDFLOW, &handflow.to_bytes(), &mut [])?;
        self.send_ioctl_blocking(IOCTL_SERIAL_SET_TIMEOUTS, &timeouts.to_bytes(), &mut [])?;

        Ok(())
    }

    ///
    /// `start_async_read_system` starts the async read system, which consists
    /// of a routine called whenever the port is sent some data.
    ///
    /// This system works by first setting the serial wait mask to RXCHAR,
    /// making the serial port driver respond to a WAIT_ON_MASK once it receives
    /// one or more characters. Then we create a IOCTL_SERIAL_WAIT_ON_MASK, and
    /// make it asynchronous. When it completes, we know there is some data
    /// available, so we make a IOCTL_SERIAL_GET_COMMSTATUS request, fetching
    /// the available bytes. Then, to end it off, we queue the IRP_MJ_READ, with
    /// the length equal to the number of available bytes, and call the
    /// appropriate callback once it completes.
    ///
    /// As an aside, when the IOCTL_SERIAL_WAIT_ON_MASK completes, we queue
    /// another one, allowing the read system to cycle forever.
    ///
    /// This function consists purely of setting the wait mask, and queueing the
    /// cyclic WAIT_ON_MASK call.
    ///
    /// This function will only operate the first time it is called. All
    /// proceeding calls on the same port are ignored, as the async read stream
    /// is already started. They will however return Ok(()).
    ///
    /// The read system receives data asynchronously from the serial port,
    /// buffers it internally, and then calls the `callback` with the buffer.
    /// Data is only ever removed from the buffer when the callback returns a
    /// usize.
    ///
    /// # Arguments
    ///
    /// * `callback` - A function to call when a read is completed, which is
    /// passed a reference to the internal data buffer.
    ///
    /// # Return value:
    ///
    /// * `Ok()` - Upon success.
    /// * `Err(PortWriteErr)` - Otherwise.
    ///
    pub fn start_async_read_system(
        &mut self,
        callback: AsyncReadCallback,
    ) -> Result<(), SendIRPErr> {
        if self.async_read_callback.is_some() {
            return Ok(());
        }

        let wait_mask = SERIAL_EV_RXCHAR;
        self.send_ioctl_blocking(
            IOCTL_SERIAL_SET_WAIT_MASK,
            &wait_mask.to_le_bytes(),
            &mut [],
        )?;
        self.async_read_callback = Some(callback);
        let async_ioctl_result = self.send_ioctl_async(
            IOCTL_SERIAL_WAIT_ON_MASK,
            &[],
            size_of::<u32>(),
            Some(rxchar_callback),
        );

        if let Err(e) = async_ioctl_result {
            self.async_read_callback = None;
            return Err(e);
        }

        Ok(())
    }
}

///
/// `AsyncReadCallback` defines a completion routine called when an asynchronous
/// read finishes on the serial port. It gives data to the callback, and expects
/// the callback to say how much data it has "consumed" (how much data can be
/// deleted from the buffer).
///
/// # Arguments
///
/// * `identifier` - The serial port's identifier, telling the callback which
///   serial port the read came from.
/// * `data` - The serial port's data buffer, showing the total data read.
///
/// # Return value:
///
/// * `usize` - The amount of data read and used, which can be removed from the
/// serial port's data buffer, shifting the buffer left by `amount` bytes. The
/// buffer's new 0th index will become data[amount].
///
type AsyncReadCallback = fn(identifier: PortIdentifier, data: &[u8]) -> usize;

///
/// `rxchar_callback` is the completion routine for the RXCHAR WAIT_ON_MASK
/// serial IOCTL. As such, this function is called when one or more characters
/// are received by a serial port.
///
/// When the RXCHAR IOCTL was successful, this function is expected to send
/// an IOCTL asking the serial port how much data it has available, and
/// then send an IRP_MJ_READ to read the data.
///
/// This function should also re-submit a WAIT_ON_MASK IOCTL to repeat the read
/// cycle.
///
/// TODO: The WAIT_ON_MASK docs don't say much about potential errors. I assume
/// that if it wasn't successful, the serial port is likely closed/unavailable.
///
/// # Arguments
///
/// * `port` - A valid pointer to a mutex holding the port the IOCTL was for.
/// * `status` - The status of the IOCTL request.
/// * `data` - The output data of the IOCTL request.
///
fn rxchar_callback(port: *mut KMutex<Port>, status: NTSTATUS, data: &[u8]) {
    if data.len() != 4 {
        return;
    }

    let wait_mask = u32::from_le_bytes(data.try_into().unwrap());
    if (wait_mask & SERIAL_EV_RXCHAR) == 0 {
        return;
    }

    if !nt_success(status) {
        return;
    }

    let mut port = unsafe { (*port).lock().unwrap() };
    let _ = port.send_ioctl_async(
        IOCTL_SERIAL_WAIT_ON_MASK,
        &[],
        size_of::<u32>(),
        Some(rxchar_callback),
    );

    let mut data = [0u8; size_of::<SERIAL_STATUS>()];
    if let Ok(len_status) = port.send_ioctl_blocking(IOCTL_SERIAL_GET_COMMSTATUS, &[], &mut data) {
        if !nt_success(len_status) {
            return;
        }

        let serial_status = SERIAL_STATUS::from_bytes(data);
        let bytes_available = serial_status.AmountInInQueue as usize;

        if let Ok(_) = port.read_blocking(bytes_available) {
            let read_callback = &port.async_read_callback.unwrap();
            let to_delete = read_callback(port.identifier.unwrap(), &port.read_buffer);
            let end_idx = to_delete.min(port.read_buffer.len());
            port.read_buffer.drain(0..end_idx);
        }
    }
}

/// A completion routine, called upon an asynchronous IOCTL completing. This
/// passes the resulting status and output data. `port` is guaranteed to be non
/// null.
type AsyncIOCTLCallback = fn(port: *mut KMutex<Port>, status: NTSTATUS, data: &[u8]);

///
/// A structure used to hold the context of an on-going asynchronous IOCTL
/// request, useful for cleaning up memory once it finishes, and calling the
/// expected completion routine.
///
struct AsyncIOCTLContext {
    /// The identifier for the port the IOCTL was sent on.
    identifier: PortIdentifier,
    /// A pointer to the WdkAllocator allocated IO_STATUS_BLOCK used by the
    /// IOCTL. Deallocated in completion routine so that lifetime is correct.
    io_status: *mut IO_STATUS_BLOCK,
    /// A pointer to the WdkAllocator allocated input data buffer used by the
    /// IOCTL. Deallocated in completion routine so that lifetime is correct.
    input_data: *mut u8,
    /// The completion routine, to be called when the async IOCTL is finished.
    completion_routine: Option<AsyncIOCTLCallback>,
}

// SAFETY: This is safe because:
//         1. This routine is only used by `send_ioctl_async`, guaranteeing the
//            invariant should be maintained.
//         2. `context` is always be an AsyncIOCTLContext allocated via
//            WdkAllocator, and thus should never be null.
//         3. `device_object` isn't trusted, and is compared to null before use.
unsafe extern "C" fn async_ioctl_completion_routine(
    device_object: *mut _DEVICE_OBJECT,
    irp: *mut _IRP,
    context: *mut c_void,
) -> NTSTATUS {
    if !context.is_null() && !irp.is_null() {
        let context = context as *mut AsyncIOCTLContext;
        // SAFETY: This is safe because:
        //         1. `context` is guaranteed to be a non null pointer to a
        //            valid AsyncIOCTLContext object.
        //         2. `irp` is guaranteed to be a non null pointer to a valid
        //            IRP.
        //         3. `device_object` is verified as a non null pointer, and
        //            thus a valid DEVICE_OBJECT before dereferencing.
        //         4. `input_data` is guaranteed to have been already used and
        //            no longer referenced by the IOCTL.
        //         5. `io_status` is assumed (TODO) to be no longer referenced,
        //            as the IOCTL is presumed complete. However I have some
        //            uncertainties about this, as I found that the passed
        //            output buffer was consistently not written until after the
        //            completion routine was called. Similarly, I found that the
        //            io_status didn't match in value to IRP.IoStatus.
        unsafe {
            WdkAllocator.dealloc((*context).io_status as *mut _, DEALLOC_LAYOUT);
            WdkAllocator.dealloc((*context).input_data as *mut _, DEALLOC_LAYOUT);

            let port = GlobalPorts::get_port((*context).identifier).unwrap();
            if !port.is_null() {
                if let Some(callback) = (*context).completion_routine {
                    let status = (*irp).IoStatus.__bindgen_anon_1.Status;
                    let bytes_read = (*irp).IoStatus.Information as usize;
                    let raw_data = {
                        if !device_object.is_null()
                            && ((*device_object).Flags & DO_DIRECT_IO) == DO_DIRECT_IO
                        {
                            todo!()
                            // (*irp).MdlAddress as *mut u8
                        } else {
                            (*irp).AssociatedIrp.SystemBuffer as *mut u8
                        }
                    };

                    let mut data = Vec::with_capacity(bytes_read);
                    if !raw_data.is_null() {
                        let slice = slice::from_raw_parts(raw_data, bytes_read);
                        data.extend_from_slice(slice);
                    }

                    callback(port, status, &data);
                }
            }

            WdkAllocator.dealloc(context as *mut _, DEALLOC_LAYOUT);
        }
    }
    STATUS_SUCCESS
}
