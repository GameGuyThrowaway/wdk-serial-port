use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::null_mut,
    slice,
    sync::atomic::{AtomicPtr, Ordering},
};

use alloc::{boxed::Box, vec::Vec};
use wdk::{nt_success, println};
use wdk_alloc::WdkAllocator;
use wdk_mutex::kmutex::KMutex;
use wdk_sys::{
    ntddk::{
        ExQueueWorkItem, IoBuildDeviceIoControlRequest, IoBuildSynchronousFsdRequest,
        IofCallDriver, KeInitializeEvent, KeWaitForSingleObject, ObfDereferenceObject, ZwClose,
    },
    BOOLEAN, DO_DIRECT_IO, HANDLE, IO_STATUS_BLOCK, IRP_MJ_FLUSH_BUFFERS, IRP_MJ_READ,
    IRP_MJ_WRITE, KEVENT, NTSTATUS, PDEVICE_OBJECT, PFILE_OBJECT, PIO_STATUS_BLOCK, PIRP, PVOID,
    PWORK_QUEUE_ITEM, STATUS_PENDING, STATUS_SUCCESS, WORK_QUEUE_ITEM,
    _EVENT_TYPE::NotificationEvent,
    _KWAIT_REASON::Executive,
    _MODE::KernelMode,
    _WORK_QUEUE_TYPE::DelayedWorkQueue,
};

use ioctl::{
    IOCTL_SERIAL_GET_COMMSTATUS, IOCTL_SERIAL_SET_BAUD_RATE, IOCTL_SERIAL_SET_CHARS,
    IOCTL_SERIAL_SET_DTR, IOCTL_SERIAL_SET_HANDFLOW, IOCTL_SERIAL_SET_LINE_CONTROL,
    IOCTL_SERIAL_SET_RTS, IOCTL_SERIAL_SET_TIMEOUTS, IOCTL_SERIAL_SET_WAIT_MASK,
    IOCTL_SERIAL_WAIT_ON_MASK, SERIAL_CHARS, SERIAL_DTR_CONTROL, SERIAL_EV_RXCHAR, SERIAL_HANDFLOW,
    SERIAL_LINE_CONTROL, SERIAL_RTS_CONTROL, SERIAL_STATUS, SERIAL_TIMEOUTS, SERIAL_XOFF_CONTINUE,
};

use crate::{
    misc::{ExInitializeWorkItem, IoSetCompletionRoutine},
    port::ioctl::SERIAL_EV_TXEMPTY,
    DEALLOC_LAYOUT,
};

mod ioctl;

/// One for keyboard, one for mouse, one for com0com, and 2 extras.
const MAX_OPEN_PORTS: usize = 5;
/// A global array of open ports, used for thread safe access to ports.
static OPEN_PORTS: [AtomicPtr<KMutex<SerialPort>>; MAX_OPEN_PORTS] = [
    AtomicPtr::new(null_mut()),
    AtomicPtr::new(null_mut()),
    AtomicPtr::new(null_mut()),
    AtomicPtr::new(null_mut()),
    AtomicPtr::new(null_mut()),
];
/// The ordering to use when loading/storing in the OPEN_PORTS array.
const PORT_ORDERING: Ordering = Ordering::SeqCst;

pub struct GlobalSerialPorts {}

impl GlobalSerialPorts {
    ///
    /// Finds the next available atomic ptr for use, and inserts the data at that
    /// place, returning the place's identifier.
    ///
    /// Returns None if the port couldn't be inserted.
    ///
    fn add_port(port: *mut KMutex<SerialPort>) -> Option<SerialPortIdentifier> {
        for port_idx in 0..MAX_OPEN_PORTS {
            let ptr = OPEN_PORTS[port_idx].load(PORT_ORDERING);
            if ptr.is_null() {
                OPEN_PORTS[port_idx].store(port, PORT_ORDERING);
                return Some(SerialPortIdentifier::from_port_idx(port_idx));
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
    pub fn get_port(id: SerialPortIdentifier) -> Option<*mut KMutex<SerialPort>> {
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
    pub fn close_port(identifier: SerialPortIdentifier) {
        if identifier.port_idx >= MAX_OPEN_PORTS {
            return;
        }

        if let Some(mutex_ptr) = GlobalSerialPorts::get_port(identifier) {
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
            GlobalSerialPorts::close_port(SerialPortIdentifier::from_port_idx(idx));
        }
    }
}

///
/// Holds the key to access ports via GlobalSerialPorts::get_port. This
/// identifier is unique to each SerialPort, easily comparable, and easily
/// copyable.
///
/// ASIDE:
///
/// This data structure can likely be removed if the method of safe concurrency
/// is changed (if `OPEN_PORTS`) is removed.
///
/// Technically GlobalSerialPorts and SerialPortIdentifier could be represented
/// as traits with implementations, however given their limited and coupled
/// uses, that seems unnecessarily complex.
///
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SerialPortIdentifier {
    /// The underlying data used to identify and reference a port. This is used
    /// for this specific GlobalSerialPorts implementation.
    port_idx: usize,
}

impl SerialPortIdentifier {
    ///
    /// Creates a new SerialPortIdentifier from the underlying identifier data.
    ///
    fn from_port_idx(port_idx: usize) -> Self {
        Self { port_idx }
    }
}

///
/// Represents an opened port, and any underlying data necessary to use the
/// port.
///
pub struct SerialPort {
    /// Must be a pointer to a valid DEVICE_OBJECT.
    device_object: PDEVICE_OBJECT,
    /// Must be a pointer to a valid FILE_OBJECT.
    file_object: PFILE_OBJECT,
    /// Must be a valid HANDLE on the file located at the port's path.
    file_handle: HANDLE,
    /// The port's baud rate.
    #[allow(dead_code)]
    baud_rate: u32,
    /// The callback called when an async read is completed. It is set by
    /// calling `start_async_read_system`. When this value is Some, it means the
    /// async read system has started. Otherwise it has not started yet.
    async_read_callback: Option<AsyncReadCallback>,
    /// The callback called when the serial port has fully flushed its write
    /// buffer. This value is set by calling `set_flush_callback`.
    hardware_flush_callback: Option<TXEmptyCallback>,
    /// The buffer used to store data until the callback fully processes it.
    /// This buffer basically holds context for when the callback can't entirely
    /// finish processing.
    read_buffer: Vec<u8>,
    /// An identifier used to retrieve the port from the GlobalSerialPorts
    /// manager. This value should always be Some(SerialPortIdentifier), outside
    /// of construction.
    identifier: Option<SerialPortIdentifier>,
}

/// Start the read buffer at a capacity big enough for 99% of transfers.
const READ_BUFFER_CAPACITY: usize = 1024;

#[derive(Debug)]
pub enum NewSerialPortErr {
    #[allow(dead_code)]
    FailedToInit(SendIRPErr),
    FailedToAddToSerialPortArray,
}

impl SerialPort {
    ///
    /// `new` is a constructor for a SerialPort instance. It automatically inits
    /// the port after construction, prior to returning, using the provided baud
    /// rate. Also puts the port in a mutex, and in the GlobalSerialPorts
    /// manager, for safe support of the async features. Returns the identifier
    /// needed to retrieve a specific port from the GlobalSerialPorts manager.
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
    /// * `Some(SerialPortIdentifier)` - The port identifier, upon success.
    /// * `Err(NewSerialPortErr)` - Otherwise.
    ///
    pub fn new(
        device_object: PDEVICE_OBJECT,
        file_object: PFILE_OBJECT,
        file_handle: HANDLE,
        baud_rate: u32,
    ) -> Result<SerialPortIdentifier, NewSerialPortErr> {
        let port = Self {
            device_object,
            file_object,
            file_handle,
            baud_rate,
            async_read_callback: None,
            hardware_flush_callback: None,
            read_buffer: Vec::with_capacity(READ_BUFFER_CAPACITY),
            identifier: None,
        };

        let mutex = Box::new(KMutex::new(port).unwrap());
        let mutex_ptr = Box::into_raw(mutex);

        if let Some(identifier) = GlobalSerialPorts::add_port(mutex_ptr) {
            let mutex_ptr = GlobalSerialPorts::get_port(identifier).unwrap();
            if mutex_ptr.is_null() {
                // impossible in theory
                return Err(NewSerialPortErr::FailedToAddToSerialPortArray);
            }

            let mut port = unsafe { (*mutex_ptr).lock().unwrap() };
            port.identifier = Some(identifier);
            port.init(baud_rate)
                .map_err(|e| NewSerialPortErr::FailedToInit(e))?;

            Ok(identifier)
        } else {
            // SAFETY: This is safe because:
            //         `mutex_ptr` was just created via Box::into_raw.
            let _ = unsafe { Box::from_raw(mutex_ptr) };
            Err(NewSerialPortErr::FailedToAddToSerialPortArray)
        }
    }

    ///
    /// `close` cleans up all stored data held by the SerialPort, freeing any in
    /// use memory. The caller is required to immediately dispose of the port
    /// after calling this function. This function is internal, and only for use
    /// by `GlobalSerialPorts::close_port`.
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

    // Read IRP Only Errors
    BufferAllocError,

    // Synchronous Only Errors
    Timeout,

    // Async Only Errors
    FailedToCloneData,
    FailedToCreateIoStatus,
    FailedToCreateContext,
}

impl SerialPort {
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
    /// * `Err(SendIRPErr)` - Otherwise.
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
    /// `flush` flushes the outgoing data on a port, blocking until the flush
    /// completes.
    ///
    /// # Return Value
    ///
    /// * `Ok(())` - Upon successful flushing.
    /// * `Err(SendIRPErr)` - Otherwise.
    ///
    pub fn flush(&self) -> Result<(), SendIRPErr> {
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
                IRP_MJ_FLUSH_BUFFERS,
                self.device_object,
                null_mut(),
                0,
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
    /// `set_baud_rate` sets the port's baud rate.
    /// 
    /// # Arguments
    /// 
    /// * `baud_rate` - The new baud rate.
    /// 
    /// # Return Value
    /// 
    /// * `Ok(())` - Upon success.
    /// * `Err(SendIRPErr)` - Otherwise.
    /// 
    pub fn set_baud_rate(&mut self, baud_rate: u32) -> Result<(), SendIRPErr> {
        self.send_ioctl_blocking(
            IOCTL_SERIAL_SET_BAUD_RATE,
            &baud_rate.to_le_bytes(),
            &mut [],
        )?;

        self.baud_rate = baud_rate;

        Ok(())
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
    /// * `Err(SendIRPErr)` - Otherwise.
    ///
    /// # Details
    ///
    /// This function can't have a timeout parameter because the only
    /// implementation would be on the KeWaitEvent, and terminating early would
    /// leave the IRP incomplete, which means either the buffer is prematurely
    /// freed (use after free), or its never freed (memory leak).
    ///
    /// Also we have to use a new buffer and not a pointer to the internal one
    /// because the pointer to a slice on the internal one could become invalid.
    ///
    fn read_blocking(&mut self, len: usize) -> Result<(), SendIRPErr> {
        let mut event = KEVENT::default();
        let mut io_status = IO_STATUS_BLOCK::default();

        // SAFETY: This is safe because:
        //         1. `event` is guaranteed to be a valid KEVENT.
        unsafe {
            KeInitializeEvent(&mut event, NotificationEvent, false as BOOLEAN);
        }

        let buffer_layout = Layout::from_size_align(len, 1).unwrap();
        // SAFETY: This is safe because:
        //         The result is compared to nullptr before being dereferenced.
        let buffer = unsafe { WdkAllocator.alloc_zeroed(buffer_layout) };
        if buffer.is_null() {
            return Err(SendIRPErr::BufferAllocError);
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
                IRP_MJ_READ,
                self.device_object,
                buffer as PVOID,
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
                // ERR: This is a memory leak. If we free the buffer, it's a
                // Use After Free.
                println!("[wdk-serial-port] Critical KeWait Error. Investigate immediately.");
                return Err(SendIRPErr::WaitError(wait_status));
            }
        }

        if nt_success(driver_call_status) {
            // SAFETY: This is safe because:
            //         `buffer` is a WdkAllocator allocated buffer, with length
            //         `len`.
            let slice = unsafe { slice::from_raw_parts(buffer, len) };
            self.read_buffer.extend(slice);
            // SAFETY: This is safe because:
            //         `buffer` is a WdkAllocator allocated buffer, with no more
            //         live references (the wait was successful).
            unsafe {
                WdkAllocator.dealloc(buffer, buffer_layout);
            }
            Ok(())
        } else {
            // SAFETY: This is safe because:
            //         `buffer` is a WdkAllocator allocated buffer, with no more
            //         live references (the wait was successful).
            unsafe {
                WdkAllocator.dealloc(buffer, buffer_layout);
            }
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
    /// * `Err(SendIRPErr)` - Otherwise.
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
            KeInitializeEvent(&mut event, NotificationEvent, false as BOOLEAN);
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
    /// * `completion_routine` - The function called when the IOCTL finishes,
    ///   called at <= IRQL_DISPATCH_LEVEL.
    ///
    /// # Return value:
    ///
    /// * `Ok()` - Upon success.
    /// * `Err(SendIRPErr)` - Otherwise.
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
        let context_ptr = unsafe { WdkAllocator.alloc(context_layout) as *mut AsyncIOCTLContext };

        if context_ptr.is_null() {
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
        //         `context_ptr` is a valid AsyncIOCTLContext pointer
        let context = unsafe { &mut *context_ptr };
        context.identifier = self.identifier.unwrap();
        context.input_data = data_clone;
        context.io_status = io_status;
        context.completion_routine = completion_routine;

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
                WdkAllocator.dealloc(context_ptr as *mut _, DEALLOC_LAYOUT);
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
                Some(async_ioctl_completion_routine_unsafe),
                context_ptr as *mut _,
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
                WdkAllocator.dealloc(context_ptr as *mut _, DEALLOC_LAYOUT);
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
    /// * `Err(SendIRPErr)` - Otherwise.
    ///
    fn init(&mut self, baud_rate: u32) -> Result<(), SendIRPErr> {
        self.set_baud_rate(baud_rate)?;

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
    /// of a routine called at IRQL_PASSIVE_LEVEL when the port receives data.
    ///
    /// The first time this function will call, it will start the wait on mask
    /// system, and enable the RXEMPTY feature. All further calls will simply
    /// change the callback.
    ///
    /// The read system receives data asynchronously from the serial port,
    /// buffers it internally, and then calls the `callback` with the buffer.
    /// Data is only ever removed from the buffer when the callback returns a
    /// usize.
    ///
    /// # Arguments
    ///
    /// * `callback` - A function to call when a read is completed, which is
    /// passed a reference to the internal data buffer. This function will
    /// always be called at IRQL_PASSIVE_LEVEL.
    ///
    /// # Return value:
    ///
    /// * `Ok()` - Upon success.
    /// * `Err(SendIRPErr)` - Otherwise.
    ///
    /// # Details:
    ///
    /// This system works by first adding RXCHAR to the serial wait mask,
    /// making the serial port driver respond to a WAIT_ON_MASK once it receives
    /// one or more characters. Then we start the wait on mask system if it
    /// isn't already. When it completes, if it was because of an RXCHAR, we
    /// know there is some data available, so we make a
    /// IOCTL_SERIAL_GET_COMMSTATUS request, fetching the available bytes. Then,
    /// to end it off, we queue the IRP_MJ_READ, with the length equal to the
    /// number of available bytes, and call the appropriate callback once it
    /// completes.
    ///
    /// Much of the above behavior is defined in other callbacks, like the
    /// `wait_on_mask_callback`.
    ///
    /// As an aside, when the IOCTL_SERIAL_WAIT_ON_MASK completes, we queue
    /// another one, allowing the read system to cycle forever.
    ///
    pub fn start_async_read_system(
        &mut self,
        callback: AsyncReadCallback,
    ) -> Result<(), SendIRPErr> {
        if self.async_read_callback.is_some() {
            self.async_read_callback = Some(callback);
            return Ok(());
        }

        let mut wait_mask = SERIAL_EV_RXCHAR;
        if self.hardware_flush_callback.is_some() {
            wait_mask |= SERIAL_EV_TXEMPTY;
        }

        self.send_ioctl_blocking(
            IOCTL_SERIAL_SET_WAIT_MASK,
            &wait_mask.to_le_bytes(),
            &mut [],
        )?;
        self.async_read_callback = Some(callback);

        // IOCTL_SERIAL_SET_WAIT_MASK resets the async wait system, so we
        // restart it here.
        if let Err(e) = self.send_async_wait_on_mask() {
            self.async_read_callback = None;
            return Err(e);
        }

        Ok(())
    }

    ///
    /// `set_flush_callback` sets the callback for when the hardware flushes its
    /// transmission buffer. This callback is called at IRQL_PASSIVE_LEVEL.
    ///
    /// The first time this function will call, it will start the wait on mask
    /// system, and enable the TXEMPTY feature. All further calls will simply
    /// change the callback.
    ///
    /// # Arguments
    ///
    /// * `callback` - A function to call when the serial port flushes its
    /// transmission buffer. This function will always be called at
    /// IRQL_PASSIVE_LEVEL.
    ///
    /// # Return value:
    ///
    /// * `Ok()` - Upon success.
    /// * `Err(SendIRPErr)` - Otherwise.
    ///
    pub fn set_flush_callback(&mut self, callback: TXEmptyCallback) -> Result<(), SendIRPErr> {
        if self.hardware_flush_callback.is_some() {
            self.hardware_flush_callback = Some(callback);
            return Ok(());
        }

        let mut wait_mask = SERIAL_EV_TXEMPTY;
        if self.async_read_callback.is_some() {
            wait_mask |= SERIAL_EV_RXCHAR;
        }

        self.send_ioctl_blocking(
            IOCTL_SERIAL_SET_WAIT_MASK,
            &wait_mask.to_le_bytes(),
            &mut [],
        )?;
        self.hardware_flush_callback = Some(callback);

        // IOCTL_SERIAL_SET_WAIT_MASK resets the async wait system, so we
        // restart it here.
        if let Err(e) = self.send_async_wait_on_mask() {
            self.hardware_flush_callback = None;
            return Err(e);
        }

        Ok(())
    }

    ///
    /// `start_wait_on_mask` begins/repeats the SERIAL_WAIT_ON_MASK loop, which
    /// is a cyclic async IOCTL, where a new IOCTL is queued after one
    /// completes.
    ///
    /// This function should only be called to either start the system, or
    /// repeat it after it stops (after IOCTL_SERIAL_SET_WAIT_MASK is called, or
    /// IOCTL_SERIAL_WAIT_ON_MASK returns).
    ///
    /// # Return value:
    ///
    /// * `Ok()` - Upon success.
    /// * `Err(SendIRPErr)` - Otherwise.
    ///
    fn send_async_wait_on_mask(&mut self) -> Result<(), SendIRPErr> {
        self.send_ioctl_async(
            IOCTL_SERIAL_WAIT_ON_MASK,
            &[],
            size_of::<u32>(),
            Some(wait_on_mask_callback),
        )
    }

    ///
    /// `handle_rxchar_event` is a helper called when a SERIAL_SET_WAIT_MASK
    /// completes, and the wait mask had RXCHAR.
    ///
    /// This function carries out most of the behavior described in the details
    /// section of `start_async_read_system`.
    ///
    fn handle_rxchar_event(&mut self) {
        if let Some(read_callback) = self.async_read_callback {
            let mut data = [0u8; size_of::<SERIAL_STATUS>()];
            if let Ok(len_status) =
                self.send_ioctl_blocking(IOCTL_SERIAL_GET_COMMSTATUS, &[], &mut data)
            {
                if !nt_success(len_status) {
                    return;
                }

                let serial_status = SERIAL_STATUS::from_bytes(data);
                let bytes_available = serial_status.AmountInInQueue as usize;

                if let Ok(_) = self.read_blocking(bytes_available) {
                    let to_delete = read_callback(self, &self.read_buffer);
                    let end_idx = to_delete.min(self.read_buffer.len());
                    self.read_buffer.drain(0..end_idx);
                }
            }
        }
    }

    ///
    /// `handle_txempty_event` is a helper called when a SERIAL_SET_WAIT_MASK
    /// completes, and the wait mask had TXEMPTY.
    ///
    /// This function simply calls the flush_callback.
    ///
    fn handle_txempty_event(&mut self) {
        if let Some(flush_callback) = self.hardware_flush_callback {
            flush_callback(self);
        }
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
/// * `port` - The serial port's that just received the data.
/// * `data` - The serial port's data buffer, showing the total data read.
///
/// # Return value:
///
/// * `usize` - The amount of data read and used, which can be removed from the
/// serial port's data buffer, shifting the buffer left by `amount` bytes. The
/// buffer's new 0th index will become data[amount].
///
type AsyncReadCallback = fn(port: &SerialPort, data: &[u8]) -> usize;

///
/// `TransmissionCompleteCallback` defines a completion routine called when the
/// physical serial port finishes flushing its buffer. This is currently used
/// for clocking, as it should run at the underlying USB clock rate.
///
/// # Arguments
///
/// * `port` - The serial port whose transmission buffer was just emptied.
///
type TXEmptyCallback = fn(port: &SerialPort);

///
/// `wait_on_mask_callback` is the completion routine for the WAIT_ON_MASK
/// serial IOCTL.
///
/// It is currently only used for the RXCHAR and TXEMPTY features.
///
/// This is called at <= IRQL_DISPATCH_LEVEL, as per `send_ioctl_async`, and so
/// is a wrapper around a worker item, which handles all port processing, due to
/// the constraints of KMutexes requiring IRQL_PASSIVE_LEVEL.
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
fn wait_on_mask_callback(identifier: SerialPortIdentifier, status: NTSTATUS, data: &[u8]) {
    if data.len() != 4 {
        return;
    }

    let wait_mask = u32::from_le_bytes(data.try_into().unwrap());
    if (wait_mask & (SERIAL_EV_RXCHAR | SERIAL_EV_TXEMPTY)) == 0 {
        return;
    }

    if !nt_success(status) {
        return;
    }

    let context_layout = Layout::new::<WaitOnMaskWorkItemContext>();
    let context_ptr =
        unsafe { WdkAllocator.alloc_zeroed(context_layout) as *mut WaitOnMaskWorkItemContext };
    if !context_ptr.is_null() {
        // SAFETY: This is safe because:
        //         `context_ptr` is a valid pointer.
        let context = unsafe { &mut *context_ptr };
        context.port_identifier = identifier;
        context.wait_mask = wait_mask;

        // SAFETY: This is safe because:
        //         1. `WorkItem` is a valid PWORK_QUEUE_ITEM.
        //         2. `context_ptr` is a WdkAllocator allocated WorkItemContext,
        //            as required by the invariant defined in
        //            `rxchar_workitem_routine`.
        unsafe {
            ExInitializeWorkItem(
                &mut context.work_item as PWORK_QUEUE_ITEM,
                Some(wait_on_mask_workitem_routine_unsafe),
                context_ptr as PVOID,
            );
        }

        // SAFETY: This is safe because:
        //         `WorkItem` is a valid PWORK_QUEUE_ITEM.
        unsafe {
            ExQueueWorkItem(&mut context.work_item as PWORK_QUEUE_ITEM, DelayedWorkQueue);
        }
    }
}

///
/// Context for a SERIAL_WAIT_MASK completion work item. This is used to store
/// all necessary information for carrying the callback for a SERIAL_WAIT_MASK
/// being completed, which requires IRQL_PASSIVE_LEVEL.
///
struct WaitOnMaskWorkItemContext {
    work_item: WORK_QUEUE_ITEM,

    wait_mask: u32,
    port_identifier: SerialPortIdentifier,
}

///
/// A wrapper around the `wait_on_mask_workitem_routine`, which ensures safety.
///
unsafe extern "C" fn wait_on_mask_workitem_routine_unsafe(context: PVOID) {
    wait_on_mask_workitem_routine(context)
}

///
/// `wait_on_mask_workitem_routine` is the callback function for a WAIT_ON_MASK
/// ioctl's WorkItem being ran. This function allows the necessary RXCHAR and
/// TXEMPTY callback behavior to be handled at IRQL_PASSIVE_LEVEL. Its behavior
/// matches the invariant described by the ExQueueWorkItem call in
/// `wait_on_mask_callback`.
///
/// Because this function is only called from a work item queue finishing, it
/// runs at IRQL_PASSIVE_LEVEL, ensuring the callback is run at
/// IRQL_PASSIVE_LEVEL.
///
/// This function should re-submit a WAIT_ON_MASK IOCTL to repeat the read
/// cycle.
///
/// # Arguments:
///
/// * `context_ptr` - A valid WaitOnMaskWorkItemContext pointer, as per the
///   ExQueueWorkItem call in `wait_on_mask_callback`.
///
fn wait_on_mask_workitem_routine(context_ptr: PVOID) {
    if context_ptr.is_null() {
        return;
    }

    // SAFETY: This is safe because:
    //         `context_ptr` is a valid WaitOnMaskWorkItemContext, as per the
    //         ExQueueWorkItem call in `wait_on_mask_callback`.
    let context = unsafe { &*(context_ptr as *mut WaitOnMaskWorkItemContext) };

    let identifier = context.port_identifier;
    let wait_mask = context.wait_mask;

    // SAFETY: This is safe because:
    //         `context_ptr` is a valid WdkAllocator allocated
    //         WaitOnMaskWorkItemContext, as per the ExQueueWorkItem call in
    //         `wait_on_mask_callback`.
    unsafe {
        WdkAllocator.dealloc(context_ptr as *mut u8, DEALLOC_LAYOUT);
    }

    let port_mutex = match GlobalSerialPorts::get_port(identifier) {
        Some(port_mutex) => port_mutex,
        None => return,
    };

    // SAFETY: This is safe because:
    //         `port_mutex` is a valid pointer, guaranteed by get_port.
    let mut port = unsafe { (*port_mutex).lock().unwrap() };
    let _ = port.send_async_wait_on_mask();

    if (wait_mask & SERIAL_EV_RXCHAR) != 0 {
        port.handle_rxchar_event();
    }

    if (wait_mask & SERIAL_EV_TXEMPTY) != 0 {
        port.handle_txempty_event();
    }
}

/// A completion routine, called upon an asynchronous IOCTL completing. This
/// passes the resulting status and output data. `port` is guaranteed to be non
/// null. Called at IRQL_DISPATCH_LEVEL.
type AsyncIOCTLCallback = fn(identifier: SerialPortIdentifier, status: NTSTATUS, data: &[u8]);

///
/// A structure used to hold the context of an on-going asynchronous IOCTL
/// request, useful for cleaning up memory once it finishes, and calling the
/// expected completion routine.
///
struct AsyncIOCTLContext {
    /// The identifier for the port the IOCTL was sent on.
    identifier: SerialPortIdentifier,
    /// A pointer to the WdkAllocator allocated IO_STATUS_BLOCK used by the
    /// IOCTL. Deallocated in completion routine so that lifetime is correct.
    io_status: PIO_STATUS_BLOCK,
    /// A pointer to the WdkAllocator allocated input data buffer used by the
    /// IOCTL. Deallocated in completion routine so that lifetime is correct.
    input_data: *mut u8,
    /// The completion routine, to be called when the async IOCTL is finished.
    completion_routine: Option<AsyncIOCTLCallback>,
}

///
/// A wrapper around the `async_ioctl_completion_routine`, which ensures safety.
///
unsafe extern "C" fn async_ioctl_completion_routine_unsafe(
    device_object: PDEVICE_OBJECT,
    irp: PIRP,
    context_ptr: PVOID,
) -> NTSTATUS {
    async_ioctl_completion_routine(device_object, irp, context_ptr)
}

///
/// `async_ioctl_completion_routine` is the completion routine for async serial
/// port IOCTLs.
///
/// This function works for a multitude of IOCTLs, as it simply calls a user
/// defined callback with the data received, port the ioctl was related to, and
/// the status of the ioctl.
///
/// Because this routine is called with IRQL = 0, I assume it is safe for me to
/// call the user callback, and trust they return within a reasonable amount of
/// time. This is in contrast to the WSK callbacks, which are at IRQL = 2, and
/// use workitem queues to defer user callback processing.
///
/// TODO: Should I trust this to run at IRQL = 0? Or should I assume it's only
/// <= 2, and use a WorkItem queue here.
///
/// # Arguments:
///
/// * `device_object` - An possibly null PDEVICE_OBJECT.
/// * `irp_ptr` - A pointer to the IRP being completed. This must not be null.
/// * `context` - A pointer to the call's context, stored in a WdKAllocator
///   allocated AsyncIOCTLContext. This must not be null.
///
/// # Return Value:
///
/// * `NTSTATUS` - The status of the call. This should always be STATUS_SUCCESS.
///
fn async_ioctl_completion_routine(
    device_object: PDEVICE_OBJECT,
    irp: PIRP,
    context_ptr: PVOID,
) -> NTSTATUS {
    if context_ptr.is_null() || irp.is_null() {
        // invariant violated
        return STATUS_SUCCESS;
    }

    // SAFETY: This is safe because:
    //         1. `context_ptr` is a non null AsyncIOCTLContext pointer, as
    //            guaranteed by the invariant held with `send_ioctl_async`.
    let context = unsafe { &mut *(context_ptr as *mut AsyncIOCTLContext) };
    // SAFETY: This is safe because:
    //         1. `irp` is a non null IRP pointer.
    let irp = unsafe { &*irp };

    // SAFETY: This is safe because:
    //         1. `io_status` and `input_data` are WdkAllocator allocated
    //            structures, as defined by the function invariant held with
    //            `send_ioctl_async`.
    unsafe {
        WdkAllocator.dealloc(context.io_status as *mut _, DEALLOC_LAYOUT);
        WdkAllocator.dealloc(context.input_data as *mut _, DEALLOC_LAYOUT);
    }

    if let Some(callback) = context.completion_routine {
        // SAFETY: This is safe because:
        //         `Status` is interpreted as an i32, and not as a dangerous
        //         type like a raw pointer.
        let status = unsafe { irp.IoStatus.__bindgen_anon_1.Status };
        let bytes_read = irp.IoStatus.Information as usize;
        // SAFETY: This is safe because:
        //         `device_object` is only derefrenced after verifying it to
        //         be a valid pointer.
        let raw_data = unsafe {
            if !device_object.is_null() && ((*device_object).Flags & DO_DIRECT_IO) == DO_DIRECT_IO {
                // I have never seen device_object be non null, nor direct
                // IO used in this context. However this todo should be
                // removed and replaced with proper mdl handling before
                // production release.

                todo!() // irp.MdlAddress as *mut u8
            } else {
                irp.AssociatedIrp.SystemBuffer as *mut u8
            }
        };

        let mut data = Vec::with_capacity(bytes_read);
        if !raw_data.is_null() {
            // SAFETY: This is safe because:
            //         `raw_data` is a valid pointer to a buffer with a
            //         length of `bytes_read` bytes.
            let slice = unsafe { slice::from_raw_parts(raw_data, bytes_read) };
            data.extend_from_slice(slice);
        }

        callback(context.identifier, status, &data);
    }

    // SAFETY: This is safe because:
    //         1. `context_ptr` is a WdkAllocator allocated structure, as
    //            defined by the function invariant held with
    //            `send_ioctl_async`.
    unsafe {
        WdkAllocator.dealloc(context_ptr as *mut _, DEALLOC_LAYOUT);
    }

    STATUS_SUCCESS
}
