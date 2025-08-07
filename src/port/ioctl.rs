//!
//! The entries in this file were copied directly from:
//! windows_rs::Windows::Win32::Devices::SerialCommunication
//!
//! Aside from the `to_bytes` function implementations.
//!
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

pub const IOCTL_INTERNAL_SERENUM_REMOVE_SELF: u32 = 3604999u32;
pub const IOCTL_SERIAL_APPLY_DEFAULT_CONFIGURATION: u32 = 1769632u32;
pub const IOCTL_SERIAL_CLEAR_STATS: u32 = 1769616u32;
pub const IOCTL_SERIAL_CLR_DTR: u32 = 1769512u32;
pub const IOCTL_SERIAL_CLR_RTS: u32 = 1769524u32;
pub const IOCTL_SERIAL_CONFIG_SIZE: u32 = 1769600u32;
pub const IOCTL_SERIAL_GET_BAUD_RATE: u32 = 1769552u32;
pub const IOCTL_SERIAL_GET_CHARS: u32 = 1769560u32;
pub const IOCTL_SERIAL_GET_COMMCONFIG: u32 = 1769604u32;
pub const IOCTL_SERIAL_GET_COMMSTATUS: u32 = 1769580u32;
pub const IOCTL_SERIAL_GET_DTRRTS: u32 = 1769592u32;
pub const IOCTL_SERIAL_GET_HANDFLOW: u32 = 1769568u32;
pub const IOCTL_SERIAL_GET_LINE_CONTROL: u32 = 1769556u32;
pub const IOCTL_SERIAL_GET_MODEMSTATUS: u32 = 1769576u32;
pub const IOCTL_SERIAL_GET_MODEM_CONTROL: u32 = 1769620u32;
pub const IOCTL_SERIAL_GET_PROPERTIES: u32 = 1769588u32;
pub const IOCTL_SERIAL_GET_STATS: u32 = 1769612u32;
pub const IOCTL_SERIAL_GET_TIMEOUTS: u32 = 1769504u32;
pub const IOCTL_SERIAL_GET_WAIT_MASK: u32 = 1769536u32;
pub const IOCTL_SERIAL_IMMEDIATE_CHAR: u32 = 1769496u32;
pub const IOCTL_SERIAL_INTERNAL_BASIC_SETTINGS: u32 = 1769484u32;
pub const IOCTL_SERIAL_INTERNAL_CANCEL_WAIT_WAKE: u32 = 1769480u32;
pub const IOCTL_SERIAL_INTERNAL_DO_WAIT_WAKE: u32 = 1769476u32;
pub const IOCTL_SERIAL_INTERNAL_RESTORE_SETTINGS: u32 = 1769488u32;
pub const IOCTL_SERIAL_PURGE: u32 = 1769548u32;
pub const IOCTL_SERIAL_RESET_DEVICE: u32 = 1769516u32;
pub const IOCTL_SERIAL_SET_BAUD_RATE: u32 = 1769476u32;
pub const IOCTL_SERIAL_SET_BREAK_OFF: u32 = 1769492u32;
pub const IOCTL_SERIAL_SET_BREAK_ON: u32 = 1769488u32;
pub const IOCTL_SERIAL_SET_CHARS: u32 = 1769564u32;
pub const IOCTL_SERIAL_SET_COMMCONFIG: u32 = 1769608u32;
pub const IOCTL_SERIAL_SET_DTR: u32 = 1769508u32;
pub const IOCTL_SERIAL_SET_FIFO_CONTROL: u32 = 1769628u32;
pub const IOCTL_SERIAL_SET_HANDFLOW: u32 = 1769572u32;
pub const IOCTL_SERIAL_SET_INTERVAL_TIMER_RESOLUTION: u32 = 1769636u32;
pub const IOCTL_SERIAL_SET_LINE_CONTROL: u32 = 1769484u32;
pub const IOCTL_SERIAL_SET_MODEM_CONTROL: u32 = 1769624u32;
pub const IOCTL_SERIAL_SET_QUEUE_SIZE: u32 = 1769480u32;
pub const IOCTL_SERIAL_SET_RTS: u32 = 1769520u32;
pub const IOCTL_SERIAL_SET_TIMEOUTS: u32 = 1769500u32;
pub const IOCTL_SERIAL_SET_WAIT_MASK: u32 = 1769540u32;
pub const IOCTL_SERIAL_SET_XOFF: u32 = 1769528u32;
pub const IOCTL_SERIAL_SET_XON: u32 = 1769532u32;
pub const IOCTL_SERIAL_WAIT_ON_MASK: u32 = 1769544u32;
pub const IOCTL_SERIAL_XOFF_COUNTER: u32 = 1769584u32;

pub const SPACE_PARITY: u32 = 4u32;
pub const MARK_PARITY: u32 = 3u32;
pub const EVEN_PARITY: u32 = 2u32;
pub const ODD_PARITY: u32 = 1u32;
pub const NO_PARITY: u32 = 0u32;

pub const STOP_BITS_2: u32 = 2u32;
pub const STOP_BITS_1_5: u32 = 1u32;
pub const STOP_BIT_1: u32 = 0u32;

pub const SERIAL_EV_BREAK: u32 = 64u32;
pub const SERIAL_EV_CTS: u32 = 8u32;
pub const SERIAL_EV_DSR: u32 = 16u32;
pub const SERIAL_EV_ERR: u32 = 128u32;
pub const SERIAL_EV_EVENT1: u32 = 2048u32;
pub const SERIAL_EV_EVENT2: u32 = 4096u32;
pub const SERIAL_EV_PERR: u32 = 512u32;
pub const SERIAL_EV_RING: u32 = 256u32;
pub const SERIAL_EV_RLSD: u32 = 32u32;
pub const SERIAL_EV_RX80FULL: u32 = 1024u32;
pub const SERIAL_EV_RXCHAR: u32 = 1u32;
pub const SERIAL_EV_RXFLAG: u32 = 2u32;
pub const SERIAL_EV_TXEMPTY: u32 = 4u32;

pub const SERIAL_DTR_MASK: u32 = 0x03;
pub const SERIAL_DTR_CONTROL: u32 = 0x01;
pub const SERIAL_DTR_HANDSHAKE: u32 = 0x02;
pub const SERIAL_CTS_HANDSHAKE: u32 = 0x08;
pub const SERIAL_DSR_HANDSHAKE: u32 = 0x10;
pub const SERIAL_DCD_HANDSHAKE: u32 = 0x20;
pub const SERIAL_OUT_HANDSHAKEMASK: u32 = 0x38;
pub const SERIAL_DSR_SENSITIVITY: u32 = 0x40;
pub const SERIAL_ERROR_ABORT: u32 = 0x80000000;
pub const SERIAL_CONTROL_INVALID: u32 = 0x7fffff84;

pub const SERIAL_AUTO_TRANSMIT: u32 = 0x01;
pub const SERIAL_AUTO_RECEIVE: u32 = 0x02;
pub const SERIAL_ERROR_CHAR: u32 = 0x04;
pub const SERIAL_NULL_STRIPPING: u32 = 0x08;
pub const SERIAL_BREAK_CHAR: u32 = 0x10;
pub const SERIAL_RTS_MASK: u32 = 0xc0;
pub const SERIAL_RTS_CONTROL: u32 = 0x40;
pub const SERIAL_RTS_HANDSHAKE: u32 = 0x80;
pub const SERIAL_TRANSMIT_TOGGLE: u32 = 0xc0;
pub const SERIAL_XOFF_CONTINUE: u32 = 0x80000000;
pub const SERIAL_FLOW_INVALID: u32 = 0x7fffff20;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SERIAL_LINE_CONTROL {
    pub StopBits: u8,
    pub Parity: u8,
    pub WordLength: u8,
}

impl SERIAL_LINE_CONTROL {
    pub fn to_bytes(&self) -> [u8; 3] {
        [self.StopBits, self.Parity, self.WordLength]
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SERIAL_CHARS {
    pub EofChar: u8,
    pub ErrorChar: u8,
    pub BreakChar: u8,
    pub EventChar: u8,
    pub XonChar: u8,
    pub XoffChar: u8,
}

impl SERIAL_CHARS {
    pub fn to_bytes(&self) -> [u8; 6] {
        [
            self.EofChar,
            self.ErrorChar,
            self.BreakChar,
            self.EventChar,
            self.XonChar,
            self.XoffChar,
        ]
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SERIAL_HANDFLOW {
    pub ControlHandShake: u32,
    pub FlowReplace: u32,
    pub XonLimit: i32,
    pub XoffLimit: i32,
}

impl SERIAL_HANDFLOW {
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.ControlHandShake.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.FlowReplace.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.XonLimit.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.XoffLimit.to_le_bytes());

        bytes
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SERIAL_TIMEOUTS {
    pub ReadIntervalTimeout: u32,
    pub ReadTotalTimeoutMultiplier: u32,
    pub ReadTotalTimeoutConstant: u32,
    pub WriteTotalTimeoutMultiplier: u32,
    pub WriteTotalTimeoutConstant: u32,
}

impl SERIAL_TIMEOUTS {
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(&self.ReadIntervalTimeout.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.ReadTotalTimeoutMultiplier.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.ReadTotalTimeoutConstant.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.WriteTotalTimeoutMultiplier.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.WriteTotalTimeoutConstant.to_le_bytes());

        bytes
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SERIAL_STATUS {
    pub Errors: u32,
    pub HoldReasons: u32,
    pub AmountInInQueue: u32,
    pub AmountInOutQueue: u32,
    pub EofReceived: bool,
    pub WaitForImmediate: bool,
}

impl SERIAL_STATUS {
    pub fn from_bytes(data: [u8; size_of::<Self>()]) -> Self {
        Self {
            Errors: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            HoldReasons: u32::from_le_bytes(data[4..8].try_into().unwrap()),
            AmountInInQueue: u32::from_le_bytes(data[8..12].try_into().unwrap()),
            AmountInOutQueue: u32::from_le_bytes(data[12..16].try_into().unwrap()),
            EofReceived: data[16] != 0,
            WaitForImmediate: data[17] != 0,
        }
    }
}
