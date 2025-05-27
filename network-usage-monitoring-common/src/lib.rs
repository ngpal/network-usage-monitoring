#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct IpStats {
    pub packets: u64,
    pub bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl Pod for IpStats {}
