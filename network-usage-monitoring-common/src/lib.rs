#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct NetStats {
    pub ingress: Traffic,
    pub egress: Traffic,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Traffic {
    pub packets: u64,
    pub bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl Pod for NetStats {}
