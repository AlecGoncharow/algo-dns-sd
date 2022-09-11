#![allow(dead_code)]
use std::net::{Ipv4Addr, Ipv6Addr};

pub mod header;
pub mod message;
mod parser;

/// https://datatracker.ietf.org/doc/html/rfc6762#section-3
pub const MDNS_LINK_LOCAL_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_LINK_LOCAL_IPV6: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xFB);
/// https://datatracker.ietf.org/doc/html/rfc6762#appendix-A
pub const MDNS_LINK_LOCAL_PORT: u16 = 5353;
