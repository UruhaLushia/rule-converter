use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};

use crate::codec::dat::proto::Cidr;

pub(super) fn addr_from_cidr(cidr: &Cidr) -> Result<IpAddr> {
    addr_from_raw(&cidr.ip)
}

pub(super) fn addr_from_raw(raw: &[u8]) -> Result<IpAddr> {
    match raw.len() {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))),
        16 => {
            let bytes: [u8; 16] = raw.try_into().expect("length checked above");
            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        len => bail!("invalid geoip dat CIDR address length: {len}"),
    }
}

pub(super) fn cidr_from_prefix(addr: IpAddr, prefix: u8) -> Cidr {
    match addr {
        IpAddr::V4(addr) => Cidr {
            ip: addr.octets().to_vec(),
            prefix: prefix as u32,
        },
        IpAddr::V6(addr) => Cidr {
            ip: addr.octets().to_vec(),
            prefix: prefix as u32,
        },
    }
}
