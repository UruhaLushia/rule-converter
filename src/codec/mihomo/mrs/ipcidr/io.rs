use std::io::{self, Read};

use super::range::{IpFamily, ParsedAddr};

pub(super) fn read_i64<R: Read>(reader: &mut R) -> io::Result<i64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(i64::from_be_bytes(bytes))
}

pub(super) fn read_addr<R: Read>(reader: &mut R) -> io::Result<ParsedAddr> {
    let mut bytes = [0; 16];
    reader.read_exact(&mut bytes)?;
    let is_v4 = bytes[..10].iter().all(|byte| *byte == 0) && bytes[10] == 0xff && bytes[11] == 0xff;
    if is_v4 {
        let value = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as u128;
        Ok(ParsedAddr {
            family: IpFamily::V4,
            value,
        })
    } else {
        Ok(ParsedAddr {
            family: IpFamily::V6,
            value: u128::from_be_bytes(bytes),
        })
    }
}
