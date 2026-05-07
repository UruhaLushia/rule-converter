use std::io::{Read, Write};

use anyhow::{Result, bail};

pub(super) fn read_byte<R: Read>(reader: &mut R) -> Result<u8> {
    let mut byte = [0; 1];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

pub(super) fn write_uvarint<W: Write>(writer: &mut W, mut value: u64) -> Result<()> {
    while value >= 0x80 {
        writer.write_all(&[((value as u8) | 0x80)])?;
        value >>= 7;
    }
    writer.write_all(&[value as u8])?;
    Ok(())
}

pub(super) fn read_uvarint<R: Read>(reader: &mut R) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = read_byte(reader)?;
        if byte < 0x80 {
            if shift == 63 && byte > 1 {
                bail!("sing-box SRS uvarint overflow");
            }
            return Ok(value | ((byte as u64) << shift));
        }
        value |= ((byte & 0x7f) as u64) << shift;
    }
    bail!("sing-box SRS uvarint overflow")
}

pub(super) fn write_u64_vec<W: Write>(writer: &mut W, values: &[u64]) -> Result<()> {
    write_uvarint(writer, values.len() as u64)?;
    for value in values {
        writer.write_all(&value.to_be_bytes())?;
    }
    Ok(())
}

pub(super) fn read_u64_vec<R: Read>(reader: &mut R) -> Result<Vec<u64>> {
    let len = read_uvarint(reader)?;
    let mut values = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let mut bytes = [0; 8];
        reader.read_exact(&mut bytes)?;
        values.push(u64::from_be_bytes(bytes));
    }
    Ok(values)
}
