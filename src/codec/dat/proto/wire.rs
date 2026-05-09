#[cfg(not(target_arch = "wasm32"))]
use std::io::Read;
use std::io::{self, Write};

pub(super) fn skip_field(
    input: &[u8],
    pos: &mut usize,
    wire_type: u64,
    context: &str,
) -> anyhow::Result<()> {
    match wire_type {
        0 => {
            read_varint(input, pos)?;
        }
        1 => skip_bytes(input, pos, 8, context)?,
        2 => {
            let len = read_varint(input, pos)? as usize;
            skip_bytes(input, pos, len, context)?;
        }
        5 => skip_bytes(input, pos, 4, context)?,
        other => anyhow::bail!("unsupported {context} protobuf wire type: {other}"),
    }
    Ok(())
}

pub(super) fn skip_bytes(
    input: &[u8],
    pos: &mut usize,
    len: usize,
    context: &str,
) -> anyhow::Result<()> {
    let end = pos
        .checked_add(len)
        .filter(|end| *end <= input.len())
        .ok_or_else(|| anyhow::anyhow!("invalid {context} protobuf field length"))?;
    *pos = end;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn skip_field_from_reader<R: Read>(
    reader: &mut R,
    wire_type: u64,
    context: &str,
) -> anyhow::Result<()> {
    match wire_type {
        0 => {
            read_required_varint_from_reader(reader)?;
        }
        1 => discard_bytes(reader, 8)?,
        2 => {
            let len = read_required_varint_from_reader(reader)?;
            discard_bytes(reader, len)?;
        }
        5 => discard_bytes(reader, 4)?,
        other => anyhow::bail!("unsupported {context} protobuf wire type: {other}"),
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn discard_bytes<R: Read>(reader: &mut R, mut len: u64) -> anyhow::Result<()> {
    let mut buffer = [0u8; 8192];
    while len > 0 {
        let read_len = buffer.len().min(len as usize);
        reader.read_exact(&mut buffer[..read_len])?;
        len -= read_len as u64;
    }
    Ok(())
}

pub(super) fn read_varint(input: &[u8], pos: &mut usize) -> anyhow::Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *input
            .get(*pos)
            .ok_or_else(|| anyhow::anyhow!("truncated protobuf varint"))?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    anyhow::bail!("protobuf varint is too large")
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn read_required_varint_from_reader<R: Read>(reader: &mut R) -> anyhow::Result<u64> {
    read_varint_from_reader(reader)?.ok_or_else(|| anyhow::anyhow!("truncated protobuf varint"))
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn read_varint_from_reader<R: Read>(reader: &mut R) -> anyhow::Result<Option<u64>> {
    let mut value = 0u64;
    let mut byte = [0u8; 1];
    for shift in (0..64).step_by(7) {
        match reader.read_exact(&mut byte) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof && shift == 0 => {
                return Ok(None);
            }
            Err(err) => return Err(err.into()),
        }
        value |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(Some(value));
        }
    }
    anyhow::bail!("protobuf varint is too large")
}

pub(super) fn write_varint_to_writer<W: Write>(writer: &mut W, mut value: u64) -> io::Result<()> {
    while value >= 0x80 {
        writer.write_all(&[((value as u8) | 0x80)])?;
        value >>= 7;
    }
    writer.write_all(&[value as u8])
}
