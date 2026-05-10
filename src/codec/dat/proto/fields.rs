#[cfg(not(target_arch = "wasm32"))]
use std::io::Read;
use std::io::Write;

use prost::Message;

#[cfg(not(target_arch = "wasm32"))]
use super::wire::{
    read_required_varint_from_reader, read_varint_from_reader, skip_field_from_reader,
};
use super::wire::{read_varint, skip_bytes, skip_field, write_varint_to_writer};

pub(in crate::codec::dat) fn for_each_raw_message_field(
    input: &[u8],
    field_number: u32,
    context: &'static str,
    mut f: impl FnMut(&[u8]) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut pos = 0usize;
    while pos < input.len() {
        let key = read_varint(input, &mut pos)?;
        let tag = key >> 3;
        let wire_type = key & 0x07;
        if tag == u64::from(field_number) && wire_type == 2 {
            let len = read_varint(input, &mut pos)? as usize;
            let end = pos
                .checked_add(len)
                .filter(|end| *end <= input.len())
                .ok_or_else(|| anyhow::anyhow!("invalid {context} entry length"))?;
            f(&input[pos..end])?;
            pos = end;
            continue;
        }
        skip_field(input, &mut pos, wire_type, context)?;
    }
    Ok(())
}

pub(in crate::codec::dat) fn first_raw_message_field<'a>(
    input: &'a [u8],
    field_number: u32,
    context: &'static str,
) -> anyhow::Result<Option<&'a [u8]>> {
    let mut pos = 0usize;
    while pos < input.len() {
        let key = read_varint(input, &mut pos)?;
        let tag = key >> 3;
        let wire_type = key & 0x07;
        if tag == u64::from(field_number) && wire_type == 2 {
            let len = read_varint(input, &mut pos)? as usize;
            let end = pos
                .checked_add(len)
                .filter(|end| *end <= input.len())
                .ok_or_else(|| anyhow::anyhow!("invalid {context} entry length"))?;
            return Ok(Some(&input[pos..end]));
        }
        skip_field(input, &mut pos, wire_type, context)?;
    }
    Ok(None)
}

pub(in crate::codec::dat) fn for_each_message_field<M>(
    input: &[u8],
    field_number: u32,
    context: &'static str,
    mut f: impl FnMut(M, &[u8]) -> anyhow::Result<()>,
) -> anyhow::Result<()>
where
    M: Message + Default,
{
    let mut pos = 0usize;
    while pos < input.len() {
        let key = read_varint(input, &mut pos)?;
        let tag = key >> 3;
        let wire_type = key & 0x07;
        if tag == u64::from(field_number) && wire_type == 2 {
            let len = read_varint(input, &mut pos)? as usize;
            let end = pos
                .checked_add(len)
                .filter(|end| *end <= input.len())
                .ok_or_else(|| anyhow::anyhow!("invalid {context} entry length"))?;
            let raw = &input[pos..end];
            let message = M::decode(raw)
                .map_err(|err| anyhow::anyhow!("failed to parse {context} entry: {err}"))?;
            f(message, raw)?;
            pos = end;
            continue;
        }
        skip_field(input, &mut pos, wire_type, context)?;
    }
    Ok(())
}

pub(in crate::codec::dat) fn write_message_field(
    output: &mut Vec<u8>,
    field_number: u32,
    message: &impl Message,
) -> anyhow::Result<()> {
    write_raw_message_field(output, field_number, message.encode_to_vec().as_slice())
}

pub(in crate::codec::dat) fn write_raw_message_field(
    output: &mut Vec<u8>,
    field_number: u32,
    raw: &[u8],
) -> anyhow::Result<()> {
    write_raw_message_field_to_writer(output, field_number, raw)
}

pub(in crate::codec::dat) fn write_raw_message_field_to_writer<W: Write>(
    mut output: W,
    field_number: u32,
    raw: &[u8],
) -> anyhow::Result<()> {
    write_varint_to_writer(&mut output, (u64::from(field_number) << 3) | 2)?;
    write_varint_to_writer(
        &mut output,
        u64::try_from(raw.len()).map_err(|_| anyhow::anyhow!("protobuf message is too large"))?,
    )?;
    output.write_all(raw)?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub(in crate::codec::dat) fn for_each_raw_message_field_from_reader<R: Read>(
    mut reader: R,
    field_number: u32,
    context: &'static str,
    mut f: impl FnMut(&[u8]) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    while let Some(key) = read_varint_from_reader(&mut reader)? {
        let tag = key >> 3;
        let wire_type = key & 0x07;
        if tag == u64::from(field_number) && wire_type == 2 {
            let len = read_required_varint_from_reader(&mut reader)?;
            let len = usize::try_from(len)
                .map_err(|_| anyhow::anyhow!("{context} entry is too large"))?;
            let mut raw = vec![0; len];
            reader.read_exact(&mut raw)?;
            f(&raw)?;
            continue;
        }
        skip_field_from_reader(&mut reader, wire_type, context)?;
    }
    Ok(())
}

pub(in crate::codec::dat) fn scan_field(
    input: &[u8],
    pos: &mut usize,
    context: &str,
) -> anyhow::Result<(u64, u64, usize, usize)> {
    let key = read_varint(input, pos)?;
    let tag = key >> 3;
    let wire_type = key & 0x07;
    let value_start = *pos;
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
    Ok((tag, wire_type, value_start, *pos))
}

pub(in crate::codec::dat) fn decode_varint(input: &[u8]) -> anyhow::Result<u64> {
    let mut pos = 0usize;
    read_varint(input, &mut pos)
}
