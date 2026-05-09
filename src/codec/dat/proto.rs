#[cfg(not(target_arch = "wasm32"))]
use std::io::Read;
use std::io::{self, Write};

use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub struct GeoIp {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    pub reverse_match: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    pub ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoSite {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<Domain>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Domain {
    #[prost(enumeration = "DomainType", tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub value: String,
    #[prost(message, repeated, tag = "3")]
    pub attribute: Vec<DomainAttribute>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DomainAttribute {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(oneof = "domain_attribute::TypedValue", tags = "2, 3")]
    pub typed_value: Option<domain_attribute::TypedValue>,
}

pub mod domain_attribute {
    use prost::Oneof;

    #[derive(Clone, PartialEq, Oneof)]
    pub enum TypedValue {
        #[prost(bool, tag = "2")]
        BoolValue(bool),
        #[prost(int64, tag = "3")]
        IntValue(i64),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum DomainType {
    Plain = 0,
    Regex = 1,
    RootDomain = 2,
    Full = 3,
}

pub(super) fn for_each_raw_message_field(
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

pub(super) fn for_each_message_field<M>(
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

pub(super) fn write_message_field(
    output: &mut Vec<u8>,
    field_number: u32,
    message: &impl Message,
) -> anyhow::Result<()> {
    write_raw_message_field(output, field_number, message.encode_to_vec().as_slice())
}

pub(super) fn write_raw_message_field(
    output: &mut Vec<u8>,
    field_number: u32,
    raw: &[u8],
) -> anyhow::Result<()> {
    write_raw_message_field_to_writer(output, field_number, raw)
}

pub(super) fn write_raw_message_field_to_writer<W: Write>(
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
pub(super) fn for_each_raw_message_field_from_reader<R: Read>(
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

fn skip_field(input: &[u8], pos: &mut usize, wire_type: u64, context: &str) -> anyhow::Result<()> {
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

fn skip_bytes(input: &[u8], pos: &mut usize, len: usize, context: &str) -> anyhow::Result<()> {
    let end = pos
        .checked_add(len)
        .filter(|end| *end <= input.len())
        .ok_or_else(|| anyhow::anyhow!("invalid {context} protobuf field length"))?;
    *pos = end;
    Ok(())
}

pub(super) fn scan_field(
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

pub(super) fn decode_varint(input: &[u8]) -> anyhow::Result<u64> {
    let mut pos = 0usize;
    read_varint(input, &mut pos)
}

#[cfg(not(target_arch = "wasm32"))]
fn skip_field_from_reader<R: Read>(
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

fn read_varint(input: &[u8], pos: &mut usize) -> anyhow::Result<u64> {
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
fn read_required_varint_from_reader<R: Read>(reader: &mut R) -> anyhow::Result<u64> {
    read_varint_from_reader(reader)?.ok_or_else(|| anyhow::anyhow!("truncated protobuf varint"))
}

#[cfg(not(target_arch = "wasm32"))]
fn read_varint_from_reader<R: Read>(reader: &mut R) -> anyhow::Result<Option<u64>> {
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

fn write_varint_to_writer<W: Write>(writer: &mut W, mut value: u64) -> io::Result<()> {
    while value >= 0x80 {
        writer.write_all(&[((value as u8) | 0x80)])?;
        value >>= 7;
    }
    writer.write_all(&[value as u8])
}
