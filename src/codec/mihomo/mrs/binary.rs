use std::io::{self, Write};

pub(crate) fn write_u64_vec<W: Write>(writer: &mut W, values: &[u64]) -> io::Result<()> {
    write_i64(writer, values.len() as i64)?;
    for value in values {
        writer.write_all(&value.to_be_bytes())?;
    }
    Ok(())
}

pub(crate) fn write_i64<W: Write>(writer: &mut W, value: i64) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}
