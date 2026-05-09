use std::io::{self, Read};

pub(super) fn read_u64_vec<R: Read>(reader: &mut R) -> io::Result<Vec<u64>> {
    let len = read_i64(reader)?;
    if len < 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid vector length",
        ));
    }
    let mut values = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let mut bytes = [0; 8];
        reader.read_exact(&mut bytes)?;
        values.push(u64::from_be_bytes(bytes));
    }
    Ok(values)
}

pub(super) fn read_i64<R: Read>(reader: &mut R) -> io::Result<i64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(i64::from_be_bytes(bytes))
}
