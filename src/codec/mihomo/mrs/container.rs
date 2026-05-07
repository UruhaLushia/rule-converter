use std::io::{Cursor, Read, Write};

use anyhow::{Context, Result, bail};

use super::{Behavior, DomainSet, IpCidrSet, RuleSetOutput, write_i64};

const MRS_MAGIC: &[u8; 4] = b"MRS\x01";

impl RuleSetOutput {
    pub fn write_mrs<W: Write>(&self, writer: W) -> Result<()> {
        let mut encoder =
            zstd::stream::Encoder::new(writer, 0).context("failed to create zstd encoder")?;
        encoder.write_all(MRS_MAGIC)?;
        encoder.write_all(&[self.behavior().byte()])?;
        write_i64(&mut encoder, self.count() as i64)?;
        write_i64(&mut encoder, 0)?;
        match self {
            Self::Domain(set) => set.write_bin(&mut encoder)?,
            Self::Ipcidr(set) => set.write_bin(&mut encoder)?,
        }
        encoder.finish().context("failed to finish zstd stream")?;
        Ok(())
    }
}

pub fn read_mrs(raw: &[u8]) -> Result<RuleSetOutput> {
    let mut decoder =
        zstd::stream::Decoder::new(Cursor::new(raw)).context("failed to create zstd decoder")?;
    let mut data = Vec::new();
    decoder
        .read_to_end(&mut data)
        .context("failed to decompress MRS")?;
    let mut reader = Cursor::new(data);

    let mut magic = [0; 4];
    reader.read_exact(&mut magic)?;
    if &magic != MRS_MAGIC {
        bail!("invalid MRS magic bytes");
    }

    let mut behavior = [0; 1];
    reader.read_exact(&mut behavior)?;
    let behavior = Behavior::from_byte(behavior[0]).context("unsupported MRS behavior")?;
    let count = read_i64_from(&mut reader)?;
    if count < 0 {
        bail!("invalid MRS rule count");
    }

    let extra_len = read_i64_from(&mut reader)?;
    if extra_len < 0 {
        bail!("invalid MRS extra length");
    }
    if extra_len > 0 {
        let mut extra = vec![0; extra_len as usize];
        reader.read_exact(&mut extra)?;
    }

    match behavior {
        Behavior::Domain => Ok(RuleSetOutput::Domain(DomainSet::read_bin(
            &mut reader,
            count as usize,
        )?)),
        Behavior::Ipcidr => Ok(RuleSetOutput::Ipcidr(IpCidrSet::read_bin(
            &mut reader,
            count as usize,
        )?)),
    }
}

fn read_i64_from<R: Read>(reader: &mut R) -> Result<i64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(i64::from_be_bytes(bytes))
}
