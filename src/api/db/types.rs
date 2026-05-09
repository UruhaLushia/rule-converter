use crate::codec::db::MmdbFormat;
use crate::codec::mihomo::mrs::Behavior;
use crate::output::OutputFormat;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbMemoryOutput {
    pub name: String,
    pub behavior: Behavior,
    pub format: OutputFormat,
    pub count: usize,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbBytesOutput {
    pub format: MmdbFormat,
    pub count: usize,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbStringOutput {
    pub name: String,
    pub behavior: Behavior,
    pub format: OutputFormat,
    pub count: usize,
    pub text: String,
}
