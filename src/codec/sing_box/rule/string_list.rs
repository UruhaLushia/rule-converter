use serde::de::{Error, Visitor};
use serde::{Deserializer, Serializer};

pub fn serialize<S>(values: &[String], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    values.serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(StringListVisitor)
}

struct StringListVisitor;

impl<'de> Visitor<'de> for StringListVisitor {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a string or a list of strings")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(vec![value.to_string()])
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(vec![value])
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element::<String>()? {
            values.push(value);
        }
        Ok(values)
    }
}

use serde::Serialize;
