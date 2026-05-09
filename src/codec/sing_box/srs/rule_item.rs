use std::io::{Read, Write};

use anyhow::{Context, Result, bail};

use crate::codec::sing_box::rule::RuleList;
use crate::codec::sing_box::{Rule, RuleStore};

use super::binary::{read_byte, read_uvarint, write_uvarint};
use super::constants::*;
use super::domain::{
    read_domain_matcher, write_domain_matcher, write_domain_matcher_list,
    write_owned_domain_matcher_list,
};
use super::ip_set::{read_ip_set, write_ip_set_item, write_ip_set_item_list};

pub(super) fn write_default_rule<W: Write>(writer: &mut W, rule: &Rule) -> Result<()> {
    writer.write_all(&[RULE_DEFAULT])?;
    if !rule.network.is_empty() {
        write_string_item(writer, ITEM_NETWORK, &rule.network)?;
    }
    if !rule.domain.is_empty() || !rule.domain_suffix.is_empty() {
        writer.write_all(&[ITEM_DOMAIN])?;
        write_domain_matcher(writer, &rule.domain, &rule.domain_suffix)?;
    }
    if !rule.domain_keyword.is_empty() {
        write_string_item(writer, ITEM_DOMAIN_KEYWORD, &rule.domain_keyword)?;
    }
    if !rule.domain_regex.is_empty() {
        write_string_item(writer, ITEM_DOMAIN_REGEX, &rule.domain_regex)?;
    }
    if !rule.source_ip_cidr.is_empty() {
        write_ip_set_item(writer, ITEM_SOURCE_IP_CIDR, &rule.source_ip_cidr)?;
    }
    if !rule.ip_cidr.is_empty() {
        write_ip_set_item(writer, ITEM_IP_CIDR, &rule.ip_cidr)?;
    }
    if !rule.source_port_range.is_empty() {
        write_string_item(writer, ITEM_SOURCE_PORT_RANGE, &rule.source_port_range)?;
    }
    if !rule.port_range.is_empty() {
        write_string_item(writer, ITEM_PORT_RANGE, &rule.port_range)?;
    }
    if !rule.process_name.is_empty() {
        write_string_item(writer, ITEM_PROCESS_NAME, &rule.process_name)?;
    }
    if !rule.process_path.is_empty() {
        write_string_item(writer, ITEM_PROCESS_PATH, &rule.process_path)?;
    }
    if !rule.process_path_regex.is_empty() {
        write_string_item(writer, ITEM_PROCESS_PATH_REGEX, &rule.process_path_regex)?;
    }
    if !rule.package_name.is_empty() {
        write_string_item(writer, ITEM_PACKAGE_NAME, &rule.package_name)?;
    }
    if !rule.package_name_regex.is_empty() {
        write_string_item(writer, ITEM_PACKAGE_NAME_REGEX, &rule.package_name_regex)?;
    }
    writer.write_all(&[ITEM_FINAL, u8::from(rule.invert)])?;
    Ok(())
}

pub(super) fn read_default_rule<R: Read>(reader: &mut R) -> Result<Rule> {
    let mut rule = Rule::default();
    loop {
        match read_byte(reader)? {
            ITEM_QUERY_TYPE => {
                let _ = read_u16_list(reader)?;
            }
            ITEM_NETWORK => rule.network = read_string_list(reader)?,
            ITEM_DOMAIN => {
                let matcher = read_domain_matcher(reader)?;
                rule.domain = matcher.domain;
                rule.domain_suffix = matcher.domain_suffix;
            }
            ITEM_DOMAIN_KEYWORD => rule.domain_keyword = read_string_list(reader)?,
            ITEM_DOMAIN_REGEX => rule.domain_regex = read_string_list(reader)?,
            ITEM_SOURCE_IP_CIDR => rule.source_ip_cidr = read_ip_set(reader)?,
            ITEM_IP_CIDR => rule.ip_cidr = read_ip_set(reader)?,
            ITEM_SOURCE_PORT => rule.source_port_range = read_u16_list_as_strings(reader)?,
            ITEM_SOURCE_PORT_RANGE => rule.source_port_range = read_string_list(reader)?,
            ITEM_PORT => rule.port_range = read_u16_list_as_strings(reader)?,
            ITEM_PORT_RANGE => rule.port_range = read_string_list(reader)?,
            ITEM_PROCESS_NAME => rule.process_name = read_string_list(reader)?,
            ITEM_PROCESS_PATH => rule.process_path = read_string_list(reader)?,
            ITEM_PACKAGE_NAME => rule.package_name = read_string_list(reader)?,
            ITEM_WIFI_SSID | ITEM_WIFI_BSSID => {
                let _ = read_string_list(reader)?;
            }
            ITEM_ADGUARD_DOMAIN => bail!("sing-box SRS AdGuard domain rules are not supported yet"),
            ITEM_PROCESS_PATH_REGEX => rule.process_path_regex = read_string_list(reader)?,
            ITEM_NETWORK_TYPE => {
                let _ = read_u8_list(reader)?;
            }
            ITEM_NETWORK_IS_EXPENSIVE | ITEM_NETWORK_IS_CONSTRAINED => {}
            ITEM_NETWORK_INTERFACE_ADDRESS | ITEM_DEFAULT_INTERFACE_ADDRESS => {
                bail!("sing-box SRS interface-address rules are not supported yet")
            }
            ITEM_PACKAGE_NAME_REGEX => rule.package_name_regex = read_string_list(reader)?,
            ITEM_FINAL => {
                rule.invert = read_byte(reader)? != 0;
                return Ok(rule);
            }
            other => bail!("unknown sing-box SRS rule item: {other}"),
        }
    }
}

pub(super) fn write_store_rules<W: Write>(writer: &mut W, store: &RuleStore) -> Result<()> {
    if !store.domain.is_empty() || !store.domain_suffix.is_empty() {
        writer.write_all(&[RULE_DEFAULT, ITEM_DOMAIN])?;
        write_domain_matcher_list(writer, &store.domain, &store.domain_suffix)?;
        writer.write_all(&[ITEM_FINAL, 0])?;
    }
    write_string_store_rule(writer, ITEM_DOMAIN_KEYWORD, &store.domain_keyword)?;
    write_string_store_rule(writer, ITEM_DOMAIN_REGEX, &store.domain_regex)?;
    write_ip_store_rule(writer, ITEM_SOURCE_IP_CIDR, &store.source_ip_cidr)?;
    write_ip_store_rule(writer, ITEM_IP_CIDR, &store.ip_cidr)?;
    write_string_store_rule(writer, ITEM_NETWORK, &store.network)?;
    write_string_store_rule(writer, ITEM_SOURCE_PORT_RANGE, &store.source_port_range)?;
    write_string_store_rule(writer, ITEM_PORT_RANGE, &store.port_range)?;
    write_string_store_rule(writer, ITEM_PROCESS_NAME, &store.process_name)?;
    write_string_store_rule(writer, ITEM_PROCESS_PATH, &store.process_path)?;
    write_string_store_rule(writer, ITEM_PROCESS_PATH_REGEX, &store.process_path_regex)?;
    Ok(())
}

pub(super) fn write_owned_store_rules<W: Write>(writer: &mut W, store: RuleStore) -> Result<()> {
    let RuleStore {
        domain,
        domain_suffix,
        domain_keyword,
        domain_regex,
        source_ip_cidr,
        ip_cidr,
        network,
        source_port_range,
        port_range,
        process_name,
        process_path,
        process_path_regex,
    } = store;

    if !domain.is_empty() || !domain_suffix.is_empty() {
        writer.write_all(&[RULE_DEFAULT, ITEM_DOMAIN])?;
        write_owned_domain_matcher_list(writer, domain, domain_suffix)?;
        writer.write_all(&[ITEM_FINAL, 0])?;
    }
    write_string_owned_store_rule(writer, ITEM_DOMAIN_KEYWORD, domain_keyword)?;
    write_string_owned_store_rule(writer, ITEM_DOMAIN_REGEX, domain_regex)?;
    write_ip_owned_store_rule(writer, ITEM_SOURCE_IP_CIDR, source_ip_cidr)?;
    write_ip_owned_store_rule(writer, ITEM_IP_CIDR, ip_cidr)?;
    write_string_owned_store_rule(writer, ITEM_NETWORK, network)?;
    write_string_owned_store_rule(writer, ITEM_SOURCE_PORT_RANGE, source_port_range)?;
    write_string_owned_store_rule(writer, ITEM_PORT_RANGE, port_range)?;
    write_string_owned_store_rule(writer, ITEM_PROCESS_NAME, process_name)?;
    write_string_owned_store_rule(writer, ITEM_PROCESS_PATH, process_path)?;
    write_string_owned_store_rule(writer, ITEM_PROCESS_PATH_REGEX, process_path_regex)?;
    Ok(())
}

fn write_string_store_rule<W: Write>(writer: &mut W, item: u8, values: &RuleList) -> Result<()> {
    if values.is_empty() {
        return Ok(());
    }
    writer.write_all(&[RULE_DEFAULT])?;
    write_string_item_list(writer, item, values)?;
    writer.write_all(&[ITEM_FINAL, 0])?;
    Ok(())
}

fn write_ip_store_rule<W: Write>(writer: &mut W, item: u8, cidrs: &RuleList) -> Result<()> {
    if cidrs.is_empty() {
        return Ok(());
    }
    writer.write_all(&[RULE_DEFAULT])?;
    write_ip_set_item_list(writer, item, cidrs)?;
    writer.write_all(&[ITEM_FINAL, 0])?;
    Ok(())
}

fn write_string_item<W, S>(writer: &mut W, item: u8, values: &[S]) -> Result<()>
where
    W: Write,
    S: AsRef<str>,
{
    writer.write_all(&[item])?;
    write_uvarint(writer, values.len() as u64)?;
    for value in values {
        let value = value.as_ref();
        write_uvarint(writer, value.len() as u64)?;
        writer.write_all(value.as_bytes())?;
    }
    Ok(())
}

fn write_string_item_list<W: Write>(writer: &mut W, item: u8, values: &RuleList) -> Result<()> {
    writer.write_all(&[item])?;
    write_uvarint(writer, values.len() as u64)?;
    for value in values.iter() {
        write_uvarint(writer, value.len() as u64)?;
        writer.write_all(value.as_bytes())?;
    }
    Ok(())
}

fn read_string_list<R: Read>(reader: &mut R) -> Result<Vec<String>> {
    let len = read_uvarint(reader)?;
    let mut values = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let str_len = read_uvarint(reader)?;
        let mut bytes = vec![0; str_len as usize];
        reader.read_exact(&mut bytes)?;
        values.push(String::from_utf8(bytes).context("invalid UTF-8 string in sing-box SRS")?);
    }
    Ok(values)
}

fn read_u8_list<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let len = read_uvarint(reader)?;
    let mut values = vec![0; len as usize];
    reader.read_exact(&mut values)?;
    Ok(values)
}

fn read_u16_list<R: Read>(reader: &mut R) -> Result<Vec<u16>> {
    let len = read_uvarint(reader)?;
    let mut values = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let mut bytes = [0; 2];
        reader.read_exact(&mut bytes)?;
        values.push(u16::from_be_bytes(bytes));
    }
    Ok(values)
}

fn read_u16_list_as_strings<R: Read>(reader: &mut R) -> Result<Vec<String>> {
    Ok(read_u16_list(reader)?
        .into_iter()
        .map(|value| value.to_string())
        .collect())
}

fn write_string_owned_store_rule<W: Write>(
    writer: &mut W,
    item: u8,
    values: RuleList,
) -> Result<()> {
    if values.is_empty() {
        return Ok(());
    }
    writer.write_all(&[RULE_DEFAULT])?;
    write_string_item_list(writer, item, &values)?;
    writer.write_all(&[ITEM_FINAL, 0])?;
    Ok(())
}

fn write_ip_owned_store_rule<W: Write>(writer: &mut W, item: u8, cidrs: RuleList) -> Result<()> {
    if cidrs.is_empty() {
        return Ok(());
    }
    writer.write_all(&[RULE_DEFAULT])?;
    write_ip_set_item_list(writer, item, &cidrs)?;
    writer.write_all(&[ITEM_FINAL, 0])?;
    Ok(())
}
