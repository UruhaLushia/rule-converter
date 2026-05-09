mod builder;
mod io;
mod prefix;
mod range;
mod set;

pub use builder::IpCidrSetBuilder;
pub use prefix::{parse_prefix, prefix_contains_ip};
pub use set::IpCidrSet;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_prefix_is_masked_and_written_as_mapped_ipv6() {
        let range = parse_prefix("192.168.1.123/24").unwrap();
        assert_eq!(range.start_as16()[12..16], [192, 168, 1, 0]);
        assert_eq!(range.end_as16()[12..16], [192, 168, 1, 255]);
        assert_eq!(range.start_as16()[10..12], [0xff, 0xff]);
    }
}
