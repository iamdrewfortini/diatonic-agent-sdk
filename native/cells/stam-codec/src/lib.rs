//! One cell: encode the existing 39-symbol STAM opcode profile into ten bytes.
//! This library grants no execution authority and is not a theorem checker.
#![forbid(unsafe_code)]

/// Preserve the existing 78-bit profile with two zero high padding bits.
pub fn pack_profile(symbols: &str) -> Result<[u8; 10], &'static str> {
    if symbols.len() != 39 {
        return Err("expected thirteen STAM triplets");
    }
    let mut value: u128 = 0;
    for byte in symbols.bytes() {
        let digit = match byte {
            b'S' => 0,
            b'T' => 1,
            b'A' => 2,
            b'M' => 3,
            _ => return Err("invalid STAM symbol"),
        };
        value = (value << 2) | digit;
    }
    let encoded = value.to_be_bytes();
    let mut result = [0u8; 10];
    result.copy_from_slice(&encoded[6..]);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::pack_profile;
    #[test]
    fn canonical_profile() {
        let input = "SSSSSTSSASAMSTMSMMASSASTASMTSSTTMTAMMMM";
        assert_eq!(pack_profile(input), Ok([0, 4, 34, 199, 62, 8, 99, 65, 118, 255]));
    }
    #[test]
    fn invalid_and_padding_boundaries() {
        assert!(pack_profile("").is_err());
        assert!(pack_profile(&"X".repeat(39)).is_err());
        assert_eq!(pack_profile(&"M".repeat(39)).unwrap()[0], 0x3f);
    }
}
