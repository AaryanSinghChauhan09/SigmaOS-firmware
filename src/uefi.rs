//! UEFI model.

#[derive(Debug, Clone)]
pub struct UefiTable {
    pub signature: [u8; 8],
    pub revision: u32,
}

#[derive(Debug, Clone)]
pub struct UefiProtocol {
    pub guid: [u8; 16],
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uefi_table() {
        let t = UefiTable { signature: *b"UEFI    ", revision: 0x20000 };
        assert_eq!(&t.signature, b"UEFI    ");
    }
}
