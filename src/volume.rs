//! Firmware volume model.

#[derive(Debug, Clone)]
pub struct FvBlock {
    pub offset: u64,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct FirmwareVolume {
    pub guid: [u8; 16],
    pub blocks: Vec<FvBlock>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_volume() {
        let fv = FirmwareVolume { guid: [0; 16], blocks: vec![] };
        assert_eq!(fv.blocks.len(), 0);
    }
}
