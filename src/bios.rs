//! BIOS model.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiosRegion { Firmware, Nvram, Me }

#[derive(Debug, Clone)]
pub struct BiosChecksum {
    pub region: BiosRegion,
    pub value: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bios_region() {
        let r = BiosRegion::Firmware;
        assert_eq!(r, BiosRegion::Firmware);
    }
}
