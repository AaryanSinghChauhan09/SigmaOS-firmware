//! TPM model.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmVersion { V1_2, V2_0 }

#[derive(Debug, Clone)]
pub struct TpmPcr {
    pub index: u32,
    pub value: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct TpmState {
    pub version: TpmVersion,
    pub pcrs: Vec<TpmPcr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_pcr() {
        let p = TpmPcr { index: 0, value: [0; 32] };
        assert_eq!(p.index, 0);
    }
}
