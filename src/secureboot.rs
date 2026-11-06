//! Secure boot model.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootState { Disabled, Enabled, AuditMode }

#[derive(Debug, Clone)]
pub struct DbEntry {
    pub guid: [u8; 16],
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secureboot_state() {
        let s = SecureBootState::Enabled;
        assert_eq!(s, SecureBootState::Enabled);
    }
}
