//! SigmaOS-firmware — firmware model.
//!
//! Models firmware interfaces: UEFI, BIOS, firmware volumes,
//! TPM (Trusted Platform Module), and secure boot state.
//! Deterministic and std-only (no actual hardware access).

pub mod uefi;
pub mod bios;
pub mod volume;
pub mod tpm;
pub mod secureboot;

pub use uefi::{UefiTable, UefiProtocol};
pub use bios::{BiosRegion, BiosChecksum};
pub use volume::{FirmwareVolume, FvBlock};
pub use tpm::{TpmVersion, TpmPcr, TpmState};
pub use secureboot::{SecureBootState, DbEntry};
