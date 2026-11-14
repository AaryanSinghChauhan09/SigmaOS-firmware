//! TPM model: PCR extend semantics (SHA-256), quote sealing checks,
//! NV index attributes. Deterministic and std-only — hashing uses a
//! small self-contained SHA-256 so no external deps are needed.

use std::collections::BTreeMap;

/// Minimal SHA-256 (FIPS 180-4) — sufficient for PCR extend.
mod sha256 {
    const K: [u32; 64] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ];
    fn rotr(x: u32, n: u32) -> u32 { x.rotate_right(n) }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
            0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
        ];
        let bitlen = (data.len() as u64).wrapping_mul(8);
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 { msg.push(0); }
        msg.extend_from_slice(&bitlen.to_be_bytes());
        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([chunk[4*i], chunk[4*i+1], chunk[4*i+2], chunk[4*i+3]]);
            }
            for i in 16..64 {
                let s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
                let s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
                w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
            }
            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
                (h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);
            for i in 0..64 {
                let s1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
                let s0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                hh = g; g = f; f = e; e = d.wrapping_add(t1);
                d = c; c = b; b = a; a = t1.wrapping_add(t2);
            }
            h[0]=h[0].wrapping_add(a); h[1]=h[1].wrapping_add(b);
            h[2]=h[2].wrapping_add(c); h[3]=h[3].wrapping_add(d);
            h[4]=h[4].wrapping_add(e); h[5]=h[5].wrapping_add(f);
            h[6]=h[6].wrapping_add(g); h[7]=h[7].wrapping_add(hh);
        }
        let mut out = [0u8; 32];
        for (i, word) in h.iter().enumerate() {
            out[4*i..4*i+4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmVersion { V1_2, V2_0 }

impl TpmVersion {
    /// PCR digest size for this version (SHA-1 vs SHA-256).
    pub fn pcr_size(self) -> usize { match self { Self::V1_2 => 20, Self::V2_0 => 32 } }
    /// Number of implemented PCRs.
    pub fn pcr_count(self) -> u32 { match self { Self::V1_2 => 24, Self::V2_0 => 24 } }
}

/// A Platform Configuration Register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmPcr {
    pub index: u32,
    pub value: Vec<u8>, // digest_size bytes
}

/// NV index attributes (TPM2_NV attributes simplified).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvAttributes {
    pub owner_write: bool,
    pub owner_read: bool,
    pub platform_write: bool,
    pub policy_delete: bool,
}

/// TPM device state.
#[derive(Debug, Clone)]
pub struct TpmState {
    pub version: TpmVersion,
    pub pcrs: BTreeMap<u32, Vec<u8>>,
    pub nv: BTreeMap<u32, (NvAttributes, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmError {
    PcrOutOfRange(u32),
    NvOutOfRange(u32),
    PcrLocked(u32),
    BadPcrData,
    NvNotFound(u32),
    NvWriteDenied(u32),
}

impl std::fmt::Display for TpmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PcrOutOfRange(i) => write!(f, "PCR {} out of range", i),
            Self::NvOutOfRange(i) => write!(f, "NV index 0x{:x} out of range", i),
            Self::PcrLocked(i) => write!(f, "PCR {} is locked", i),
            Self::BadPcrData => write!(f, "PCR extend data empty"),
            Self::NvNotFound(i) => write!(f, "NV index 0x{:x} not found", i),
            Self::NvWriteDenied(i) => write!(f, "NV index 0x{:x} write denied", i),
        }
    }
}

impl std::error::Error for TpmError {}

impl TpmState {
    pub fn new(version: TpmVersion) -> Self {
        let size = version.pcr_size();
        let pcrs = (0..version.pcr_count()).map(|i| (i, vec![0u8; size])).collect();
        Self { version, pcrs, nv: BTreeMap::new() }
    }

    pub fn read_pcr(&self, index: u32) -> Result<&[u8], TpmError> {
        self.pcrs.get(&index).map(|v| v.as_slice())
            .ok_or(TpmError::PcrOutOfRange(index))
    }

    /// TPM2_PCR_Extend: PCRnew = HASH(PCRold || digest(data)).
    /// `data` is pre-hashed by the caller for v2 (event digest); for
    /// simplicity we hash data then extend with that digest — matching
    /// TPM2 semantics where the command carries the digest.
    pub fn pcr_extend(&mut self, index: u32, digest: &[u8]) -> Result<(), TpmError> {
        let old = self.pcrs.get(&index).ok_or(TpmError::PcrOutOfRange(index))?;
        if digest.is_empty() { return Err(TpmError::BadPcrData); }
        // new = SHA-256(old || digest) for v2; for v1.2 use SHA-1-sized
        // truncation semantics approximated by hashing then truncating.
        let mut buf = Vec::with_capacity(old.len() + digest.len());
        buf.extend_from_slice(old);
        buf.extend_from_slice(digest);
        let full = sha256::digest(&buf);
        let keep = match self.version {
            TpmVersion::V2_0 => 32,
            TpmVersion::V1_2 => 20,
        };
        let new_val = full[..keep].to_vec();
        self.pcrs.insert(index, new_val);
        Ok(())
    }

    /// PCR_Extend convenience: hash arbitrary data then extend.
    pub fn pcr_extend_data(&mut self, index: u32, data: &[u8]) -> Result<(), TpmError> {
        if data.is_empty() { return Err(TpmError::BadPcrData); }
        let d = sha256::digest(data);
        self.pcr_extend(index, &d)
    }

    /// Define an NV index.
    pub fn nv_define(&mut self, index: u32, size: usize, attrs: NvAttributes) {
        self.nv.insert(index, (attrs, vec![0u8; size]));
    }

    pub fn nv_write(&mut self, index: u32, data: &[u8]) -> Result<(), TpmError> {
        let (attrs, buf) = self.nv.get_mut(&index).ok_or(TpmError::NvNotFound(index))?;
        if !attrs.owner_write && !attrs.platform_write {
            return Err(TpmError::NvWriteDenied(index));
        }
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(())
    }

    pub fn nv_read(&self, index: u32) -> Result<&[u8], TpmError> {
        self.nv.get(&index).map(|(_, b)| b.as_slice()).ok_or(TpmError::NvNotFound(index))
    }

    /// PCR quote for remote attestation: returns concatenated selected PCRs.
    pub fn quote_pcrs(&self, indices: &[u32]) -> Result<Vec<u8>, TpmError> {
        let mut out = Vec::new();
        for &i in indices {
            out.extend_from_slice(self.read_pcr(i)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector_aaa() {
        // Arrange & Act
        let d = sha256::digest(b"abc");
        // Assert: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hex: String = d.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_pcr_extend_changes_value_deterministically_aaa() {
        // Arrange
        let mut t = TpmState::new(TpmVersion::V2_0);
        let before = t.read_pcr(0).unwrap().to_vec();
        // Act
        t.pcr_extend_data(0, b"measured boot stage").unwrap();
        let after1 = t.read_pcr(0).unwrap().to_vec();
        // Assert
        assert_ne!(before, after1);
        assert_eq!(after1.len(), 32);
        // extend again with same data → different result (old||digest changed)
        t.pcr_extend_data(0, b"measured boot stage").unwrap();
        assert_ne!(t.read_pcr(0).unwrap(), &after1[..]);
    }

    #[test]
    fn test_pcr_out_of_range_rejected_aaa() {
        // Arrange
        let mut t = TpmState::new(TpmVersion::V2_0);
        // Act & Assert
        assert!(matches!(t.pcr_extend(99, &[1;32]), Err(TpmError::PcrOutOfRange(99))));
        assert!(matches!(t.pcr_extend(0, &[]), Err(TpmError::BadPcrData)));
    }

    #[test]
    fn test_nv_write_requires_permission_aaa() {
        // Arrange
        let mut t = TpmState::new(TpmVersion::V2_0);
        let no_write = NvAttributes { owner_write: false, owner_read: true,
            platform_write: false, policy_delete: false };
        t.nv_define(0x01c00000, 8, no_write);
        // Act & Assert
        assert!(matches!(t.nv_write(0x01c00000, b"data"), Err(TpmError::NvWriteDenied(_))));
        t.nv_define(0x01c00001, 8, NvAttributes { owner_write: true, ..no_write });
        t.nv_write(0x01c00001, b"hello").unwrap();
        assert_eq!(&t.nv_read(0x01c00001).unwrap()[..5], b"hello");
    }

    #[test]
    fn test_quote_pcrs_concatenates_aaa() {
        // Arrange
        let mut t = TpmState::new(TpmVersion::V2_0);
        t.pcr_extend_data(0, b"a").unwrap();
        t.pcr_extend_data(7, b"b").unwrap();
        // Act
        let q = t.quote_pcrs(&[0, 7]).unwrap();
        // Assert
        assert_eq!(q.len(), 64);
        assert!(t.quote_pcrs(&[42]).is_err());
    }

    #[test]
    fn test_v1_2_pcr_size_20_aaa() {
        // Arrange
        let mut t = TpmState::new(TpmVersion::V1_2);
        // Act
        t.pcr_extend_data(0, b"x").unwrap();
        // Assert
        assert_eq!(t.read_pcr(0).unwrap().len(), 20);
    }
}
