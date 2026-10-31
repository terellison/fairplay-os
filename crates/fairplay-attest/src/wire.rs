//! Just enough TPM 2.0 unmarshalling (big-endian, TPM 2.0 Part 2) for the
//! verifier to read a quote and its signature without libtss2.

pub const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

pub const NOT_A_QUOTE: &str = "not a quote";

#[derive(Debug)]
pub struct ParseError(pub String);

fn err<T>(m: &str) -> Result<T, ParseError> {
    Err(ParseError(m.to_string()))
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.buf.len() < n {
            return err("truncated");
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ParseError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, ParseError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    /// A TPM2B: u16 size, then that many bytes.
    fn tpm2b(&mut self) -> Result<&'a [u8], ParseError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn finish(&self) -> Result<(), ParseError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            err("trailing bytes")
        }
    }
}

/// The parts of a TPMS_ATTEST of type TPM_ST_ATTEST_QUOTE the verifier needs.
#[derive(Debug)]
pub struct Quote {
    pub extra_data: Vec<u8>,
    /// (hash algorithm, PCR bitmap) per TPMS_PCR_SELECTION.
    pub pcr_select: Vec<(u16, Vec<u8>)>,
    pub pcr_digest: Vec<u8>,
}

pub fn parse_quote(b: &[u8]) -> Result<Quote, ParseError> {
    let mut r = Reader { buf: b };
    if r.u32()? != TPM_GENERATED_VALUE {
        return err(NOT_A_QUOTE);
    }
    if r.u16()? != TPM_ST_ATTEST_QUOTE {
        return err(NOT_A_QUOTE);
    }
    r.tpm2b()?; // qualifiedSigner
    let extra_data = r.tpm2b()?.to_vec();
    r.take(8 + 4 + 4 + 1)?; // clockInfo: clock, resetCount, restartCount, safe
    r.take(8)?; // firmwareVersion
    let count = r.u32()?;
    if count > 16 {
        return err("too many PCR selections");
    }
    let mut pcr_select = Vec::new();
    for _ in 0..count {
        let alg = r.u16()?;
        let size = r.u8()? as usize;
        pcr_select.push((alg, r.take(size)?.to_vec()));
    }
    let pcr_digest = r.tpm2b()?.to_vec();
    r.finish()?;
    Ok(Quote {
        extra_data,
        pcr_select,
        pcr_digest,
    })
}

/// Parse a TPMT_SIGNATURE holding ECDSA-SHA256 into (r, s), left-padded to
/// 32 bytes each.
pub fn parse_ecdsa_signature(b: &[u8]) -> Result<([u8; 32], [u8; 32]), ParseError> {
    let mut r = Reader { buf: b };
    if r.u16()? != TPM_ALG_ECDSA {
        return err("not an ECDSA signature");
    }
    if r.u16()? != TPM_ALG_SHA256 {
        return err("not signed with SHA-256");
    }
    let sig_r = pad32(r.tpm2b()?)?;
    let sig_s = pad32(r.tpm2b()?)?;
    r.finish()?;
    Ok((sig_r, sig_s))
}

fn pad32(v: &[u8]) -> Result<[u8; 32], ParseError> {
    if v.len() > 32 {
        return err("ECDSA scalar longer than 32 bytes");
    }
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(v);
    Ok(out)
}

/// The 3-byte TPMS_PCR_SELECTION bitmap for these PCR indices (< 24).
pub fn pcr_bitmap(pcrs: &[u8]) -> Vec<u8> {
    let mut map = vec![0u8; 3];
    for &n in pcrs {
        map[n as usize / 8] |= 1 << (n % 8);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmap_for_quoted_pcrs() {
        assert_eq!(pcr_bitmap(crate::QUOTED_PCRS), vec![0xff, 0x24, 0x00]);
    }

    #[test]
    fn rejects_truncated_quote() {
        let mut q = TPM_GENERATED_VALUE.to_be_bytes().to_vec();
        q.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        assert!(parse_quote(&q).is_err());
    }

    #[test]
    fn rejects_non_quote() {
        let mut q = TPM_GENERATED_VALUE.to_be_bytes().to_vec();
        q.extend_from_slice(&0x8017u16.to_be_bytes()); // ATTEST_CERTIFY
        assert_eq!(parse_quote(&q).unwrap_err().0, NOT_A_QUOTE);
    }
}
