//! Client side: quote the PCRs with the TPM (libtss2 via tss-esapi).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

use tss_esapi::{
    abstraction::pcr::read_all,
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        resource_handles::Hierarchy,
    },
    structures::{
        Data, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, PcrSelectionList,
        PcrSlot, Public, PublicBuilder, PublicEccParametersBuilder, SignatureScheme,
        SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    traits::Marshall,
    Context,
};

use crate::{AkPublic, Error, Evidence, PcrValue, IMA_LOG_PATH, QUOTED_PCRS};

/// Where `collect_with` finds the TPM and the IMA log.
#[derive(Debug, Clone)]
pub struct CollectOptions {
    /// A TCTI string as libtss2 spells it, e.g. `device:/dev/tpmrm0` or
    /// `swtpm:host=127.0.0.1,port=2321`.
    pub tcti: String,
    /// The binary IMA log. `None`, or a file we can't read, sends no log.
    pub ima_log: Option<PathBuf>,
}

impl Default for CollectOptions {
    fn default() -> Self {
        CollectOptions {
            tcti: "device:/dev/tpmrm0".into(),
            ima_log: Some(PathBuf::from(IMA_LOG_PATH)),
        }
    }
}

fn other(what: &str) -> impl Fn(tss_esapi::Error) -> Error + '_ {
    move |e| Error::Other(format!("{what}: {e}"))
}

/// Collect evidence for `nonce` (at most 64 bytes) from the TPM `opts` names.
pub fn collect_with(nonce: &[u8], opts: &CollectOptions) -> Result<Evidence, Error> {
    let tcti = TctiNameConf::from_str(&opts.tcti).map_err(other("bad TCTI"))?;
    let mut ctx = Context::new(tcti).map_err(other("opening TPM"))?;
    let qualifying = Data::try_from(nonce.to_vec())
        .map_err(|_| Error::Other("nonce must be at most 64 bytes".into()))?;
    let selection = quoted_selection()?;

    let ak = ctx
        .execute_with_nullauth_session(|c| {
            c.create_primary(
                Hierarchy::Endorsement,
                ak_template()?,
                None,
                None,
                None,
                None,
            )
        })
        .map_err(other("creating attestation key"))?;
    let result = quote_and_read(&mut ctx, ak.key_handle, qualifying, selection);
    // Transient objects fill the TPM's few slots; always flush.
    let _ = ctx.flush_context(ak.key_handle.into());
    let (quote, signature, pcrs) = result?;

    // Read the log after the quote: IMA only appends, so if a measurement
    // lands in between, the log is ahead of the quote and the verifier sees
    // a mismatch rather than us silently trimming it.
    let ima_log = opts.ima_log.as_ref().and_then(|p| std::fs::read(p).ok());

    Ok(Evidence {
        nonce: nonce.to_vec(),
        quote,
        signature,
        pcrs,
        ima_log,
        ak_public: ak_public(&ak.out_public)?,
    })
}

type Quoted = (Vec<u8>, Vec<u8>, BTreeMap<u8, PcrValue>);

/// Quote, with PCR reads on both sides; retry if a PCR moved in between so
/// the reported values are the ones the quote covers.
fn quote_and_read(
    ctx: &mut Context,
    ak: tss_esapi::handles::KeyHandle,
    qualifying: Data,
    selection: PcrSelectionList,
) -> Result<Quoted, Error> {
    for _ in 0..3 {
        let before = read_pcrs(ctx, &selection)?;
        let (attest, sig) = ctx
            .execute_with_nullauth_session(|c| {
                c.quote(
                    ak,
                    qualifying.clone(),
                    SignatureScheme::Null,
                    selection.clone(),
                )
            })
            .map_err(other("TPM2_Quote"))?;
        let after = read_pcrs(ctx, &selection)?;
        if before == after {
            let quote = attest.marshall().map_err(other("marshalling quote"))?;
            let signature = sig.marshall().map_err(other("marshalling signature"))?;
            return Ok((quote, signature, after));
        }
    }
    Err(Error::Other(
        "PCRs kept changing while quoting; try again".into(),
    ))
}

fn quoted_selection() -> Result<PcrSelectionList, Error> {
    let slots: Vec<PcrSlot> = QUOTED_PCRS
        .iter()
        .map(|&n| PcrSlot::try_from(1u32 << n))
        .collect::<Result<_, _>>()
        .map_err(other("PCR slot"))?;
    PcrSelectionList::builder()
        .with_selection(HashingAlgorithm::Sha256, &slots)
        .build()
        .map_err(other("PCR selection"))
}

fn read_pcrs(
    ctx: &mut Context,
    selection: &PcrSelectionList,
) -> Result<BTreeMap<u8, PcrValue>, Error> {
    let data = read_all(ctx, selection.clone()).map_err(other("reading PCRs"))?;
    let bank = data
        .pcr_bank(HashingAlgorithm::Sha256)
        .ok_or_else(|| Error::Other("TPM has no SHA-256 PCR bank".into()))?;
    let mut out = BTreeMap::new();
    for &n in QUOTED_PCRS {
        let slot = PcrSlot::try_from(1u32 << n).map_err(other("PCR slot"))?;
        let digest = bank
            .get_digest(slot)
            .ok_or_else(|| Error::Other(format!("TPM did not return PCR {n}")))?;
        let value: PcrValue = digest
            .value()
            .try_into()
            .map_err(|_| Error::Other(format!("PCR {n} is not 32 bytes")))?;
        out.insert(n, value);
    }
    Ok(out)
}

/// A restricted ECDSA-SHA256 P-256 signing key. Created as a primary in the
/// endorsement hierarchy, so the same TPM always derives the same key from
/// this template: "create or load" without persistent handles.
fn ak_template() -> tss_esapi::Result<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_restricted(true)
        .with_sign_encrypt(true)
        .with_decrypt(false)
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::Null)
                .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_curve(EccCurve::NistP256)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .with_is_signing_key(true)
                .with_restricted(true)
                .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

fn ak_public(public: &Public) -> Result<AkPublic, Error> {
    let Public::Ecc { unique, .. } = public else {
        return Err(Error::Other("attestation key is not ECC".into()));
    };
    let mut sec1 = vec![0x04];
    for coord in [unique.x().value(), unique.y().value()] {
        if coord.len() > 32 {
            return Err(Error::Other("AK coordinate longer than 32 bytes".into()));
        }
        sec1.extend(std::iter::repeat_n(0u8, 32 - coord.len()));
        sec1.extend_from_slice(coord);
    }
    Ok(AkPublic(sec1))
}
