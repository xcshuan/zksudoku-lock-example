// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::vec::Vec;

use ark_bls12_381::Fr;
use ark_ff::fields::PrimeField;
use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16, PreparedVerifyingKey, Proof};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::Unpack,
    debug,
    high_level::{load_script, load_witness_args},
};

use crate::error::Error;

pub fn main() -> Result<(), Error> {
    // remove below examples and write your code here
    let script = load_script()?;
    let args: Vec<u8> = script.args().unpack();
    debug!("vk len: {}", args.len());

    let (public_input, vk) = args.split_at(32);

    let prepared_vk =
        match PreparedVerifyingKey::<ark_bls12_381::Bls12_381>::deserialize_compressed_unchecked(vk)
        {
            Ok(prepared_vk) => prepared_vk,
            Err(_) => return Err(Error::VerificationError),
        };

    let witness = load_witness_args(0, Source::Input).unwrap();

    let proof = match witness.lock().to_opt() {
        Some(proof) => {
            let proof = proof.raw_data();
            debug!("signature_with_recid len: {}", proof.len());
            if let Ok(proof) =
                Proof::<ark_bls12_381::Bls12_381>::deserialize_compressed_unchecked(proof.as_ref())
            {
                proof
            } else {
                return Err(Error::VerificationError);
            }
        }
        None => return Err(Error::VerificationError),
    };

    let public_input = Fr::from_le_bytes_mod_order(&public_input[..31]);

    let valid_proof =
        Groth16::<ark_bls12_381::Bls12_381, LibsnarkReduction>::verify_with_processed_vk(
            &prepared_vk,
            &[public_input],
            &proof,
        )
        .unwrap();

    if !valid_proof {
        return Err(Error::VerificationError);
    }

    Ok(())
}
