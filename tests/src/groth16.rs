use std::time::Instant;

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16, PreparedVerifyingKey, Proof};
use ark_relations::r1cs::{ConstraintLayer, ConstraintSynthesizer, ConstraintSystem, TracingMode};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use rand::thread_rng;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;

use crate::{
    circuit::SudokuCircuit,
    parameters::{get_unsolved_hash, SOLVED, UNSOLVED},
};

pub fn run_groth16<F, E>() -> (Vec<u8>, PreparedVerifyingKey<E>, Proof<E>)
where
    E: Pairing<ScalarField = F>,
    F: PrimeField,
    SudokuCircuit<F>: ConstraintSynthesizer<<E as Pairing>::ScalarField>,
{
    // First, some boilerplat that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);
    let unsolved_hash = get_unsolved_hash(UNSOLVED);
    let unsolved_hash_fr = F::from_le_bytes_mod_order(&unsolved_hash[0..31]);
    // should success
    let circuit_to_verify_success: SudokuCircuit<E::ScalarField> = SudokuCircuit {
        unsolved_hash: unsolved_hash_fr,
        unsolved: UNSOLVED,
        solved: SOLVED,
    };

    let cs = ConstraintSystem::new_ref();
    circuit_to_verify_success
        .clone()
        .generate_constraints(cs.clone())
        .unwrap();

    let circuit_defining_cs: SudokuCircuit<F> = SudokuCircuit {
        unsolved_hash: Default::default(),
        unsolved: Default::default(),
        solved: Default::default(),
    };
    let mut rng = thread_rng();

    let setup_start = Instant::now();
    let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit_defining_cs, &mut rng).unwrap();
    let processed_vk = Groth16::<E>::process_vk(&vk).unwrap();
    let setup_time = setup_start.elapsed();
    println!(
        "setup time {}ms, {}s",
        setup_time.as_millis(),
        setup_time.as_secs()
    );

    let cs = ConstraintSystem::new_ref();
    circuit_to_verify_success
        .clone()
        .generate_constraints(cs.clone())
        .unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();

    assert!(is_satisfied);

    let prove_start = Instant::now();
    let proof = Groth16::<E>::prove(&pk, circuit_to_verify_success.clone(), &mut rng).unwrap();
    let prove_time = prove_start.elapsed();
    println!(
        "prove time {}ms, {}s",
        prove_time.as_millis(),
        prove_time.as_secs()
    );
    println!(
        "proof len: {}",
        proof.serialized_size(ark_serialize::Compress::Yes)
    );

    let verify_start = Instant::now();
    let valid_proof = Groth16::<E, LibsnarkReduction>::verify_with_processed_vk(
        &processed_vk,
        &[circuit_to_verify_success.unsolved_hash],
        &proof,
    )
    .unwrap();
    let verify_time = verify_start.elapsed();
    println!(
        "verify time {}ms, {}s",
        verify_time.as_millis(),
        verify_time.as_secs()
    );
    assert!(valid_proof);

    let invalid_proof =
        Groth16::<E>::verify_with_processed_vk(&processed_vk, &[F::one()], &proof).unwrap();
    assert!(!invalid_proof);

    (unsolved_hash, processed_vk, proof)
}
