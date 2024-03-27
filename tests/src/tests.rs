use crate::groth16::run_groth16;

use super::*;
use ark_serialize::CanonicalSerialize;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};

const MAX_CYCLES: u64 = 1000_000_000;

#[test]
fn test_zkverify() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("zksudoku-lock");
    let out_point = context.deploy_cell(contract_bin);

    let (public_input, prepared_vk, proof) =
        run_groth16::<ark_bls12_381::Fr, ark_bls12_381::Bls12_381>();

    let mut prepared_vk_bytes = vec![];
    prepared_vk
        .serialize_compressed(&mut prepared_vk_bytes)
        .unwrap();
    let lock_args = [public_input.as_slice(), &prepared_vk_bytes].concat();

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, Bytes::from(lock_args))
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    let mut proof_bytes = vec![];
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    let witness = WitnessArgsBuilder::default()
        .lock(Some(Bytes::from(proof_bytes)).pack())
        .build();
    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}
