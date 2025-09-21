//! ZK-Friendly Hash Functions Example
//!
//! Demonstrates zero-knowledge friendly hash functions including
//! Poseidon, Rescue, MiMC, and Pedersen hashing.

use gcrypt::FieldElement;

#[cfg(all(feature = "zk-hash", feature = "alloc"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔮 ZK-Friendly Hash Functions Demo");
    println!("==================================\n");

    // 1. Poseidon Hash - Most Efficient in Circuits
    println!("1. Poseidon Hash Function (Most Circuit-Efficient)...");

    let input1 = FieldElement::from_u64(42);
    let input2 = FieldElement::from_u64(1337);
    let input3 = FieldElement::from_u64(9999);

    println!("   Input values:");
    println!("     • Value 1: {} (0x{:016x})", 42, 42);
    println!("     • Value 2: {} (0x{:016x})", 1337, 1337);
    println!("     • Value 3: {} (0x{:016x})", 9999, 9999);

    // Two-input Poseidon hash
    let poseidon_two = gcrypt::zk_hash::poseidon::hash_two(&input1, &input2)?;
    println!("   ✓ Poseidon(42, 1337): {:?}", hex::encode(poseidon_two.to_bytes())[..16]);

    // Many-input Poseidon hash
    let inputs = vec![input1, input2, input3];
    let poseidon_many = gcrypt::zk_hash::poseidon::hash_many(&inputs)?;
    println!("   ✓ Poseidon(42, 1337, 9999): {:?}", hex::encode(poseidon_many.to_bytes())[..16]);

    // Poseidon sponge for variable output
    let sponge_output = gcrypt::zk_hash::poseidon::sponge(&inputs, 3)?;
    println!("   ✓ Poseidon sponge output: {} field elements", sponge_output.len());
    for (i, elem) in sponge_output.iter().enumerate() {
        println!("     Output[{}]: {:?}", i, hex::encode(elem.to_bytes())[..16]);
    }

    // 2. Rescue Hash - Symmetric Design
    println!("\n2. Rescue Hash Function (Symmetric Design)...");

    let rescue_two = gcrypt::zk_hash::rescue::hash_two(&input1, &input2)?;
    println!("   ✓ Rescue(42, 1337): {:?}", hex::encode(rescue_two.to_bytes())[..16]);

    let rescue_many = gcrypt::zk_hash::rescue::hash_many(&inputs)?;
    println!("   ✓ Rescue(42, 1337, 9999): {:?}", hex::encode(rescue_many.to_bytes())[..16]);

    let rescue_sponge = gcrypt::zk_hash::rescue::sponge(&inputs, 2)?;
    println!("   ✓ Rescue sponge output: {} field elements", rescue_sponge.len());

    // 3. MiMC Hash - Minimal Multiplicative Complexity
    println!("\n3. MiMC Hash Function (Minimal Multiplicative Complexity)...");

    let mimc_two = gcrypt::zk_hash::mimc::hash_two(&input1, &input2)?;
    println!("   ✓ MiMC(42, 1337): {:?}", hex::encode(mimc_two.to_bytes())[..16]);

    let mimc_many = gcrypt::zk_hash::mimc::hash_many(&inputs)?;
    println!("   ✓ MiMC(42, 1337, 9999): {:?}", hex::encode(mimc_many.to_bytes())[..16]);

    // MiMC permutation
    let mimc_perm = gcrypt::zk_hash::mimc::permutation(&input1)?;
    println!("   ✓ MiMC permutation(42): {:?}", hex::encode(mimc_perm.to_bytes())[..16]);

    // MiMC encryption
    let mimc_encrypted = gcrypt::zk_hash::mimc::encrypt(&input1, &input2)?;
    println!("   ✓ MiMC encrypt(42, 1337): {:?}", hex::encode(mimc_encrypted.to_bytes())[..16]);

    // MiMC Feistel construction
    let (left_out, right_out) = gcrypt::zk_hash::mimc::feistel(&input1, &input2, 8)?;
    println!("   ✓ MiMC Feistel(42, 1337, 8 rounds):");
    println!("     Left:  {:?}", hex::encode(left_out.to_bytes())[..16]);
    println!("     Right: {:?}", hex::encode(right_out.to_bytes())[..16]);

    // 4. Pedersen Hash - Elliptic Curve Based
    println!("\n4. Pedersen Hash Function (Elliptic Curve Based)...");

    let pedersen_two = gcrypt::zk_hash::pedersen::hash_two(&input1, &input2)?;
    println!("   ✓ Pedersen(42, 1337): {:?}", hex::encode(pedersen_two.to_bytes())[..16]);

    let pedersen_many = gcrypt::zk_hash::pedersen::hash_many(&inputs)?;
    println!("   ✓ Pedersen(42, 1337, 9999): {:?}", hex::encode(pedersen_many.to_bytes())[..16]);

    // Pedersen hash from bytes
    let message = b"Hello, Pedersen hash!";
    let pedersen_bytes = gcrypt::zk_hash::pedersen::hash_bytes(message)?;
    println!("   ✓ Pedersen(\"{}\"): {:?}",
             String::from_utf8_lossy(message),
             hex::encode(pedersen_bytes.to_bytes())[..16]);

    // Pedersen hash to elliptic curve point
    let pedersen_point = gcrypt::zk_hash::pedersen::hash_to_point(message)?;
    let compressed_point = pedersen_point.compress();
    println!("   ✓ Pedersen point hash: {:?}", hex::encode(compressed_point.to_bytes())[..16]);

    // 5. Hash Function Comparison
    println!("\n5. Hash Function Comparison...");

    let test_inputs = vec![
        FieldElement::from_u64(12345),
        FieldElement::from_u64(67890),
    ];

    println!("   Comparing hash outputs for same input [12345, 67890]:");

    let poseidon_result = gcrypt::zk_hash::poseidon::hash_many(&test_inputs)?;
    let rescue_result = gcrypt::zk_hash::rescue::hash_many(&test_inputs)?;
    let mimc_result = gcrypt::zk_hash::mimc::hash_many(&test_inputs)?;
    let pedersen_result = gcrypt::zk_hash::pedersen::hash_many(&test_inputs)?;

    println!("   • Poseidon:  {:?}", hex::encode(poseidon_result.to_bytes())[..32]);
    println!("   • Rescue:    {:?}", hex::encode(rescue_result.to_bytes())[..32]);
    println!("   • MiMC:      {:?}", hex::encode(mimc_result.to_bytes())[..32]);
    println!("   • Pedersen:  {:?}", hex::encode(pedersen_result.to_bytes())[..32]);

    // Verify all outputs are different
    let outputs = vec![poseidon_result, rescue_result, mimc_result, pedersen_result];
    let mut all_different = true;
    for i in 0..outputs.len() {
        for j in i+1..outputs.len() {
            if outputs[i] == outputs[j] {
                all_different = false;
                break;
            }
        }
    }
    println!("   ✓ All hash functions produce different outputs: {}", all_different);

    // 6. Performance Benchmarking
    println!("\n6. Performance Benchmarking...");

    let bench_inputs = vec![
        FieldElement::from_u64(111111),
        FieldElement::from_u64(222222),
        FieldElement::from_u64(333333),
        FieldElement::from_u64(444444),
        FieldElement::from_u64(555555),
    ];

    let iterations = 100;
    println!("   Running {} iterations for each hash function...", iterations);

    // Poseidon benchmark
    let poseidon_start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = gcrypt::zk_hash::poseidon::hash_many(&bench_inputs)?;
    }
    let poseidon_time = poseidon_start.elapsed();

    // Rescue benchmark
    let rescue_start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = gcrypt::zk_hash::rescue::hash_many(&bench_inputs)?;
    }
    let rescue_time = rescue_start.elapsed();

    // MiMC benchmark
    let mimc_start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = gcrypt::zk_hash::mimc::hash_many(&bench_inputs)?;
    }
    let mimc_time = mimc_start.elapsed();

    // Pedersen benchmark
    let pedersen_start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = gcrypt::zk_hash::pedersen::hash_many(&bench_inputs)?;
    }
    let pedersen_time = pedersen_start.elapsed();

    println!("   Performance results ({} iterations):", iterations);
    println!("   • Poseidon:  {:.2}ms ({:.3}ms/hash)", poseidon_time.as_millis(), poseidon_time.as_millis() as f64 / iterations as f64);
    println!("   • Rescue:    {:.2}ms ({:.3}ms/hash)", rescue_time.as_millis(), rescue_time.as_millis() as f64 / iterations as f64);
    println!("   • MiMC:      {:.2}ms ({:.3}ms/hash)", mimc_time.as_millis(), mimc_time.as_millis() as f64 / iterations as f64);
    println!("   • Pedersen:  {:.2}ms ({:.3}ms/hash)", pedersen_time.as_millis(), pedersen_time.as_millis() as f64 / iterations as f64);

    // 7. Privacy Application Demo
    println!("\n7. Privacy Application Demo (Confidential Transactions)...");

    // Simulate confidential transaction commitments
    let amount = 1000u64;
    let blinding_factor = FieldElement::from_u64(0x1234567890ABCDEFu64);
    let recipient_key = FieldElement::from_u64(0xFEDCBA0987654321u64);

    // Create commitment using different hash functions
    let amount_field = FieldElement::from_u64(amount);

    println!("   Transaction details:");
    println!("     • Amount: {} GSPR", amount);
    println!("     • Blinding factor: {:?}", hex::encode(blinding_factor.to_bytes())[..16]);
    println!("     • Recipient key: {:?}", hex::encode(recipient_key.to_bytes())[..16]);

    let poseidon_commitment = gcrypt::zk_hash::poseidon::hash_many(&[amount_field, blinding_factor, recipient_key])?;
    let rescue_commitment = gcrypt::zk_hash::rescue::hash_many(&[amount_field, blinding_factor, recipient_key])?;
    let mimc_commitment = gcrypt::zk_hash::mimc::hash_many(&[amount_field, blinding_factor, recipient_key])?;
    let pedersen_commitment = gcrypt::zk_hash::pedersen::hash_many(&[amount_field, blinding_factor, recipient_key])?;

    println!("   Privacy commitments:");
    println!("     • Poseidon:  {:?}", hex::encode(poseidon_commitment.to_bytes())[..32]);
    println!("     • Rescue:    {:?}", hex::encode(rescue_commitment.to_bytes())[..32]);
    println!("     • MiMC:      {:?}", hex::encode(mimc_commitment.to_bytes())[..32]);
    println!("     • Pedersen:  {:?}", hex::encode(pedersen_commitment.to_bytes())[..32]);

    // 8. ZK-SNARK Circuit Considerations
    println!("\n8. ZK-SNARK Circuit Considerations...");

    println!("   Hash function properties for ZK circuits:");
    println!("   • Poseidon:");
    println!("     - Multiplicative complexity: LOW (designed for SNARKs)");
    println!("     - Round function: S-box with x^α");
    println!("     - Best for: Most ZK proof systems");
    println!("   • Rescue:");
    println!("     - Multiplicative complexity: MEDIUM");
    println!("     - Round function: Forward + inverse S-box");
    println!("     - Best for: Symmetric security proofs");
    println!("   • MiMC:");
    println!("     - Multiplicative complexity: MINIMAL");
    println!("     - Round function: x^α with round constants");
    println!("     - Best for: Minimal constraint systems");
    println!("   • Pedersen:");
    println!("     - Multiplicative complexity: HIGH (elliptic curves)");
    println!("     - Security: Very strong collision resistance");
    println!("     - Best for: Non-circuit applications, commitments");

    println!("\n   Recommended use cases:");
    println!("   🔹 Merkle trees in circuits: Poseidon");
    println!("   🔹 Symmetric encryption proofs: Rescue");
    println!("   🔹 Minimal constraint count: MiMC");
    println!("   🔹 Commitment schemes: Pedersen");
    println!("   🔹 General-purpose ZK: Poseidon");

    println!("\n🎉 ZK-Friendly Hash Functions demo completed!");
    println!("   Privacy-preserving cryptography ready for Ghostchain!");

    Ok(())
}

#[cfg(not(all(feature = "zk-hash", feature = "alloc")))]
fn main() {
    println!("This example requires the following features:");
    println!("  --features zk-hash,alloc");
    println!("\nRun with:");
    println!("  cargo run --example zk_hash_functions --features zk-hash,alloc");
}