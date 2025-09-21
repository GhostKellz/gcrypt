//! Batch Operations Example
//!
//! Demonstrates high-throughput batch operations for DeFi protocols
//! including signature verification, arithmetic, and Merkle trees.

use gcrypt::{Scalar, EdwardsPoint, FieldElement};

#[cfg(all(feature = "batch-operations", feature = "alloc"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("⚡ Batch Operations Demo");
    println!("=======================\n");

    // 1. Batch Signature Verification - DEX Order Book
    println!("1. Batch Signature Verification (DEX Order Book Simulation)...");

    let order_count = 50;
    let mut public_keys = Vec::new();
    let mut messages = Vec::new();
    let mut signatures = Vec::new();

    println!("   Creating {} trading orders...", order_count);

    // Simulate trading orders
    for i in 0..order_count {
        let trader_secret = Scalar::from_u64((i + 1) * 1000 + 42);
        let secret_key = gcrypt::protocols::ed25519::SecretKey::from_scalar(trader_secret);
        let public_key = gcrypt::protocols::ed25519::PublicKey::from(&secret_key);

        let order = format!(
            "{{\"type\":\"buy\",\"amount\":{},\"price\":{},\"pair\":\"GSPR/USDC\",\"nonce\":{}}}",
            (i + 1) * 100,
            5000 + i * 10,
            i
        );
        let message = order.into_bytes();
        let signature = gcrypt::protocols::ed25519::sign(&secret_key, &message);

        public_keys.push(public_key);
        messages.push(message);
        signatures.push(signature);
    }

    let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

    // Individual verification timing
    let individual_start = std::time::Instant::now();
    let mut individual_valid = 0;
    for ((pubkey, message), signature) in public_keys.iter().zip(message_refs.iter()).zip(signatures.iter()) {
        if gcrypt::protocols::ed25519::verify(pubkey, message, signature) {
            individual_valid += 1;
        }
    }
    let individual_time = individual_start.elapsed();

    // Batch verification timing
    let batch_start = std::time::Instant::now();
    let batch_result = gcrypt::batch::batch_signatures::verify_ed25519_batch(
        &public_keys,
        &message_refs,
        &signatures
    )?;
    let batch_time = batch_start.elapsed();

    // Fast batch verification (mathematical optimization)
    let fast_batch_start = std::time::Instant::now();
    let fast_batch_result = gcrypt::batch::batch_signatures::verify_ed25519_batch_fast(
        &public_keys,
        &message_refs,
        &signatures
    )?;
    let fast_batch_time = fast_batch_start.elapsed();

    println!("   ✓ Individual verification: {}/{} valid ({:.2}ms)",
             individual_valid, order_count, individual_time.as_millis());
    println!("   ✓ Batch verification: {} ({:.2}ms, {:.1}x speedup)",
             if batch_result { "VALID" } else { "INVALID" },
             batch_time.as_millis(),
             individual_time.as_millis() as f64 / batch_time.as_millis() as f64);
    println!("   ✓ Fast batch verification: {} ({:.2}ms, {:.1}x speedup)",
             if fast_batch_result { "VALID" } else { "INVALID" },
             fast_batch_time.as_millis(),
             individual_time.as_millis() as f64 / fast_batch_time.as_millis() as f64);

    // 2. Batch Arithmetic Operations - Transaction Processing
    println!("\n2. Batch Arithmetic Operations (Transaction Processing)...");

    let tx_count = 100;
    let transaction_scalars: Vec<Scalar> = (1..=tx_count)
        .map(|i| Scalar::from_u64(i * 12345 + 67890))
        .collect();

    println!("   Processing {} transactions...", tx_count);

    // Batch base scalar multiplication (public key generation)
    let pubkey_start = std::time::Instant::now();
    let public_key_points = gcrypt::batch::batch_arithmetic::scalar_mul_base(&transaction_scalars)?;
    let pubkey_time = pubkey_start.elapsed();

    println!("   ✓ Batch public key generation: {} keys ({:.2}ms, {:.1} keys/ms)",
             public_key_points.len(),
             pubkey_time.as_millis(),
             public_key_points.len() as f64 / pubkey_time.as_millis() as f64);

    // Batch point addition (UTXO aggregation)
    let point_add_start = std::time::Instant::now();
    let aggregated_points = gcrypt::batch::batch_arithmetic::point_add(&public_key_points, &public_key_points)?;
    let point_add_time = point_add_start.elapsed();

    println!("   ✓ Batch point addition: {} operations ({:.2}ms)",
             aggregated_points.len(), point_add_time.as_millis());

    // Multi-scalar multiplication (batch verification optimization)
    let multiscalar_start = std::time::Instant::now();
    let combined_point = gcrypt::batch::batch_arithmetic::multiscalar_mul(&transaction_scalars, &public_key_points)?;
    let multiscalar_time = multiscalar_start.elapsed();

    println!("   ✓ Multi-scalar multiplication: combined {} scalars and points ({:.2}ms)",
             transaction_scalars.len(), multiscalar_time.as_millis());

    // Batch scalar inversion (modular arithmetic)
    let inversion_start = std::time::Instant::now();
    let inverted_scalars = gcrypt::batch::batch_arithmetic::scalar_invert(&transaction_scalars)?;
    let inversion_time = inversion_start.elapsed();

    println!("   ✓ Batch scalar inversion: {} inversions ({:.2}ms, {:.1} inv/ms)",
             inverted_scalars.len(),
             inversion_time.as_millis(),
             inverted_scalars.len() as f64 / inversion_time.as_millis() as f64);

    // Verify inversions
    let mut correct_inversions = 0;
    for (original, inverted) in transaction_scalars.iter().zip(inverted_scalars.iter()) {
        if *original * inverted == Scalar::one() {
            correct_inversions += 1;
        }
    }
    println!("   ✓ Inversion verification: {}/{} correct", correct_inversions, inverted_scalars.len());

    // 3. Field Element Batch Operations - ZK-SNARK Preprocessing
    println!("\n3. Field Element Batch Operations (ZK-SNARK Preprocessing)...");

    let field_count = 200;
    let field_elements_a: Vec<FieldElement> = (1..=field_count)
        .map(|i| FieldElement::from_u64(i * 7 + 13))
        .collect();
    let field_elements_b: Vec<FieldElement> = (1..=field_count)
        .map(|i| FieldElement::from_u64(i * 11 + 17))
        .collect();

    println!("   Processing {} field elements...", field_count);

    // Batch field addition
    let field_add_start = std::time::Instant::now();
    let field_sums = gcrypt::batch::batch_arithmetic::field_add(&field_elements_a, &field_elements_b)?;
    let field_add_time = field_add_start.elapsed();

    // Batch field multiplication
    let field_mul_start = std::time::Instant::now();
    let field_products = gcrypt::batch::batch_arithmetic::field_mul(&field_elements_a, &field_elements_b)?;
    let field_mul_time = field_mul_start.elapsed();

    // Batch field inversion
    let field_inv_start = std::time::Instant::now();
    let field_inverted = gcrypt::batch::batch_arithmetic::field_invert(&field_elements_a)?;
    let field_inv_time = field_inv_start.elapsed();

    println!("   ✓ Batch field addition: {} operations ({:.2}ms)",
             field_sums.len(), field_add_time.as_millis());
    println!("   ✓ Batch field multiplication: {} operations ({:.2}ms)",
             field_products.len(), field_mul_time.as_millis());
    println!("   ✓ Batch field inversion: {} operations ({:.2}ms)",
             field_inverted.len(), field_inv_time.as_millis());

    // 4. Batch Merkle Tree Operations - Blockchain State Management
    println!("\n4. Batch Merkle Tree Operations (Blockchain State)...");

    let leaf_count = 128;
    let state_entries: Vec<Vec<u8>> = (0..leaf_count)
        .map(|i| format!("account_{}:balance_{}", i, i * 1000 + 500).into_bytes())
        .collect();
    let leaves: Vec<&[u8]> = state_entries.iter().map(|e| e.as_slice()).collect();

    println!("   Building Merkle tree for {} state entries...", leaf_count);

    // Build Merkle tree
    let tree_start = std::time::Instant::now();
    let merkle_root = gcrypt::batch::batch_merkle::build_tree_root(&leaves)?;
    let tree_time = tree_start.elapsed();

    println!("   ✓ Merkle tree construction: ({:.2}ms)", tree_time.as_millis());
    println!("   ✓ Root hash: {:?}", hex::encode(merkle_root)[..32]);

    // Generate proofs for all leaves
    let proofs_start = std::time::Instant::now();
    let (root2, all_proofs) = gcrypt::batch::batch_merkle::build_tree_with_proofs(&leaves)?;
    let proofs_time = proofs_start.elapsed();

    assert_eq!(merkle_root, root2);

    println!("   ✓ Proof generation: {} proofs ({:.2}ms, {:.1} proofs/ms)",
             all_proofs.len(),
             proofs_time.as_millis(),
             all_proofs.len() as f64 / proofs_time.as_millis() as f64);

    // Batch verify all proofs
    let verify_start = std::time::Instant::now();
    let all_proofs_valid = gcrypt::batch::batch_merkle::verify_proofs(&all_proofs, &leaves)?;
    let verify_time = verify_start.elapsed();

    println!("   ✓ Batch proof verification: {} ({:.2}ms)",
             if all_proofs_valid { "ALL VALID" } else { "SOME INVALID" },
             verify_time.as_millis());

    // Verify individual proofs
    let mut valid_proofs = 0;
    for (i, proof) in all_proofs.iter().enumerate() {
        if proof.verify(&leaves[i]) && proof.root == merkle_root {
            valid_proofs += 1;
        }
    }
    println!("   ✓ Individual verification: {}/{} proofs valid", valid_proofs, all_proofs.len());

    // 5. Performance Summary and DeFi Throughput Analysis
    println!("\n5. Performance Summary - DeFi Throughput Analysis...");

    let total_signatures = order_count;
    let total_arithmetic_ops = tx_count * 4; // base mul, point add, multiscalar, inversion
    let total_field_ops = field_count * 3; // add, mul, invert
    let total_merkle_ops = leaf_count; // tree construction + verification

    let total_processing_time = individual_time + pubkey_time + point_add_time +
                               multiscalar_time + inversion_time + field_add_time +
                               field_mul_time + field_inv_time + tree_time +
                               proofs_time + verify_time;

    println!("   📊 Operation Throughput Analysis:");
    println!("      • Signature verification: {:.1} sigs/ms", total_signatures as f64 / batch_time.as_millis() as f64);
    println!("      • Arithmetic operations: {:.1} ops/ms", total_arithmetic_ops as f64 / (pubkey_time + point_add_time + multiscalar_time + inversion_time).as_millis() as f64);
    println!("      • Field operations: {:.1} ops/ms", total_field_ops as f64 / (field_add_time + field_mul_time + field_inv_time).as_millis() as f64);
    println!("      • Merkle operations: {:.1} ops/ms", total_merkle_ops as f64 / (tree_time + verify_time).as_millis() as f64);

    println!("\n   🚀 DeFi Protocol Readiness:");
    println!("      • DEX order processing: {} orders/second", (order_count as f64 / batch_time.as_secs_f64()) as u32);
    println!("      • Transaction validation: {} tx/second", (tx_count as f64 / (pubkey_time + point_add_time).as_secs_f64()) as u32);
    println!("      • State proof generation: {} proofs/second", (leaf_count as f64 / proofs_time.as_secs_f64()) as u32);
    println!("      • Batch verification: {} items/second", ((total_signatures + total_arithmetic_ops + total_merkle_ops) as f64 / total_processing_time.as_secs_f64()) as u32);

    // 6. Parallel Processing Demo (if available)
    #[cfg(feature = "rayon")]
    {
        println!("\n6. Parallel Processing Demonstration...");

        let large_batch_size = 500;
        let large_scalars: Vec<Scalar> = (1..=large_batch_size)
            .map(|i| Scalar::from_u64(i * 999))
            .collect();

        // Sequential processing
        let seq_start = std::time::Instant::now();
        let seq_results: Vec<EdwardsPoint> = large_scalars.iter()
            .map(|s| EdwardsPoint::mul_base(s))
            .collect();
        let seq_time = seq_start.elapsed();

        // Parallel processing
        let par_start = std::time::Instant::now();
        let par_results = gcrypt::batch::batch_arithmetic::scalar_mul_base(&large_scalars)?;
        let par_time = par_start.elapsed();

        // Verify results are identical
        let results_match = seq_results.iter().zip(par_results.iter()).all(|(a, b)| a == b);

        println!("   ✓ Sequential processing: {} operations ({:.2}ms)",
                 large_batch_size, seq_time.as_millis());
        println!("   ✓ Parallel processing: {} operations ({:.2}ms, {:.1}x speedup)",
                 large_batch_size, par_time.as_millis(),
                 seq_time.as_millis() as f64 / par_time.as_millis() as f64);
        println!("   ✓ Results verification: {}", if results_match { "IDENTICAL" } else { "MISMATCH" });
    }

    println!("\n🎉 Batch Operations demo completed!");
    println!("   High-throughput DeFi operations ready for production!");

    Ok(())
}

#[cfg(not(all(feature = "batch-operations", feature = "alloc")))]
fn main() {
    println!("This example requires the following features:");
    println!("  --features batch-operations,alloc");
    println!("\nRun with:");
    println!("  cargo run --example batch_operations --features batch-operations,alloc");
    println!("\nFor parallel processing add:");
    println!("  --features batch-operations,alloc,parallel");
}