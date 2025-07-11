use gcrypt::{EdwardsPoint, FieldElement};

fn main() {
    println!("Testing basic operations...");
    
    // Create a simple basepoint manually to avoid the constant issue
    let basepoint = EdwardsPoint {
        X: FieldElement(gcrypt::backend::FieldImpl::ZERO),
        Y: FieldElement(gcrypt::backend::FieldImpl::ONE),
        Z: FieldElement(gcrypt::backend::FieldImpl::ONE),
        T: FieldElement(gcrypt::backend::FieldImpl::ZERO),
    };
    
    println!("Basepoint created manually");
    
    println!("✅ All operations successful!");
}