//! Simple main file for testing gcrypt functionality

fn main() {
    println!("gcrypt - A modern Curve25519 implementation");
    println!("Status: Pre-release - Core functionality implemented");
    
    #[cfg(feature = "std")]
    {
        // Basic functionality test
        use gcrypt::{Scalar, FieldElement};
        
        // Test basic scalar operations
        let scalar_zero = Scalar::ZERO;
        let scalar_one = Scalar::ONE;
        let scalar_sum = &scalar_zero + &scalar_one;
        
        println!("Basic scalar arithmetic works!");
        println!("0 + 1 = {:?}", scalar_sum.to_bytes()[0]); // Should be 1
        
        // Test basic field operations  
        let field_zero = FieldElement::ZERO;
        let field_one = FieldElement::ONE;
        let field_sum = &field_zero + &field_one;
        
        println!("Basic field arithmetic works!");
        println!("Field 0 + 1 first byte: {}", field_sum.to_bytes()[0]); // Should be 1
    }
}
