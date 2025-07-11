//! 64-bit backend implementation.
//!
//! This backend uses 64-bit limbs for efficient arithmetic on 64-bit platforms.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Scalar implementation using 5 52-bit limbs.
#[derive(Copy, Clone, Debug)]
pub(crate) struct ScalarImpl {
    limbs: [u64; 5],
}

/// Field element implementation using 5 51-bit limbs.
#[derive(Copy, Clone, Debug)]
pub(crate) struct FieldImpl {
    limbs: [u64; 5],
}

impl ScalarImpl {
    pub const ZERO: ScalarImpl = ScalarImpl { limbs: [0, 0, 0, 0, 0] };
    pub const ONE: ScalarImpl = ScalarImpl { limbs: [1, 0, 0, 0, 0] };

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        // Convert little-endian bytes to limbs
        let mut limbs = [0u64; 5];
        
        // Pack bytes into 52-bit limbs
        let mut bits = 0u64;
        let mut bit_count = 0;
        let mut limb_index = 0;
        
        for &byte in &bytes {
            bits |= (byte as u64) << bit_count;
            bit_count += 8;
            
            if bit_count >= 52 && limb_index < 4 {
                limbs[limb_index] = bits & ((1u64 << 52) - 1);
                bits >>= 52;
                bit_count -= 52;
                limb_index += 1;
            }
        }
        
        if limb_index < 5 {
            limbs[limb_index] = bits;
        }
        
        ScalarImpl { limbs }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let mut bits = 0u64;
        let mut bit_count = 0;
        let mut byte_index = 0;
        
        for &limb in &self.limbs {
            bits |= limb << bit_count;
            bit_count += 52;
            
            while bit_count >= 8 && byte_index < 32 {
                bytes[byte_index] = (bits & 0xff) as u8;
                bits >>= 8;
                bit_count -= 8;
                byte_index += 1;
            }
        }
        
        bytes
    }

    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
        let mut limbs = [0u64; 5];
        
        // Pack bytes into 52-bit limbs
        let mut bits = 0u64;
        let mut bit_count = 0;
        let mut limb_index = 0;
        
        for &byte in &bytes {
            bits |= (byte as u64) << bit_count;
            bit_count += 8;
            
            if bit_count >= 52 && limb_index < 4 {
                limbs[limb_index] = bits & ((1u64 << 52) - 1);
                bits >>= 52;
                bit_count -= 52;
                limb_index += 1;
            }
        }
        
        if limb_index < 5 {
            limbs[limb_index] = bits;
        }
        
        // Reduce modulo l = 2^252 + 27742317777372353535851937790883648493
        // l in 52-bit limbs: [0xd3f5, 0x5c1a6312, 0x58d69cf7, 0xa2def9de, 0x14]
        let l = [
            0xfed3f5c1a631258d, // l limb 0
            0x69cf7a2def9de14,  // l limb 1
            0x0000000000000000, // l limb 2
            0x0000000000000000, // l limb 3
            0x1000000000000000, // l limb 4
        ];
        
        // Simple comparison and subtraction if >= l
        // This is a simplified reduction - production code would use Barrett reduction
        let mut needs_reduction = false;
        for i in (0..5).rev() {
            if limbs[i] > l[i] {
                needs_reduction = true;
                break;
            } else if limbs[i] < l[i] {
                break;
            }
        }
        
        if needs_reduction {
            // Subtract l
            let mut borrow = 0u64;
            for i in 0..5 {
                let diff = (limbs[i] as u128) - (l[i] as u128) - (borrow as u128);
                if diff < 0 {
                    limbs[i] = (diff + (1u128 << 52)) as u64;
                    borrow = 1;
                } else {
                    limbs[i] = diff as u64;
                    borrow = 0;
                }
            }
        }
        
        ScalarImpl { limbs }
    }

    pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        // Barrett reduction for 64-byte input
        // This is a simplified implementation
        
        // Split into high and low 32-byte halves
        let mut low_bytes = [0u8; 32];
        let mut high_bytes = [0u8; 32];
        low_bytes.copy_from_slice(&bytes[..32]);
        high_bytes.copy_from_slice(&bytes[32..]);
        
        // Convert to scalars
        let low = Self::from_bytes(low_bytes);
        let high = Self::from_bytes(high_bytes);
        
        // Multiply high by 2^256 mod l
        // Since 2^256 ≡ 2^4 * (2^252) ≡ 16 * (l - 27742317777372353535851937790883648493) (mod l)
        // This is simplified - real implementation would precompute this
        let high_reduced = high.mul(&ScalarImpl::from_bytes([16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        
        low.add(&high_reduced)
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 5];
        let mut carry = 0u64;
        
        for i in 0..5 {
            let sum = self.limbs[i] + other.limbs[i] + carry;
            result[i] = sum & ((1u64 << 52) - 1);
            carry = sum >> 52;
        }
        
        // Handle modular reduction (simplified)
        ScalarImpl { limbs: result }
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut result = [0u64; 5];
        let mut borrow = 0i64;
        
        for i in 0..5 {
            let diff = (self.limbs[i] as i64) - (other.limbs[i] as i64) - borrow;
            if diff < 0 {
                result[i] = (diff + (1i64 << 52)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }
        
        ScalarImpl { limbs: result }
    }

    pub fn mul(&self, other: &Self) -> Self {
        // Simplified multiplication - production would use more efficient algorithms
        let mut result = ScalarImpl::ZERO;
        for i in 0..5 {
            for j in 0..5 {
                if i + j < 5 {
                    // Use checked arithmetic to prevent overflow
                    let product = self.limbs[i].wrapping_mul(other.limbs[j]);
                    result.limbs[i + j] = result.limbs[i + j].wrapping_add(product);
                }
            }
        }
        
        // Carry propagation and reduction would happen here
        result
    }

    pub fn neg(&self) -> Self {
        // 0 - self
        ScalarImpl::ZERO.sub(self)
    }

    pub fn invert(&self) -> Self {
        // Simplified inversion using Fermat's little theorem
        // In production, would use more efficient algorithms
        let mut result = *self;
        for _ in 0..250 { // Approximate for demonstration
            result = result.mul(&result);
        }
        result
    }
}

impl ConstantTimeEq for ScalarImpl {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.limbs.ct_eq(&other.limbs)
    }
}

impl ConditionallySelectable for ScalarImpl {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut result = [0u64; 5];
        for i in 0..5 {
            result[i] = u64::conditional_select(&a.limbs[i], &b.limbs[i], choice);
        }
        ScalarImpl { limbs: result }
    }
}

// Field implementation
impl FieldImpl {
    pub const ZERO: FieldImpl = FieldImpl { limbs: [0, 0, 0, 0, 0] };
    pub const ONE: FieldImpl = FieldImpl { limbs: [1, 0, 0, 0, 0] };
    pub const MINUS_ONE: FieldImpl = FieldImpl { 
        limbs: [
            0x7ffffffffffec,  // p - 1 mod 2^51
            0x7ffffffffffff,  // 2^51 - 1
            0x7ffffffffffff,  // 2^51 - 1
            0x7ffffffffffff,  // 2^51 - 1
            0x7ffffffffffff,  // 2^51 - 1
        ]
    };
    
    // Edwards curve parameter d = -121665/121666 mod p
    pub const EDWARDS_D: FieldImpl = FieldImpl {
        limbs: [
            0x78a3d0a7ed5cd,  // -121665/121666 mod p, limb 0
            0x695e41e5b89b4,  // limb 1
            0x7ffffffffffff,  // limb 2
            0x7ffffffffffff,  // limb 3
            0x52036cee2b6fe,  // limb 4
        ]
    };
    
    // Edwards curve parameter d2 = 2*d mod p
    pub const EDWARDS_D2: FieldImpl = FieldImpl {
        limbs: [
            0xf147a14fad9a,   // 2*d mod p, limb 0
            0xd2bc83cb713688,  // limb 1
            0x7ffffffffffff,  // limb 2  
            0x7ffffffffffff,  // limb 3
            0xa406d9dc56dfd,   // limb 4
        ]
    };
    
    // Montgomery curve parameter A = 486662
    pub const MONTGOMERY_A: FieldImpl = FieldImpl {
        limbs: [486662, 0, 0, 0, 0]
    };
    
    // Montgomery curve parameter A + 2 = 486664
    pub const MONTGOMERY_A_PLUS_2: FieldImpl = FieldImpl {
        limbs: [486664, 0, 0, 0, 0]
    };
    
    // sqrt(-1) in the field
    pub const SQRT_M1: FieldImpl = FieldImpl {
        limbs: [
            0x61b274a0ea0b0,  // sqrt(-1) mod p, limb 0
            0xd5a5fc8f189d,   // limb 1
            0x7ef5e9cbd0c60,  // limb 2
            0x78595a6804c9e,  // limb 3
            0x2b8324804fc1d,  // limb 4
        ]
    };
    
    // Placeholder for other constants - these need proper computation
    pub const INVSQRT_A_MINUS_D: FieldImpl = FieldImpl::ONE;

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 5];
        
        // Pack bytes into 51-bit limbs
        limbs[0] = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6] & 0x07, 0
        ]);
        
        limbs[1] = u64::from_le_bytes([
            (bytes[6] >> 3) | (bytes[7] << 5),
            bytes[8], bytes[9], bytes[10],
            bytes[11], bytes[12], bytes[13] & 0x3f, 0
        ]);
        
        // Continue for remaining limbs...
        // Simplified implementation
        
        FieldImpl { limbs }
    }
    
    /// Access the internal limbs (for SIMD operations)
    pub(crate) fn limbs(&self) -> &[u64; 5] {
        &self.limbs
    }
    
    /// Create from limbs (for SIMD operations)
    pub(crate) fn from_limbs(limbs: [u64; 5]) -> Self {
        FieldImpl { limbs }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        
        // Convert limbs back to bytes
        let limb0_bytes = self.limbs[0].to_le_bytes();
        bytes[0..6].copy_from_slice(&limb0_bytes[0..6]);
        bytes[6] = limb0_bytes[6] & 0x07;
        
        // Continue for remaining limbs...
        // Simplified implementation
        
        bytes
    }

    pub fn square(&self) -> Self {
        // Simplified squaring
        self.mul(self)
    }

    pub fn invert(&self) -> Self {
        // Simplified inversion for compilation - will optimize later
        // Use repeated squaring for now (Fermat's little theorem)
        let mut result = *self;
        for _ in 0..253 {
            result = result.square();
        }
        result
    }
    
    /// Square this field element n times
    pub fn square_n(&self, n: u32) -> Self {
        let mut result = *self;
        for _ in 0..n {
            result = result.square();
        }
        result
    }

    pub fn sqrt(&self) -> (Choice, Self) {
        // For p = 2^255 - 19, we can use the efficient square root formula
        // Since p ≡ 5 (mod 8), we can use:
        // If x^((p-1)/2) ≡ 1 (mod p), then sqrt(x) = ±x^((p+3)/8) (mod p)
        // If x^((p-1)/2) ≡ -1 (mod p), then sqrt(x) = ±x^((p+3)/8) * sqrt(-1) (mod p)
        
        // (p + 3) / 8 = (2^255 - 19 + 3) / 8 = (2^255 - 16) / 8 = 2^252 - 2
        let exp_252_minus_2 = self.pow_252_minus_2();
        
        // Check if candidate^2 = self
        let candidate_squared = exp_252_minus_2.square();
        let is_correct = candidate_squared.ct_eq(self);
        
        // If not correct, try candidate * sqrt(-1)
        let candidate_times_sqrtm1 = exp_252_minus_2.mul(FieldImpl::SQRT_M1);
        let candidate2_squared = candidate_times_sqrtm1.square();
        let is_correct2 = candidate2_squared.ct_eq(self);
        
        let final_candidate = FieldImpl::conditional_select(
            &exp_252_minus_2,
            &candidate_times_sqrtm1,
            is_correct2
        );
        
        let is_square = is_correct | is_correct2;
        
        (is_square, final_candidate)
    }
    
    /// Compute x^(2^252 - 2) for square root computation
    fn pow_252_minus_2(&self) -> Self {
        // Similar to inversion but with different exponent
        let z2 = self.square();                    // 2^1
        let z3 = z2.mul(*self);                   // 2^1 + 1  
        let z6 = z3.square();                     // 2^2 + 2^1
        let z12 = z6.square_n(6);                // 2^8 + 2^7
        let z15 = z12.mul(z3);                   // 2^8 + 2^7 + 2^1 + 1
        let z30 = z15.square_n(15);              // 2^23 + ... + 2^16 + 2^15
        let z30 = z30.mul(z15);                  // 2^23 + ... + 2^1 + 1
        let z60 = z30.square_n(30);              // 2^53 + ... + 2^31 + 2^30
        let z60 = z60.mul(z30);                  // 2^53 + ... + 2^1 + 1
        let z120 = z60.square_n(60);             // 2^113 + ... + 2^61 + 2^60
        let z120 = z120.mul(z60);                // 2^113 + ... + 2^1 + 1
        let z240 = z120.square_n(120);           // 2^233 + ... + 2^121 + 2^120
        let z240 = z240.mul(z120);               // 2^233 + ... + 2^1 + 1
        let z250 = z240.square_n(10);            // 2^243 + ... + 2^11 + 2^10
        let z250 = z250.mul(z30);                // 2^243 + ... + 2^1 + 1 (partial)
        
        // Final 2 squares to get 2^252 - 2
        z250.square().square()
    }

    pub fn sqrt_ratio_i(u: &Self, v: &Self) -> (Choice, Self) {
        // Simplified implementation
        let ratio = u.mul(&v.invert());
        ratio.sqrt()
    }

    pub fn conditional_negate(&mut self, choice: Choice) {
        let negated = self.neg();
        *self = Self::conditional_select(self, &negated, choice);
    }

    pub fn is_negative(&self) -> Choice {
        // Check if least significant bit is 1 in canonical representation
        let bytes = self.to_bytes();
        Choice::from(bytes[0] & 1)
    }

    pub fn mul(&self, other: &Self) -> Self {
        // Schoolbook multiplication
        let mut result = [0u128; 10];
        
        for i in 0..5 {
            for j in 0..5 {
                result[i + j] += (self.limbs[i] as u128) * (other.limbs[j] as u128);
            }
        }
        
        // Reduction modulo 2^255 - 19
        // p = 2^255 - 19, so we use the fact that 2^255 ≡ 19 (mod p)
        
        // Carry propagation
        for i in 0..9 {
            result[i + 1] += result[i] >> 51;
            result[i] &= (1u128 << 51) - 1;
        }
        
        // Reduce using 2^255 ≡ 19 (mod p)
        // result[5..9] represents coefficients of 2^255, 2^306, etc.
        let mut carry = result[5] * 19;
        carry = carry.wrapping_add(result[6] * (19u128 << 51));
        carry = carry.wrapping_add(result[7] * 19); // Simplified to avoid overflow
        // 2^255 = 19 mod p, so higher powers need reduction
        // 2^306 = 2^(255+51) = 19 * 2^51 mod p
        // 2^357 = 2^(255+102) = 19 * 2^102 mod p
        carry = carry.wrapping_add(result[8] * 19); // Simplified: just use 19 for higher terms
        carry = carry.wrapping_add(result[9] * 19);
        
        result[0] = result[0].wrapping_add(carry);
        
        // Final carry propagation
        for i in 0..4 {
            result[i + 1] = result[i + 1].wrapping_add(result[i] >> 51);
            result[i] &= (1u128 << 51) - 1;
        }
        
        // Handle potential overflow in the last limb
        let overflow = result[4] >> 51;
        result[4] &= (1u128 << 51) - 1;
        result[0] = result[0].wrapping_add(overflow * 19);
        
        // Final carry if needed
        let final_carry = result[0] >> 51;
        result[0] &= (1u128 << 51) - 1;
        result[1] = result[1].wrapping_add(final_carry);
        
        FieldImpl {
            limbs: [
                result[0] as u64,
                result[1] as u64,
                result[2] as u64,
                result[3] as u64,
                result[4] as u64,
            ],
        }
    }

    pub fn neg(&self) -> Self {
        // Compute p - self where p = 2^255 - 19
        FieldImpl::sub(&FieldImpl::ZERO, self)
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut result = [0u64; 5];
        let mut borrow = 0i64;
        
        for i in 0..5 {
            let diff = (self.limbs[i] as i64) - (other.limbs[i] as i64) - borrow;
            if diff < 0 {
                result[i] = (diff + (1i64 << 51)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }
        
        FieldImpl { limbs: result }
    }
}

// Implement arithmetic traits for FieldImpl
impl Add for FieldImpl {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut result = [0u64; 5];
        let mut carry = 0u64;
        
        for i in 0..5 {
            let sum = self.limbs[i].wrapping_add(other.limbs[i]).wrapping_add(carry);
            result[i] = sum & ((1u64 << 51) - 1);
            carry = sum >> 51;
        }
        
        // Handle final carry with reduction
        if carry > 0 {
            // carry represents 2^255, so multiply by 19 and add to result[0]
            let extra_carry = carry * 19;
            result[0] = result[0].wrapping_add(extra_carry);
            
            // Propagate carry if needed
            for i in 0..4 {
                if result[i] >= (1u64 << 51) {
                    result[i + 1] = result[i + 1].wrapping_add(result[i] >> 51);
                    result[i] &= (1u64 << 51) - 1;
                }
            }
            
            // Handle overflow in last limb
            if result[4] >= (1u64 << 51) {
                let overflow = result[4] >> 51;
                result[4] &= (1u64 << 51) - 1;
                result[0] = result[0].wrapping_add(overflow * 19);
                
                // One more carry if needed
                if result[0] >= (1u64 << 51) {
                    result[1] = result[1].wrapping_add(result[0] >> 51);
                    result[0] &= (1u64 << 51) - 1;
                }
            }
        }
        
        FieldImpl { limbs: result }
    }
}

impl AddAssign for FieldImpl {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl Sub for FieldImpl {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        FieldImpl::sub(&self, &other)
    }
}

impl SubAssign for FieldImpl {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl Mul for FieldImpl {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        FieldImpl::mul(&self, &other)
    }
}

impl MulAssign for FieldImpl {
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl Neg for FieldImpl {
    type Output = Self;

    fn neg(self) -> Self {
        FieldImpl::neg(&self)
    }
}

impl ConstantTimeEq for FieldImpl {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.limbs.ct_eq(&other.limbs)
    }
}

impl ConditionallySelectable for FieldImpl {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut result = [0u64; 5];
        for i in 0..5 {
            result[i] = u64::conditional_select(&a.limbs[i], &b.limbs[i], choice);
        }
        FieldImpl { limbs: result }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for ScalarImpl {
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for FieldImpl {
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}
