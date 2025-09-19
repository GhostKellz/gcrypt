//! Zero-Knowledge Proof Primitives
//!
//! This module provides fundamental building blocks for zero-knowledge
//! proof systems, including commitments, polynomial operations, and
//! constraint systems.

use crate::{Scalar, EdwardsPoint};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Error types for zero-knowledge operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkError {
    /// Invalid proof
    InvalidProof,
    /// Proof verification failed
    VerificationFailed,
    /// Invalid circuit
    InvalidCircuit,
    /// Missing witness
    MissingWitness,
    /// Constraint system error
    ConstraintSystemError,
    /// Setup error
    SetupError,
    /// Serialization error
    SerializationError,
    /// Invalid parameters
    InvalidParameters,
}

/// Trait for constraint systems used in zero-knowledge proofs
pub trait ConstraintSystem {
    /// Type representing field elements
    type Field;
    /// Type representing variables
    type Variable;

    /// Allocate a new variable
    fn alloc_input<F>(&mut self, f: F) -> Result<Self::Variable, ZkError>
    where
        F: FnOnce() -> Result<Self::Field, ZkError>;

    /// Allocate a private witness variable
    fn alloc<F>(&mut self, f: F) -> Result<Self::Variable, ZkError>
    where
        F: FnOnce() -> Result<Self::Field, ZkError>;

    /// Enforce a constraint: a * b = c
    fn enforce<A, B, C>(&mut self, a: A, b: B, c: C) -> Result<(), ZkError>
    where
        A: Into<LinearCombination<Self::Field>>,
        B: Into<LinearCombination<Self::Field>>,
        C: Into<LinearCombination<Self::Field>>;

    /// Get the number of constraints
    fn num_constraints(&self) -> usize;
}

/// Linear combination of variables and constants
#[derive(Debug, Clone)]
pub struct LinearCombination<F> {
    /// Terms in the linear combination
    pub terms: Vec<(F, Variable)>,
    /// Constant term
    pub constant: F,
}

/// Variable in a constraint system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Variable(pub usize);

impl Variable {
    /// Create a new variable
    pub fn new(index: usize) -> Self {
        Self(index)
    }

    /// Get variable index
    pub fn index(&self) -> usize {
        self.0
    }
}

/// Trait for circuits that can be compiled to constraint systems
pub trait Circuit<F> {
    /// Synthesize the circuit into a constraint system
    fn synthesize<CS: ConstraintSystem<Field = F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), ZkError>;
}

/// Polynomial commitment scheme
pub trait PolynomialCommitment {
    /// Type for polynomials
    type Polynomial;
    /// Type for commitments
    type Commitment;
    /// Type for proofs
    type Proof;
    /// Type for evaluation points
    type Point;
    /// Type for values
    type Value;

    /// Commit to a polynomial
    fn commit(&self, polynomial: &Self::Polynomial) -> Result<Self::Commitment, ZkError>;

    /// Open a commitment at a specific point
    fn open(
        &self,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Value, Self::Proof), ZkError>;

    /// Verify an opening proof
    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &Self::Value,
        proof: &Self::Proof,
    ) -> Result<bool, ZkError>;
}

/// Polynomial operations over finite fields
#[derive(Debug, Clone)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Polynomial {
    /// Polynomial coefficients (from constant to highest degree)
    pub coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Create a new polynomial from coefficients
    pub fn new(coefficients: Vec<Scalar>) -> Self {
        Self { coefficients }
    }

    /// Create a zero polynomial
    pub fn zero() -> Self {
        Self {
            coefficients: vec![Scalar::ZERO],
        }
    }

    /// Create a constant polynomial
    pub fn constant(value: Scalar) -> Self {
        Self {
            coefficients: vec![value],
        }
    }

    /// Get the degree of the polynomial
    pub fn degree(&self) -> usize {
        if self.coefficients.is_empty() {
            0
        } else {
            self.coefficients.len() - 1
        }
    }

    /// Evaluate the polynomial at a given point
    pub fn evaluate(&self, x: &Scalar) -> Scalar {
        if self.coefficients.is_empty() {
            return Scalar::ZERO;
        }

        // Horner's method
        let mut result = self.coefficients[self.coefficients.len() - 1];
        for coeff in self.coefficients.iter().rev().skip(1) {
            result = result * x + coeff;
        }
        result
    }

    /// Add two polynomials
    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.coefficients.len().max(other.coefficients.len());
        let mut result = vec![Scalar::ZERO; max_len];

        for (i, coeff) in self.coefficients.iter().enumerate() {
            result[i] = result[i] + coeff;
        }

        for (i, coeff) in other.coefficients.iter().enumerate() {
            result[i] = result[i] + coeff;
        }

        Self::new(result)
    }

    /// Multiply polynomial by a scalar
    pub fn scalar_mul(&self, scalar: &Scalar) -> Self {
        let coefficients = self.coefficients.iter()
            .map(|coeff| coeff * scalar)
            .collect();
        Self::new(coefficients)
    }
}

/// Simple constraint system implementation for testing
#[derive(Debug)]
pub struct SimpleConstraintSystem {
    /// Number of variables
    pub num_vars: usize,
    /// Constraints in the system
    pub constraints: Vec<(LinearCombination<Scalar>, LinearCombination<Scalar>, LinearCombination<Scalar>)>,
    /// Variable assignments (for testing)
    pub assignments: Vec<Option<Scalar>>,
}

impl SimpleConstraintSystem {
    /// Create a new constraint system
    pub fn new() -> Self {
        Self {
            num_vars: 0,
            constraints: Vec::new(),
            assignments: Vec::new(),
        }
    }

    /// Check if all constraints are satisfied
    pub fn is_satisfied(&self) -> bool {
        for (a, b, c) in &self.constraints {
            let a_val = self.evaluate_lc(a);
            let b_val = self.evaluate_lc(b);
            let c_val = self.evaluate_lc(c);

            if a_val * b_val != c_val {
                return false;
            }
        }
        true
    }

    /// Evaluate a linear combination
    fn evaluate_lc(&self, lc: &LinearCombination<Scalar>) -> Scalar {
        let mut result = lc.constant;
        for (coeff, var) in &lc.terms {
            if let Some(val) = self.assignments.get(var.0).and_then(|x| *x) {
                result = result + (*coeff * val);
            }
        }
        result
    }
}

impl Default for SimpleConstraintSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintSystem for SimpleConstraintSystem {
    type Field = Scalar;
    type Variable = Variable;

    fn alloc_input<F>(&mut self, f: F) -> Result<Self::Variable, ZkError>
    where
        F: FnOnce() -> Result<Self::Field, ZkError>,
    {
        let var = Variable::new(self.num_vars);
        self.num_vars += 1;

        let value = f()?;
        self.assignments.push(Some(value));

        Ok(var)
    }

    fn alloc<F>(&mut self, f: F) -> Result<Self::Variable, ZkError>
    where
        F: FnOnce() -> Result<Self::Field, ZkError>,
    {
        let var = Variable::new(self.num_vars);
        self.num_vars += 1;

        let value = f().ok();
        self.assignments.push(value);

        Ok(var)
    }

    fn enforce<A, B, C>(&mut self, a: A, b: B, c: C) -> Result<(), ZkError>
    where
        A: Into<LinearCombination<Self::Field>>,
        B: Into<LinearCombination<Self::Field>>,
        C: Into<LinearCombination<Self::Field>>,
    {
        self.constraints.push((a.into(), b.into(), c.into()));
        Ok(())
    }

    fn num_constraints(&self) -> usize {
        self.constraints.len()
    }
}

impl<F> From<Variable> for LinearCombination<F>
where
    F: Clone + From<u64>,
{
    fn from(var: Variable) -> Self {
        Self {
            terms: vec![(F::from(1), var)],
            constant: F::from(0),
        }
    }
}

impl<F> From<F> for LinearCombination<F>
where
    F: Clone,
{
    fn from(constant: F) -> Self {
        Self {
            terms: Vec::new(),
            constant,
        }
    }
}

/// Utilities for zero-knowledge proofs
pub mod utils {
    use super::*;

    /// Generate a random polynomial of given degree
    #[cfg(feature = "rand_core")]
    pub fn random_polynomial<R: rand_core::RngCore + rand_core::CryptoRng>(
        degree: usize,
        rng: &mut R,
    ) -> Polynomial {
        let coefficients = (0..=degree)
            .map(|_| Scalar::random(rng))
            .collect();
        Polynomial::new(coefficients)
    }

    /// Check if a polynomial is zero
    pub fn is_zero_polynomial(poly: &Polynomial) -> bool {
        poly.coefficients.iter().all(|c| c.is_zero())
    }

    /// Interpolate a polynomial from points
    pub fn lagrange_interpolation(points: &[(Scalar, Scalar)]) -> Result<Polynomial, ZkError> {
        if points.is_empty() {
            return Ok(Polynomial::zero());
        }

        let mut result = Polynomial::zero();

        for (i, (xi, yi)) in points.iter().enumerate() {
            let mut li = Polynomial::constant(Scalar::ONE);

            // Compute Lagrange basis polynomial
            for (j, (xj, _)) in points.iter().enumerate() {
                if i != j {
                    let denominator = (*xi - *xj).invert()
                        .ok_or(ZkError::InvalidParameters)?;

                    // li *= (x - xj) / (xi - xj)
                    let numerator_poly = Polynomial::new(vec![-*xj, Scalar::ONE]);
                    li = multiply_polynomials(&li, &numerator_poly.scalar_mul(&denominator));
                }
            }

            // Add yi * li to result
            result = result.add(&li.scalar_mul(yi));
        }

        Ok(result)
    }

    /// Multiply two polynomials
    pub fn multiply_polynomials(a: &Polynomial, b: &Polynomial) -> Polynomial {
        if a.coefficients.is_empty() || b.coefficients.is_empty() {
            return Polynomial::zero();
        }

        let degree = a.degree() + b.degree();
        let mut coefficients = vec![Scalar::ZERO; degree + 1];

        for (i, a_coeff) in a.coefficients.iter().enumerate() {
            for (j, b_coeff) in b.coefficients.iter().enumerate() {
                coefficients[i + j] = coefficients[i + j] + (*a_coeff * *b_coeff);
            }
        }

        Polynomial::new(coefficients)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_evaluation() {
        // Test polynomial: 3 + 2x + x^2
        let poly = Polynomial::new(vec![
            Scalar::from_u64(3),
            Scalar::from_u64(2),
            Scalar::ONE,
        ]);

        // Evaluate at x = 2: 3 + 2*2 + 2^2 = 11
        let x = Scalar::from_u64(2);
        let result = poly.evaluate(&x);
        let expected = Scalar::from_u64(11);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_polynomial_addition() {
        let poly1 = Polynomial::new(vec![Scalar::ONE, Scalar::from_u64(2)]);
        let poly2 = Polynomial::new(vec![Scalar::from_u64(3), Scalar::ONE]);

        let result = poly1.add(&poly2);
        let expected = Polynomial::new(vec![Scalar::from_u64(4), Scalar::from_u64(3)]);

        assert_eq!(result.coefficients, expected.coefficients);
    }

    #[test]
    fn test_simple_constraint_system() {
        let mut cs = SimpleConstraintSystem::new();

        // Allocate variables: x = 3, y = 4
        let x = cs.alloc_input(|| Ok(Scalar::from_u64(3))).unwrap();
        let y = cs.alloc_input(|| Ok(Scalar::from_u64(4))).unwrap();
        let z = cs.alloc(|| Ok(Scalar::from_u64(12))).unwrap();

        // Enforce constraint: x * y = z
        cs.enforce(x, y, z).unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 1);
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_lagrange_interpolation() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        // Test with known polynomial: f(x) = x^2
        let points = vec![
            (Scalar::ZERO, Scalar::ZERO),
            (Scalar::ONE, Scalar::ONE),
            (Scalar::from_u64(2), Scalar::from_u64(4)),
        ];

        let poly = utils::lagrange_interpolation(&points).unwrap();

        // Verify interpolation by checking a different point
        let x = Scalar::from_u64(3);
        let result = poly.evaluate(&x);
        let expected = Scalar::from_u64(9); // 3^2 = 9

        assert_eq!(result, expected);
    }
}