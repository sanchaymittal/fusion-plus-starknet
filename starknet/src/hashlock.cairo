//! Hashlock functionality for atomic swaps
//! Validates secrets against pre-committed hashes

use core::array::ArrayTrait;
use core::keccak::keccak_u256s_be_inputs;
use core::integer::u256; // Import u256 for hash values

// Computes the Keccak-256 hash of a felt252 secret.
// The secret is treated as a single u256 value for hashing.
pub fn keccak_bytes32(secret: felt252) -> u256 {
    let mut input = ArrayTrait::new();
    // Convert felt252 to u256 as keccak_u256s_be_inputs expects Span<u256>.
    input.append(secret.into());
    keccak_u256s_be_inputs(input.span())
}

// Validates a secret by hashing it and comparing with an expected hash.
pub fn validate_secret(secret: felt252, expected_hash: u256) -> bool {
    keccak_bytes32(secret) == expected_hash
}

#[derive(Drop, Serde)]
pub struct HashlockValidator {
    pub hash_value: u256, // Hash values are now u256
}

// Define the trait for HashlockValidator functionality explicitly.
// #[generate_trait] is not used in Cairo 2.0; traits are defined directly.
pub trait HashlockValidatorTrait {
    fn new(hash_value: u256) -> HashlockValidator;
    fn validate(self: @HashlockValidator, secret: felt252) -> bool;
    fn get_hash(self: @HashlockValidator) -> u256;
}

// Implement the HashlockValidatorTrait for HashlockValidator.
pub impl HashlockValidatorImpl of HashlockValidatorTrait {
    fn new(hash_value: u256) -> HashlockValidator {
        HashlockValidator { hash_value }
    }
    
    fn validate(self: @HashlockValidator, secret: felt252) -> bool {
        validate_secret(secret, *self.hash_value)
    }
    
    fn get_hash(self: @HashlockValidator) -> u256 {
        *self.hash_value
    }
}

// Error definitions
pub mod Errors {
    pub const INVALID_SECRET: felt252 = 'Invalid secret provided';
}