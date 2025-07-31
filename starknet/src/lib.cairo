use starknet::ContractAddress;

pub mod hashlock;
pub mod timelock;
pub mod merkle_validator;
pub mod interactions;
pub mod escrow_base;
pub mod escrow_src;
pub mod escrow_dst;
pub mod escrow_factory;


// Common types and structures
#[derive(Drop, Serde, Copy, starknet::Store)]
pub struct Immutables {
    pub maker: ContractAddress,
    pub taker: ContractAddress,
    pub token: ContractAddress,
    pub amount: u256,
    pub hashlock: u256,
    pub timelocks: u256,
    pub dst_escrow_factory: ContractAddress,
    pub src_escrow_factory: ContractAddress,
}

#[derive(Drop, Serde)]
pub struct Order {
    pub salt: felt252,
    pub maker: ContractAddress,
    pub receiver: ContractAddress,
    pub maker_asset: ContractAddress,
    pub taker_asset: ContractAddress,
    pub making_amount: u256,
    pub taking_amount: u256,
    pub maker_traits: u256,
}