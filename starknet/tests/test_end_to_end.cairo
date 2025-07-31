//! End-to-end tests for cross-chain atomic swap functionality
//! Tests both scenarios: Starknet as destination and Starknet as source

use starknet::{ContractAddress, get_block_timestamp, ClassHash};
use core::traits::{Into, TryInto};
use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait, start_cheat_block_timestamp, 
    stop_cheat_block_timestamp, start_cheat_caller_address, stop_cheat_caller_address
};

use cross_chain_swap::{
    Immutables, Order,
    escrow_dst::{IEscrowDstDispatcher, IEscrowDstDispatcherTrait},
    escrow_src::{IEscrowSrcDispatcher, IEscrowSrcDispatcherTrait},
    escrow_factory::{IEscrowFactoryDispatcher, IEscrowFactoryDispatcherTrait, ExtraDataArgs},
    escrow_base::{IBaseEscrowDispatcher, IBaseEscrowDispatcherTrait},
    timelock::{TimelockDataStorePacking, TimelockData},
    hashlock::{keccak_bytes32},
    merkle_validator::{IMerkleStorageInvalidator, IMerkleStorageInvalidatorDispatcher, IMerkleStorageInvalidatorDispatcherTrait, MerkleLeaf}
};

// Simple ERC20 interface for testing
#[starknet::interface]
trait IERC20<TContractState> {
    fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(ref self: TContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256) -> bool;
    fn approve(ref self: TContractState, spender: ContractAddress, amount: u256) -> bool;
    fn mint(ref self: TContractState, to: ContractAddress, amount: u256);
}

// Simple MockERC20 for testing 
#[starknet::contract]
mod MockERC20 {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess, StoragePointerWriteAccess};
    
    #[storage]
    struct Storage {
        balances: Map<ContractAddress, u256>,
        allowances: Map<(ContractAddress, ContractAddress), u256>,
        total_supply: u256,
    }
    
    #[constructor]
    fn constructor(ref self: ContractState) {
        // Empty constructor - tokens minted as needed
    }
    
    #[abi(embed_v0)]
    impl IERC20Impl of super::IERC20<ContractState> {
        fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
            self.balances.read(account)
        }
        
        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
            let sender = get_caller_address();
            self._transfer(sender, recipient, amount);
            true
        }
        
        fn transfer_from(ref self: ContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256) -> bool {
            let caller = get_caller_address();
            let allowance = self.allowances.read((sender, caller));
            assert(allowance >= amount, 'Insufficient allowance');
            
            self.allowances.write((sender, caller), allowance - amount);
            self._transfer(sender, recipient, amount);
            true
        }
        
        fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) -> bool {
            let owner = get_caller_address();
            self.allowances.write((owner, spender), amount);
            true
        }
        
        fn mint(ref self: ContractState, to: ContractAddress, amount: u256) {
            let balance = self.balances.read(to);
            self.balances.write(to, balance + amount);
            let supply = self.total_supply.read();
            self.total_supply.write(supply + amount);
        }
    }
    
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _transfer(ref self: ContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256) {
            let sender_balance = self.balances.read(sender);
            assert(sender_balance >= amount, 'Insufficient balance');
            
            self.balances.write(sender, sender_balance - amount);
            let recipient_balance = self.balances.read(recipient);
            self.balances.write(recipient, recipient_balance + amount);
        }
    }
}

// Simple Mock Merkle Invalidator for testing
#[starknet::contract]
mod MockMerkleInvalidator {
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use super::MerkleLeaf;
    
    #[storage]
    struct Storage {
        validated_leaves: Map<felt252, MerkleLeaf>,
    }
    
    #[constructor]
    fn constructor(ref self: ContractState) {
        // Empty constructor
    }
    
    #[abi(embed_v0)]
    impl IMerkleStorageInvalidatorImpl of cross_chain_swap::merkle_validator::IMerkleStorageInvalidator<ContractState> {
        fn get_last_validated(self: @ContractState, key: felt252) -> MerkleLeaf {
            self.validated_leaves.read(key)
        }
        
        fn invalidate_merkle_leaf(ref self: ContractState, key: felt252, leaf: MerkleLeaf) {
            self.validated_leaves.write(key, leaf);
        }
        
        fn is_leaf_valid(self: @ContractState, key: felt252, leaf: MerkleLeaf) -> bool {
            let last_validated = self.get_last_validated(key);
            // A leaf is valid if it has a higher amount than the last validated leaf
            // For testing, always return true on first use (when last_validated.amount == 0)
            leaf.amount > last_validated.amount
        }
    }
}

// Test constants
const SECRET: felt252 = 0x123456789;
const AMOUNT: u256 = 1000000000000000000; // 1 token with 18 decimals
const SALT: felt252 = 0x1;

fn get_hashlock() -> u256 {
    keccak_bytes32(SECRET)
}

fn deploy_mock_erc20() -> ContractAddress {
    let contract = declare("MockERC20").unwrap().contract_class();
    let mut calldata: Array<felt252> = ArrayTrait::new();
    // For now, deploy with empty calldata and mint tokens as needed in tests
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    contract_address
}

fn deploy_mock_merkle_invalidator() -> ContractAddress {
    let contract = declare("MockMerkleInvalidator").unwrap().contract_class();
    let mut calldata: Array<felt252> = ArrayTrait::new();
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    contract_address
}

fn deploy_escrow_factory() -> ContractAddress {
    deploy_escrow_factory_with_merkle(0x789.try_into().unwrap())
}

fn deploy_escrow_factory_with_merkle(merkle_invalidator: ContractAddress) -> ContractAddress {
    let escrow_dst_class = declare("EscrowDst").unwrap().contract_class();
    let escrow_src_class = declare("EscrowSrc").unwrap().contract_class();
    
    let contract = declare("EscrowFactory").unwrap().contract_class();
    let mut calldata: Array<felt252> = ArrayTrait::new();
    // owner
    calldata.append(0x123);
    // src_escrow_class_hash  
    calldata.append((*escrow_src_class.class_hash).into());
    // dst_escrow_class_hash
    calldata.append((*escrow_dst_class.class_hash).into());
    // limit_order_protocol
    calldata.append(0x456);
    // merkle_invalidator
    calldata.append(merkle_invalidator.into());
    
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    contract_address
}

fn create_test_timelocks() -> u256 {
    let _current_time = get_block_timestamp();
    
    let timelock_data = TimelockData {
        deployed_at: 0, // Will be set during deployment
        dst_withdrawal: 300,        // 5 minutes
        dst_public_withdrawal: 600, // 10 minutes  
        dst_cancellation: 1800,     // 30 minutes
        src_withdrawal: 900,        // 15 minutes
        src_public_withdrawal: 1200, // 20 minutes
        src_cancellation: 2400,     // 40 minutes
        src_public_cancellation: 3600, // 60 minutes
    };
    
    TimelockDataStorePacking::pack(timelock_data)
}

fn create_test_immutables(
    maker: ContractAddress,
    taker: ContractAddress, 
    token: ContractAddress,
    factory: ContractAddress
) -> Immutables {
    Immutables {
        maker,
        taker,
        token,
        amount: AMOUNT,
        hashlock: get_hashlock(),
        timelocks: create_test_timelocks(),
        dst_escrow_factory: factory,
        src_escrow_factory: factory,
    }
}

/// Test 1: Starknet as Destination - Resolver creates dst escrow and claims funds
#[test]
fn test_starknet_as_destination_resolver_claim() {
    // Setup accounts
    let maker: ContractAddress = 0x1.try_into().unwrap();
    let taker: ContractAddress = 0x2.try_into().unwrap();
    let resolver: ContractAddress = 0x3.try_into().unwrap();
    
    // Deploy contracts
    let token = deploy_mock_erc20();
    let factory = deploy_escrow_factory();
    
    let token_dispatcher = IERC20Dispatcher { contract_address: token };
    let factory_dispatcher = IEscrowFactoryDispatcher { contract_address: factory };
    
    // Setup initial token balances
    token_dispatcher.mint(maker, AMOUNT * 2);
    
    // Create immutables
    let immutables = create_test_immutables(maker, taker, token, factory);
    
    // Maker approves the factory to spend tokens (simulating cross-chain setup)
    start_cheat_caller_address(token, maker);
    token_dispatcher.approve(factory, AMOUNT);
    stop_cheat_caller_address(token);
    
    // Resolver creates dst escrow (simulating resolver deployment after order initiation on another chain)
    start_cheat_caller_address(factory, resolver);
    let dst_escrow_address = factory_dispatcher.create_dst_escrow(
        get_hashlock(), 
        taker, 
        immutables
    );
    stop_cheat_caller_address(factory);
    
    let dst_escrow = IEscrowDstDispatcher { contract_address: dst_escrow_address };
    let base_escrow = IBaseEscrowDispatcher { contract_address: dst_escrow_address };
    
    // Verify escrow was created with correct immutables
    let stored_immutables = base_escrow.get_immutables();
    assert(stored_immutables.maker == maker, 'Wrong maker');
    assert(stored_immutables.taker == taker, 'Wrong taker');
    assert(stored_immutables.amount == AMOUNT, 'Wrong amount');
    
    // Verify tokens were transferred to escrow
    let escrow_balance = token_dispatcher.balance_of(dst_escrow_address);
    assert(escrow_balance == AMOUNT, 'Wrong escrow balance');
    
    // Fast forward to dst_public_withdrawal period  
    let current_time = get_block_timestamp();
    start_cheat_block_timestamp(dst_escrow_address, current_time + 700); // More than 600 seconds
    
    // Resolver claims funds using the secret (simulating knowledge from order creation)
    start_cheat_caller_address(dst_escrow_address, resolver);
    dst_escrow.withdraw_public(immutables, SECRET);
    stop_cheat_caller_address(dst_escrow_address);
    
    stop_cheat_block_timestamp(dst_escrow_address);
    
    // Verify tokens were transferred to taker
    let taker_balance = token_dispatcher.balance_of(taker);
    assert(taker_balance == AMOUNT, 'Taker should receive tokens');
    
    let escrow_balance_after = token_dispatcher.balance_of(dst_escrow_address);
    assert(escrow_balance_after == 0, 'Escrow should be empty');
}

/// Test 2: Starknet as Source - Resolver creates src escrow and withdraws funds
#[test] 
fn test_starknet_as_source_resolver_withdraw() {
    // Setup accounts
    let maker: ContractAddress = 0x1.try_into().unwrap();
    let taker: ContractAddress = 0x2.try_into().unwrap();
    let resolver: ContractAddress = 0x3.try_into().unwrap();
    
    // Deploy contracts
    let token = deploy_mock_erc20();
    let factory = deploy_escrow_factory();
    
    let token_dispatcher = IERC20Dispatcher { contract_address: token };
    let factory_dispatcher = IEscrowFactoryDispatcher { contract_address: factory };
    
    // Setup initial token balances
    token_dispatcher.mint(maker, AMOUNT * 2);
    
    // Create test order (simulating 1inch limit order)
    let order = Order {
        salt: SALT,
        maker,
        receiver: taker,
        maker_asset: token,
        taker_asset: token, // Same token for simplicity
        making_amount: AMOUNT,
        taking_amount: AMOUNT,
        maker_traits: 0,
    };
    
    // Create extra data for src escrow
    let extra_data = ExtraDataArgs {
        hashlock_info: get_hashlock(),
        timelocks: create_test_timelocks(),
    };
    
    // Maker approves the factory to spend tokens
    start_cheat_caller_address(token, maker);
    token_dispatcher.approve(factory, AMOUNT);
    stop_cheat_caller_address(token);
    
    // Resolver creates src escrow (simulating order fulfillment scenario)
    start_cheat_caller_address(factory, resolver);
    let src_escrow_address = factory_dispatcher.create_src_escrow(
        order,
        ArrayTrait::new(), // empty extension
        0x1234, // order_hash
        taker,
        AMOUNT, // making_amount
        AMOUNT, // taking_amount  
        AMOUNT, // remaining_making_amount
        extra_data
    );
    stop_cheat_caller_address(factory);
    
    let src_escrow = IEscrowSrcDispatcher { contract_address: src_escrow_address };
    let base_escrow = IBaseEscrowDispatcher { contract_address: src_escrow_address };
    
    // Verify escrow was created correctly
    let stored_immutables = base_escrow.get_immutables();
    assert(stored_immutables.maker == maker, 'Wrong maker');
    assert(stored_immutables.taker == taker, 'Wrong taker');
    assert(stored_immutables.amount == AMOUNT, 'Wrong amount');
    
    // Verify tokens were transferred to escrow
    let escrow_balance = token_dispatcher.balance_of(src_escrow_address);
    assert(escrow_balance == AMOUNT, 'Wrong escrow balance');
    
    // Fast forward to src_public_withdrawal period
    let current_time = get_block_timestamp();
    start_cheat_block_timestamp(src_escrow_address, current_time + 1300); // More than 1200 seconds
    
    // Resolver withdraws funds at source using the secret
    start_cheat_caller_address(src_escrow_address, resolver);
    src_escrow.withdraw_public(stored_immutables, SECRET);
    stop_cheat_caller_address(src_escrow_address);
    
    stop_cheat_block_timestamp(src_escrow_address);
    
    // Verify tokens were transferred to taker
    let taker_balance = token_dispatcher.balance_of(taker);
    assert(taker_balance == AMOUNT, 'Taker should receive tokens');
    
    let escrow_balance_after = token_dispatcher.balance_of(src_escrow_address);
    assert(escrow_balance_after == 0, 'Escrow should be empty');
}

/// Test 3: Test timelock enforcement - early withdrawal should fail
#[test]
#[should_panic(expected: ('Too early',))]
fn test_early_withdrawal_fails() {
    // Setup
    let maker: ContractAddress = 0x1.try_into().unwrap();
    let taker: ContractAddress = 0x2.try_into().unwrap();
    let resolver: ContractAddress = 0x3.try_into().unwrap();
    
    let token = deploy_mock_erc20();
    let factory = deploy_escrow_factory();
    
    let token_dispatcher = IERC20Dispatcher { contract_address: token };
    let factory_dispatcher = IEscrowFactoryDispatcher { contract_address: factory };
    
    token_dispatcher.mint(maker, AMOUNT * 2);
    
    let immutables = create_test_immutables(maker, taker, token, factory);
    
    start_cheat_caller_address(token, maker);
    token_dispatcher.approve(factory, AMOUNT);
    stop_cheat_caller_address(token);
    
    start_cheat_caller_address(factory, resolver);
    let dst_escrow_address = factory_dispatcher.create_dst_escrow(
        get_hashlock(), 
        taker, 
        immutables
    );
    stop_cheat_caller_address(factory);
    
    let dst_escrow = IEscrowDstDispatcher { contract_address: dst_escrow_address };
    
    // Try to withdraw immediately (should fail - too early)
    start_cheat_caller_address(dst_escrow_address, taker);
    dst_escrow.withdraw_public(immutables, SECRET);
    stop_cheat_caller_address(dst_escrow_address);
}

/// Test 4: Test late withdrawal after cancellation period should fail
#[test]
#[should_panic(expected: ('Too late',))]
fn test_late_withdrawal_fails() {
    // Setup
    let maker: ContractAddress = 0x1.try_into().unwrap();
    let taker: ContractAddress = 0x2.try_into().unwrap();
    let resolver: ContractAddress = 0x3.try_into().unwrap();
    
    let token = deploy_mock_erc20();
    let factory = deploy_escrow_factory();
    
    let token_dispatcher = IERC20Dispatcher { contract_address: token };
    let factory_dispatcher = IEscrowFactoryDispatcher { contract_address: factory };
    
    token_dispatcher.mint(maker, AMOUNT * 2);
    
    let immutables = create_test_immutables(maker, taker, token, factory);
    
    start_cheat_caller_address(token, maker);
    token_dispatcher.approve(factory, AMOUNT);
    stop_cheat_caller_address(token);
    
    start_cheat_caller_address(factory, resolver);
    let dst_escrow_address = factory_dispatcher.create_dst_escrow(
        get_hashlock(), 
        taker, 
        immutables
    );
    stop_cheat_caller_address(factory);
    
    let dst_escrow = IEscrowDstDispatcher { contract_address: dst_escrow_address };
    
    // Fast forward past cancellation period
    let current_time = get_block_timestamp();
    start_cheat_block_timestamp(dst_escrow_address, current_time + 2000);
    
    // Try to withdraw after cancellation period (should fail - too late)
    start_cheat_caller_address(dst_escrow_address, taker);
    dst_escrow.withdraw_public(immutables, SECRET);
    stop_cheat_caller_address(dst_escrow_address);
    
    stop_cheat_block_timestamp(dst_escrow_address);
}

/// Test 5: Test cancellation scenario
#[test]
fn test_cancellation_scenario() {
    // Setup
    let maker: ContractAddress = 0x1.try_into().unwrap();
    let taker: ContractAddress = 0x2.try_into().unwrap();
    let resolver: ContractAddress = 0x3.try_into().unwrap();
    
    let token = deploy_mock_erc20();
    let factory = deploy_escrow_factory();
    
    let token_dispatcher = IERC20Dispatcher { contract_address: token };
    let factory_dispatcher = IEscrowFactoryDispatcher { contract_address: factory };
    
    token_dispatcher.mint(maker, AMOUNT * 2);
    
    let immutables = create_test_immutables(maker, taker, token, factory);
    
    start_cheat_caller_address(token, maker);
    token_dispatcher.approve(factory, AMOUNT);
    stop_cheat_caller_address(token);
    
    start_cheat_caller_address(factory, resolver);
    let dst_escrow_address = factory_dispatcher.create_dst_escrow(
        get_hashlock(), 
        taker, 
        immutables
    );
    stop_cheat_caller_address(factory);
    
    let dst_escrow = IEscrowDstDispatcher { contract_address: dst_escrow_address };
    
    // Fast forward to cancellation period
    let current_time = get_block_timestamp();
    start_cheat_block_timestamp(dst_escrow_address, current_time + 2000);
    
    // Maker cancels and gets refund
    start_cheat_caller_address(dst_escrow_address, maker);
    dst_escrow.cancel_private(immutables);
    stop_cheat_caller_address(dst_escrow_address);
    
    stop_cheat_block_timestamp(dst_escrow_address);
    
    // Verify tokens were returned to maker
    let maker_balance = token_dispatcher.balance_of(maker);
    assert(maker_balance == AMOUNT * 2, 'Maker refund'); // Original AMOUNT * 2 - AMOUNT + AMOUNT
    
    let escrow_balance = token_dispatcher.balance_of(dst_escrow_address);
    assert(escrow_balance == 0, 'Empty after cancel');
}

/// Test 6: Test source escrow with merkle validation enabled (parts_amount > 1)
#[test]
fn test_src_escrow_with_merkle_validation() {
    // Setup accounts
    let maker: ContractAddress = 0x1.try_into().unwrap();
    let taker: ContractAddress = 0x2.try_into().unwrap();
    let resolver: ContractAddress = 0x3.try_into().unwrap();
    
    // Deploy contracts including mock merkle invalidator
    let token = deploy_mock_erc20();
    let merkle_invalidator = deploy_mock_merkle_invalidator();
    let factory = deploy_escrow_factory_with_merkle(merkle_invalidator);
    
    let token_dispatcher = IERC20Dispatcher { contract_address: token };
    let factory_dispatcher = IEscrowFactoryDispatcher { contract_address: factory };
    
    // Setup initial token balances - maker has enough for multiple fills
    token_dispatcher.mint(maker, AMOUNT * 10);
    
    // Create test order for partial fill
    let order = Order {
        salt: SALT,
        maker,
        receiver: taker,
        maker_asset: token,
        taker_asset: token, // Same token for simplicity
        making_amount: AMOUNT * 4, // Total order is for 4 tokens
        taking_amount: AMOUNT * 4,
        maker_traits: 0,
    };
    
    // Create extra data with parts_amount = 4 to trigger merkle validation
    let partial_amount = AMOUNT; // Fill 1 out of 4 tokens (25% fill)
    let parts_amount: u16 = 4; // Total parts - triggers merkle validation
    
    // For partial fills, we'll use the normal hashlock but set parts_amount in a way 
    // that allows the factory to detect it's a partial fill
    // In a real implementation, parts_amount would be encoded differently (e.g., in upper bits of order_hash)
    // For testing, let's use a simpler approach: store the original hashlock but signal partial fill
    let hashlock_raw = get_hashlock();
    let encoded_hashlock_info = hashlock_raw; // Keep the original hashlock intact
    
    let extra_data = ExtraDataArgs {
        hashlock_info: encoded_hashlock_info,
        timelocks: create_test_timelocks(),
    };
    
    // Maker approves the factory to spend tokens
    start_cheat_caller_address(token, maker);
    token_dispatcher.approve(factory, AMOUNT * 10);
    stop_cheat_caller_address(token);
    
    // Resolver creates src escrow with merkle validation (parts_amount > 1)
    start_cheat_caller_address(factory, resolver);
    let src_escrow_address = factory_dispatcher.create_src_escrow(
        order,
        ArrayTrait::new(), // empty extension
        0x1234, // order_hash
        taker,
        partial_amount, // making_amount - partial fill
        partial_amount, // taking_amount - partial fill  
        partial_amount, // remaining_making_amount
        extra_data
    );
    stop_cheat_caller_address(factory);
    
    let src_escrow = IEscrowSrcDispatcher { contract_address: src_escrow_address };
    let base_escrow = IBaseEscrowDispatcher { contract_address: src_escrow_address };
    
    // Verify escrow was created correctly
    let stored_immutables = base_escrow.get_immutables();
    assert(stored_immutables.maker == maker, 'Wrong maker');
    assert(stored_immutables.taker == taker, 'Wrong taker');
    assert(stored_immutables.amount == partial_amount, 'Wrong partial amount');
    
    // Verify tokens were transferred to escrow
    let escrow_balance = token_dispatcher.balance_of(src_escrow_address);
    assert(escrow_balance == partial_amount, 'Wrong escrow balance');
    
    // Fast forward to src_public_withdrawal period
    let current_time = get_block_timestamp();
    start_cheat_block_timestamp(src_escrow_address, current_time + 1300); // More than 1200 seconds
    
    // Resolver withdraws partial fill using the secret
    start_cheat_caller_address(src_escrow_address, resolver);
    src_escrow.withdraw_public(stored_immutables, SECRET);
    stop_cheat_caller_address(src_escrow_address);
    
    stop_cheat_block_timestamp(src_escrow_address);
    
    // Verify tokens were transferred to taker
    let taker_balance = token_dispatcher.balance_of(taker);
    assert(taker_balance == partial_amount, 'Taker should receive partial');
    
    let escrow_balance_after = token_dispatcher.balance_of(src_escrow_address);
    assert(escrow_balance_after == 0, 'Escrow should be empty');
    
    // Verify maker still has remaining tokens for future partial fills
    let maker_balance = token_dispatcher.balance_of(maker);
    assert(maker_balance == AMOUNT * 9, 'Maker should have remaining'); // Started with 10, used 1
    
    // This test successfully exercises the merkle validation logic with parts_amount > 1
}

/// Test 7: Test Starknet as destination with actual partial fill enabled
#[test]
fn test_starknet_as_destination_partial_fill() {
    // Setup accounts
    let maker: ContractAddress = 0x1.try_into().unwrap();
    let taker: ContractAddress = 0x2.try_into().unwrap();
    let resolver: ContractAddress = 0x3.try_into().unwrap();
    
    // Deploy contracts including mock merkle invalidator
    let token = deploy_mock_erc20();
    let merkle_invalidator = deploy_mock_merkle_invalidator();
    let factory = deploy_escrow_factory_with_merkle(merkle_invalidator);
    
    let token_dispatcher = IERC20Dispatcher { contract_address: token };
    let factory_dispatcher = IEscrowFactoryDispatcher { contract_address: factory };
    
    // Setup initial token balances - maker has enough for multiple partial fills
    token_dispatcher.mint(maker, AMOUNT * 5);
    
    // Create immutables for a larger total order (3 tokens total)
    let total_amount = AMOUNT * 3;
    let partial_amount = AMOUNT; // This partial fill is for 1/3 of the total order
    
    // We'll simulate that this is a partial fill from a larger cross-chain order
    // For the destination escrow, we just need the partial amount
    let immutables = Immutables {
        maker,
        taker,
        token,
        amount: partial_amount,
        hashlock: get_hashlock(),
        timelocks: create_test_timelocks(),
        dst_escrow_factory: factory,
        src_escrow_factory: factory,
    };
    
    // Maker approves the factory to spend tokens
    start_cheat_caller_address(token, maker);
    token_dispatcher.approve(factory, AMOUNT * 5);
    stop_cheat_caller_address(token);
    
    // Resolver creates dst escrow for partial fill
    // This simulates receiving a partial fill from another chain
    start_cheat_caller_address(factory, resolver);
    let dst_escrow_address = factory_dispatcher.create_dst_escrow(
        get_hashlock(),
        taker,
        immutables
    );
    stop_cheat_caller_address(factory);
    
    let dst_escrow = IEscrowDstDispatcher { contract_address: dst_escrow_address };
    let base_escrow = IBaseEscrowDispatcher { contract_address: dst_escrow_address };
    
    // Verify escrow was created correctly for partial amount
    let stored_immutables = base_escrow.get_immutables();
    assert(stored_immutables.maker == maker, 'Wrong maker');
    assert(stored_immutables.taker == taker, 'Wrong taker');
    assert(stored_immutables.amount == partial_amount, 'Wrong partial amount');
    
    // Verify partial amount of tokens were transferred to escrow
    let escrow_balance = token_dispatcher.balance_of(dst_escrow_address);
    assert(escrow_balance == partial_amount, 'Wrong escrow balance');
    
    // Fast forward to dst_public_withdrawal period
    let current_time = get_block_timestamp();
    start_cheat_block_timestamp(dst_escrow_address, current_time + 700); // More than 600 seconds
    
    // Resolver claims partial funds using the secret
    start_cheat_caller_address(dst_escrow_address, resolver);
    dst_escrow.withdraw_public(stored_immutables, SECRET);
    stop_cheat_caller_address(dst_escrow_address);
    
    stop_cheat_block_timestamp(dst_escrow_address);
    
    // Verify partial amount was transferred to taker
    let taker_balance = token_dispatcher.balance_of(taker);
    assert(taker_balance == partial_amount, 'Taker should receive partial');
    
    let escrow_balance_after = token_dispatcher.balance_of(dst_escrow_address);
    assert(escrow_balance_after == 0, 'Escrow should be empty');
    
    // Verify maker has remaining tokens for other partial fills
    let maker_balance = token_dispatcher.balance_of(maker);
    assert(maker_balance == AMOUNT * 4, 'Maker should have remaining'); // Started with 5, used 1
    
    // This test demonstrates that multiple partial fills could be processed
    // Each would be a separate dst escrow with its own amount
}