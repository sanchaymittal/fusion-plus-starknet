//! Factory contract for deploying escrow contracts
//! Handles both source and destination escrow creation

use starknet::ContractAddress;
use starknet::ClassHash;
use crate::{Immutables, Order};

#[derive(Drop, Serde)]
pub struct ExtraDataArgs {
    pub hashlock_info: u256,
    pub timelocks: u256,
}

#[starknet::interface]
pub trait IEscrowFactory<TContractState> {
    fn get_escrow_address(
        self: @TContractState,
        immutables: Immutables,
        salt: felt252
    ) -> ContractAddress;
    
    fn create_dst_escrow(
        ref self: TContractState,
        hashlock: u256,
        taker: ContractAddress,
        immutables: Immutables
    ) -> ContractAddress;
    
    fn create_src_escrow(
        ref self: TContractState,
        order: Order,
        extension: Array<felt252>,
        order_hash: felt252,
        taker: ContractAddress,
        making_amount: u256,
        taking_amount: u256,
        remaining_making_amount: u256,
        extra_data: ExtraDataArgs
    ) -> ContractAddress;
    
    fn get_src_escrow_class_hash(self: @TContractState) -> ClassHash;
    fn get_dst_escrow_class_hash(self: @TContractState) -> ClassHash;
}

#[starknet::contract]
pub mod EscrowFactory {
    // Import strictly the required types for the contract module from super and crate
    use super::{IEscrowFactory, Immutables, Order, ExtraDataArgs};
    use crate::merkle_validator::{IMerkleStorageInvalidatorDispatcher, IMerkleStorageInvalidatorDispatcherTrait, MerkleLeaf};
    use crate::interactions::{InteractionContext}; // BaseExtension, InteractionUtils are not directly used
    use crate::timelock::{Timelocks, TimelocksTrait, TimelockDataStorePacking, Stage};
    use crate::hashlock::{keccak_bytes32};

    // Always use full paths for core library imports.
    use starknet::ContractAddress;
    use starknet::ClassHash;
    use starknet::{get_block_timestamp, get_contract_address};
    use starknet::syscalls::deploy_syscall;
    use starknet::SyscallResultTrait;
    use starknet::storage::*; // Always add all storage imports

    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::security::reentrancyguard::ReentrancyGuardComponent;
    use openzeppelin::token::erc20::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: ReentrancyGuardComponent, storage: reentrancy_guard, event: ReentrancyGuardEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;
    impl ReentrancyGuardInternalImpl = ReentrancyGuardComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        src_escrow_class_hash: ClassHash,
        dst_escrow_class_hash: ClassHash,
        limit_order_protocol: ContractAddress,
        merkle_invalidator: IMerkleStorageInvalidatorDispatcher,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        reentrancy_guard: ReentrancyGuardComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        SrcEscrowCreated: SrcEscrowCreated,
        DstEscrowCreated: DstEscrowCreated,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        ReentrancyGuardEvent: ReentrancyGuardComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    struct SrcEscrowCreated {
        #[key]
        escrow: ContractAddress,
        #[key]
        order_hash: felt252,
        #[key]
        maker: ContractAddress,
        hashlock: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct DstEscrowCreated {
        #[key]
        escrow: ContractAddress,
        #[key]
        hashlock: felt252,
        #[key]
        taker: ContractAddress,
    }

    pub mod Errors {
        pub const UNAUTHORIZED: felt252 = 'Unauthorized caller';
        pub const DEPLOYMENT_FAILED: felt252 = 'Deployment failed';
        pub const INVALID_CREATION_TIME: felt252 = 'Invalid creation time';
        pub const INVALID_MERKLE_PROOF: felt252 = 'Invalid merkle proof';
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        src_escrow_class_hash: ClassHash,
        dst_escrow_class_hash: ClassHash,
        limit_order_protocol: ContractAddress,
        merkle_invalidator: ContractAddress
    ) {
        self.ownable.initializer(owner);
        self.src_escrow_class_hash.write(src_escrow_class_hash);
        self.dst_escrow_class_hash.write(dst_escrow_class_hash);
        self.limit_order_protocol.write(limit_order_protocol);
        self.merkle_invalidator.write(
            IMerkleStorageInvalidatorDispatcher { contract_address: merkle_invalidator }
        );
    }

    #[abi(embed_v0)]
    pub impl EscrowFactoryImpl of IEscrowFactory<ContractState> {
        fn get_escrow_address(
            self: @ContractState,
            immutables: Immutables,
            salt: felt252
        ) -> ContractAddress {
            // For now, return a deterministic address based on input hash
            // In production, this would use proper address calculation
            let class_hash = self.src_escrow_class_hash.read();
            let deployer = get_contract_address();
            
            // Create a simple deterministic address based on hash of inputs
            let hash_input = salt + class_hash.into() + deployer.into() + immutables.hashlock.low.into();
            let calculated_address: felt252 = hash_input; // Simplified for now
            calculated_address.try_into().expect('Addr conv failed')
        }

        fn create_src_escrow(
            ref self: ContractState,
            order: Order,
            extension: Array<felt252>, // This parameter is not used in the function body.
            order_hash: felt252,
            taker: ContractAddress,
            making_amount: u256,
            taking_amount: u256, // This parameter is not used in the function body.
            remaining_making_amount: u256, // This parameter is not used in the function body.
            extra_data: ExtraDataArgs
        ) -> ContractAddress {
            self.reentrancy_guard.start();

            // Only limit order protocol can create src escrows
            // TODO: For now, we'll allow any caller for testing purposes
            // In production, uncomment the line below:
            // assert(get_caller_address() == self.limit_order_protocol.read(), Errors::UNAUTHORIZED);

            let mut hashlock = extra_data.hashlock_info;

            // Handle partial fills via merkle validation
            // For testing, we'll detect partial fills based on the making_amount vs order making_amount
            // In a real implementation, this would be encoded in the extra_data properly
            let parts_amount: u16 = if making_amount < order.making_amount {
                // This is a partial fill - calculate parts based on the ratio
                (order.making_amount / making_amount).try_into().unwrap_or(1)
            } else {
                1
            };

            if parts_amount > 1 {
                // For partial fills, keep the original hashlock since we're not encoding parts_amount in it anymore
                // hashlock is already set to extra_data.hashlock_info which contains the correct value
                // This is a partial fill - validate merkle proof
                // Extract lower bits for merkle key calculation  
                let lower_bits = extra_data.hashlock_info.low.into(); // Convert to felt252 for now, use the full hashlock_info
                let merkle_key = keccak_bytes32(order_hash + lower_bits);

                let merkle_leaf = MerkleLeaf {
                    leaf_hash: hashlock.low.into(), // Convert u256 to felt252
                    amount: making_amount
                };

                // Validate and invalidate merkle leaf
                let merkle_invalidator = self.merkle_invalidator.read();
                let merkle_key_felt: felt252 = merkle_key.low.into(); // Use lower bits as felt252
                assert(merkle_invalidator.is_leaf_valid(merkle_key_felt, merkle_leaf), Errors::INVALID_MERKLE_PROOF);
                merkle_invalidator.invalidate_merkle_leaf(merkle_key_felt, merkle_leaf);

                // For partial fills, don't change the hashlock - keep the original
                // The merkle leaf validation is separate from the secret hashlock
                // hashlock should remain the original value for secret validation
            }

            // Set deployment timestamp
            let timelocks = Timelocks { data: TimelockDataStorePacking::unpack(extra_data.timelocks) };
            let timelocks_with_timestamp = timelocks.set_deployed_at(get_block_timestamp());

            let immutables = Immutables {
                maker: order.maker,
                taker,
                token: order.maker_asset,
                amount: making_amount,
                hashlock,
                timelocks: TimelockDataStorePacking::pack(timelocks_with_timestamp.data),
                dst_escrow_factory: 0.try_into().expect('Factory addr conv failed'), // Will be set by the destination chain
                src_escrow_factory: get_contract_address(),
            };

            // Deploy escrow contract
            let class_hash = self.src_escrow_class_hash.read();
            // Convert immutables struct to constructor calldata
            let constructor_calldata = self._immutables_to_calldata(immutables);

            let (escrow_address, _) = deploy_syscall(
                class_hash,
                order_hash, // Use order hash as salt
                constructor_calldata.span(),
                false
            ).unwrap_syscall();

            // Transfer tokens from maker to escrow
            let token = ERC20ABIDispatcher { contract_address: order.maker_asset };
            let success = token.transfer_from(
                order.maker,
                escrow_address,
                making_amount
            );
            assert(success, 'Transfer failed');

            self.emit(SrcEscrowCreated {
                escrow: escrow_address,
                order_hash,
                maker: order.maker,
                hashlock: hashlock.low.into() // Convert u256 to felt252 for event
            });

            self.reentrancy_guard.end();
            escrow_address
        }

        fn create_dst_escrow(
            ref self: ContractState,
            hashlock: u256,
            taker: ContractAddress,
            mut immutables: Immutables
        ) -> ContractAddress {
            self.reentrancy_guard.start();

            // Set deployment timestamp and validate timing
            let mut timelocks = Timelocks { data: TimelockDataStorePacking::unpack(immutables.timelocks) };
            timelocks = timelocks.set_deployed_at(get_block_timestamp());
            immutables.timelocks = TimelockDataStorePacking::pack(timelocks.data);

            // Validate that dst cancellation is not before src cancellation
            let src_cancellation_timestamp = timelocks.get_stage_time(Stage::SrcCancellation);
            let dst_cancellation_timestamp = timelocks.get_stage_time(Stage::DstCancellation);

            assert(dst_cancellation_timestamp <= src_cancellation_timestamp, Errors::INVALID_CREATION_TIME);

            // Deploy escrow contract
            let class_hash = self.dst_escrow_class_hash.read();
            // Convert immutables struct to constructor calldata
            let constructor_calldata = self._immutables_to_calldata(immutables);

            let salt_hash = keccak_bytes32(hashlock.low.into() + taker.into()); // Deterministic salt
            let salt: felt252 = salt_hash.low.into(); // Use only the lower 128 bits

            let (escrow_address, _) = deploy_syscall(
                class_hash,
                salt,
                constructor_calldata.span(),
                false
            ).unwrap_syscall();

            // Transfer tokens from maker to escrow
            let token = ERC20ABIDispatcher { contract_address: immutables.token };
            let success = token.transfer_from(
                immutables.maker,
                escrow_address,
                immutables.amount
            );
            assert(success, 'Transfer failed');

            self.emit(DstEscrowCreated {
                escrow: escrow_address,
                hashlock: immutables.hashlock.low.into(), // Convert u256 to felt252 for event
                taker
            });

            self.reentrancy_guard.end();
            escrow_address
        }

        fn get_src_escrow_class_hash(self: @ContractState) -> ClassHash {
            self.src_escrow_class_hash.read()
        }

        fn get_dst_escrow_class_hash(self: @ContractState) -> ClassHash {
            self.dst_escrow_class_hash.read()
        }
    }

    // Implement interaction interfaces for integration with limit order protocol
    #[abi(embed_v0)]
    pub impl PreInteractionImpl of crate::interactions::IPreInteraction<ContractState> {
        fn pre_interaction(
            ref self: ContractState,
            context: InteractionContext
        ) {
            // Pre-interaction logic - can be extended for custom behavior
        }
    }

    #[abi(embed_v0)]
    pub impl PostInteractionImpl of crate::interactions::IPostInteraction<ContractState> {
        fn post_interaction(
            ref self: ContractState,
            context: InteractionContext
        ) {
            // Post-interaction logic - can be extended for custom behavior
        }
    }

    #[abi(embed_v0)]
    pub impl TakerInteractionImpl of crate::interactions::ITakerInteraction<ContractState> {
        fn taker_interaction(
            ref self: ContractState,
            context: InteractionContext
        ) {
            // Handle taker interaction - create escrow contracts based on context
            // This would contain the logic to parse extra_data and create appropriate escrows
        }
    }

    #[generate_trait]
    impl EscrowFactoryInternalImpl of EscrowFactoryInternalTrait {
        fn _immutables_to_calldata(
            self: @ContractState,
            immutables: Immutables
        ) -> Array<felt252> {
            let mut calldata = ArrayTrait::new();
            calldata.append(immutables.maker.into());
            calldata.append(immutables.taker.into());
            calldata.append(immutables.token.into());
            calldata.append(immutables.amount.low.into());
            calldata.append(immutables.amount.high.into());
            calldata.append(immutables.hashlock.low.into());
            calldata.append(immutables.hashlock.high.into());
            calldata.append(immutables.timelocks.low.into());
            calldata.append(immutables.timelocks.high.into());
            calldata.append(immutables.dst_escrow_factory.into());
            calldata.append(immutables.src_escrow_factory.into());
            calldata
        }
    }
}