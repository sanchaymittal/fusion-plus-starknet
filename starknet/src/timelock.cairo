//! Timelock functionality for escrow contracts
//! Manages different phases of atomic swap lifecycle

use starknet::get_block_timestamp;
use starknet::storage_access::StorePacking;

// Timelock stages equivalent to Solidity enum
#[derive(Drop, Serde, Copy, PartialEq)]
pub enum Stage {
    DstWithdrawal,
    DstPublicWithdrawal, 
    DstCancellation,
    SrcWithdrawal,
    SrcPublicWithdrawal,
    SrcCancellation,
    SrcPublicCancellation,
}

// Constants for bit packing
const TWO_POW_32: u256 = 0x100000000;
const TWO_POW_64: u256 = 0x10000000000000000;
const TWO_POW_96: u256 = 0x1000000000000000000000000;
const TWO_POW_128: u256 = 0x100000000000000000000000000000000;
const TWO_POW_160: u256 = 0x10000000000000000000000000000000000000000;
const TWO_POW_192: u256 = 0x1000000000000000000000000000000000000000000000000;
const TWO_POW_224: u256 = 0x100000000000000000000000000000000000000000000000000000000;

const MASK_32: u256 = 0xFFFFFFFF;
const MASK_64: u256 = 0xFFFFFFFFFFFFFFFF;

#[derive(Drop, Serde, Copy)]
pub struct TimelockData {
    pub deployed_at: u64,
    pub dst_withdrawal: u32,
    pub dst_public_withdrawal: u32,
    pub dst_cancellation: u32,
    pub src_withdrawal: u32,
    pub src_public_withdrawal: u32,
    pub src_cancellation: u32,
    pub src_public_cancellation: u32,
}

#[derive(Drop, Serde, Copy)]
pub struct Timelocks {
    pub data: TimelockData,
}

pub impl TimelockDataStorePacking of StorePacking<TimelockData, u256> {
    fn pack(value: TimelockData) -> u256 {
        value.src_public_cancellation.into()
            + (value.src_cancellation.into() * TWO_POW_32)
            + (value.src_public_withdrawal.into() * TWO_POW_64)
            + (value.src_withdrawal.into() * TWO_POW_96)
            + (value.dst_cancellation.into() * TWO_POW_128)
            + (value.dst_public_withdrawal.into() * TWO_POW_160)
            + (value.dst_withdrawal.into() * TWO_POW_192)
            + (value.deployed_at.into() * TWO_POW_224)
    }

    fn unpack(value: u256) -> TimelockData {
        let src_public_cancellation = value & MASK_32;
        let src_cancellation = (value / TWO_POW_32) & MASK_32;
        let src_public_withdrawal = (value / TWO_POW_64) & MASK_32;
        let src_withdrawal = (value / TWO_POW_96) & MASK_32;
        let dst_cancellation = (value / TWO_POW_128) & MASK_32;
        let dst_public_withdrawal = (value / TWO_POW_160) & MASK_32;
        let dst_withdrawal = (value / TWO_POW_192) & MASK_32;
        let deployed_at = (value / TWO_POW_224) & MASK_64;

        TimelockData {
            deployed_at: deployed_at.try_into().expect('deploy_at conv failed'),
            dst_withdrawal: dst_withdrawal.try_into().expect('dst_withdraw conv failed'),
            dst_public_withdrawal: dst_public_withdrawal.try_into().expect('dst_pub_withdraw conv failed'),
            dst_cancellation: dst_cancellation.try_into().expect('dst_cancel conv failed'),
            src_withdrawal: src_withdrawal.try_into().expect('src_withdraw conv failed'),
            src_public_withdrawal: src_public_withdrawal.try_into().expect('src_pub_withdraw conv failed'),
            src_cancellation: src_cancellation.try_into().expect('src_cancel conv failed'),
            src_public_cancellation: src_public_cancellation.try_into().expect('src_pub_cancel conv failed'),
        }
    }
}

#[generate_trait]
pub impl TimelocksImpl of TimelocksTrait {
    fn new(
        dst_withdrawal: u32,
        dst_public_withdrawal: u32, 
        dst_cancellation: u32,
        src_withdrawal: u32,
        src_public_withdrawal: u32,
        src_cancellation: u32,
        src_public_cancellation: u32
    ) -> Timelocks {
        let data = TimelockData {
            deployed_at: 0,
            dst_withdrawal,
            dst_public_withdrawal,
            dst_cancellation,
            src_withdrawal,
            src_public_withdrawal,
            src_cancellation,
            src_public_cancellation,
        };
        
        Timelocks { data }
    }
    
    fn set_deployed_at(self: Timelocks, deployed_at: u64) -> Timelocks {
        let mut data = self.data;
        data.deployed_at = deployed_at;
        Timelocks { data }
    }
    
    fn get_deployed_at(self: @Timelocks) -> u64 {
        (*self).data.deployed_at
    }
    
    fn get_stage_time(self: @Timelocks, stage: Stage) -> u64 {
        let stage_delay = match stage {
            Stage::DstWithdrawal => (*self).data.dst_withdrawal,
            Stage::DstPublicWithdrawal => (*self).data.dst_public_withdrawal,
            Stage::DstCancellation => (*self).data.dst_cancellation,
            Stage::SrcWithdrawal => (*self).data.src_withdrawal,
            Stage::SrcPublicWithdrawal => (*self).data.src_public_withdrawal,
            Stage::SrcCancellation => (*self).data.src_cancellation,
            Stage::SrcPublicCancellation => (*self).data.src_public_cancellation,
        };
        
        let deployed_at = self.get_deployed_at();
        deployed_at + stage_delay.into()
    }
    
    fn rescue_start(self: @Timelocks, rescue_delay: u64) -> u64 {
        rescue_delay + self.get_deployed_at()
    }
    
    fn is_stage_active(self: @Timelocks, stage: Stage) -> bool {
        let current_time = get_block_timestamp();
        let stage_time = self.get_stage_time(stage);
        current_time >= stage_time
    }
    
    fn is_before_stage(self: @Timelocks, stage: Stage) -> bool {
        let current_time = get_block_timestamp();
        let stage_time = self.get_stage_time(stage);
        current_time < stage_time
    }
}

// Error definitions
pub mod Errors {
    pub const TOO_EARLY: felt252 = 'Too early for this operation';
    pub const TOO_LATE: felt252 = 'Too late for this operation';
    pub const INVALID_TIMELOCK: felt252 = 'Invalid timelock configuration';
}