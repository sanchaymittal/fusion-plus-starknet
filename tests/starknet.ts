import {Account, Contract, RpcProvider, CallData, cairo, uint256, Call} from 'starknet'
import {parseUnits} from 'ethers'
import {readFileSync} from 'fs'

interface ContractClass {
    abi: any[]
    // other fields...
}

// Starknet configuration
// const STARKNET_RPC_URL = process.env.STARKNET_RPC_URL || 'https://starknet-sepolia.public.blastapi.io/rpc/v0_7'

export const StarknetProvider = new RpcProvider() // Sepolia
// new Open Zeppelin account v0.17.0
// Generate public and private key pair.
const OZcontractAddress = '0x07e6062aa6bd572a9e046045d93e52c20b8267bbc9cd89c7156bc9b2853fa20f'
const privateKey = '0x1c6aaf3f632d99997f145c708e4e83db3a02c87c4dea52e406990841933b361'
export const StarknetWallet = new Account(StarknetProvider, OZcontractAddress, privateKey)

export const escrowFactoryAddress = '0x0613303200348786097f8409c67208d189c4326762e20d9354659bef4a77522b'

export const tokenAddress = '0x038b828abff1c65ef2c99234339f655177118131c58579b92f1775a7a1c7f5c4'

const erc20ContractClass: ContractClass = JSON.parse(
    readFileSync('./starknet/target/dev/cross_chain_swap_MyToken.contract_class.json', 'utf8')
)
const erc20Abi = erc20ContractClass.abi
export const StarknetErc20 = new Contract(erc20Abi, tokenAddress, StarknetProvider)

const escrowFactoryContractClass: ContractClass = JSON.parse(
    readFileSync('./starknet/target/dev/cross_chain_swap_EscrowFactory.contract_class.json', 'utf8')
)
const escrowFactoryAbi = escrowFactoryContractClass.abi
export const StarknetEscrowFactory = new Contract(escrowFactoryAbi, escrowFactoryAddress, StarknetProvider)

// Utility functions
export async function signAndSubmit(
    account: Account,
    payload: Call
): Promise<{txHash: string; blockTimestamp: number}> {
    console.log(`[signAndSubmit] Executing payload:`, payload)
    const {transaction_hash} = await account.execute(payload)
    console.log(`[signAndSubmit] Waiting for Tx to be Accepted on Starknet - ${transaction_hash}...`)
    const receipt = await StarknetProvider.waitForTransaction(transaction_hash)

    // Get block info for timestamp
    const block = await StarknetProvider.getBlockWithTxs('latest')

    return {
        txHash: transaction_hash,
        blockTimestamp: block.timestamp
    }
}

// ERC20 token balance function using cairo utilities
export async function getTokenBalance(tokenAddress: string, accountAddress: string): Promise<bigint> {
    try {
        console.log(`[getTokenBalance] Getting balance for token: ${tokenAddress}, account: ${accountAddress}`)
        const erc20 = new Contract(erc20Abi, tokenAddress, StarknetProvider)
        const result = await erc20.balanceOf(accountAddress)
        const balance = uint256.uint256ToBN(result)
        console.log(`[getTokenBalance] Balance result:`, balance.toString())
        return balance
    } catch (error) {
        console.error(`[getTokenBalance] Error getting balance for token ${tokenAddress}:`, error)
        return 0n
    }
}

// Mint tokens function (requires the token contract to have a public mint function)
export async function mintTokens(tokenAddress: string, recipient: string, amount: bigint): Promise<string> {
    try {
        console.log(
            `[mintTokens] Minting tokens: ${tokenAddress}, recipient: ${recipient}, amount: ${amount.toString()}`
        )
        StarknetErc20.connect(StarknetWallet)

        console.log(`[mintTokens] Invoking mint with recipient: ${recipient}, amount: ${amount.toString()}`)

        const invokeResult = await StarknetErc20.invoke('mint', [recipient, cairo.uint256(amount)])

        console.log(`[mintTokens] Invoke result:`, invokeResult)

        // Wait for transaction confirmation
        const receipt = await StarknetProvider.waitForTransaction(invokeResult.transaction_hash)
        console.log(`[mintTokens] Mint transaction confirmed:`, invokeResult.transaction_hash)

        return invokeResult.transaction_hash
    } catch (error) {
        console.error(`[mintTokens] Error minting tokens (mint function may not be available):`, error)
        throw error
    }
}

// Approve token function using cairo utilities
export async function approveToken(tokenAddress: string, spender: string, amount: bigint): Promise<string> {
    try {
        console.log(
            `[approveToken] Approving token: ${tokenAddress}, spender: ${spender}, amount: ${amount.toString()}`
        )

        StarknetErc20.connect(StarknetWallet)

        console.log(`[approveToken] Invoking approve with spender: ${spender}, amount: ${amount.toString()}`)

        const invokeResult = await StarknetErc20.invoke('approve', [spender, cairo.uint256(amount)])

        console.log(`[approveToken] Invoke result:`, invokeResult)

        // Wait for transaction confirmation
        const receipt = await StarknetProvider.waitForTransaction(invokeResult.transaction_hash)
        console.log(`[approveToken] Approve transaction confirmed:`, invokeResult.transaction_hash)

        return invokeResult.transaction_hash
    } catch (error) {
        console.error(`[approveToken] Error approving token:`, error)
        throw error
    }
}

// Deploy destination escrow via EscrowFactory
export async function deployDstEscrow(
    immutables: any,
    secret: string
): Promise<{txHash: string; blockTimestamp: number; escrowAddress?: string; deployedImmutables?: any}> {
    try {
        console.log(`[deployDstEscrow] Deploying destination escrow with immutables:`, immutables)
        StarknetEscrowFactory.connect(StarknetWallet)

        // Create simple ContractAddress values (felt252)
        const makerAddr = immutables.taker // Use taker (Starknet address) as maker for Starknet side
        const takerAddr = immutables.taker
        const tokenAddr = tokenAddress
        const amountValue = typeof immutables.amount === 'bigint' ? immutables.amount : BigInt(immutables.amount)
        // Generate hashlock using the Cairo contract function
        console.log(`[deployDstEscrow] Generating hashlock for secret: ${secret}`)
        const hashlockResult = await StarknetEscrowFactory.generate_hashlock(BigInt(secret))
        console.log(`[deployDstEscrow] Generated hashlock:`, hashlockResult)
        const hashlockBigInt = hashlockResult.transaction_hash // Use the transaction hash as the hashlock

        // Create timelock structure for the flattened Timelocks struct
        const timelocks = {
            deployed_at: 0, // u64 - will be set by the contract during deployment
            dst_withdrawal: Number(immutables.timelocks._dstWithdrawal), // u32
            dst_public_withdrawal: Number(immutables.timelocks._dstPublicWithdrawal), // u32
            dst_cancellation: Number(immutables.timelocks._dstCancellation), // u32
            src_withdrawal: Number(immutables.timelocks._srcWithdrawal), // u32
            src_public_withdrawal: Number(immutables.timelocks._srcPublicWithdrawal), // u32
            src_cancellation: Number(immutables.timelocks._srcCancellation), // u32
            src_public_cancellation: Number(immutables.timelocks._srcPublicCancellation) // u32
        }

        // Approve the factory contract to spend tokens on behalf of the maker
        console.log(`[deployDstEscrow] Approving factory to spend ${amountValue} tokens...`)
        const approveHash = await approveToken(tokenAddr, escrowFactoryAddress, amountValue)
        console.log(`[deployDstEscrow] Approval transaction: ${approveHash}`)

        // Now invoke the contract method with detailed parameter logging
        console.log(`[deployDstEscrow] Invoking create_dst_escrow with parameters:`, {
            hashlock: cairo.uint256(hashlockBigInt),
            taker: '0x07e6062aa6bd572a9e046045d93e52c20b8267bbc9cd89c7156bc9b2853fa20f',
            immutables: {
                maker: makerAddr,
                taker: takerAddr,
                token: tokenAddr,
                amount: cairo.uint256(amountValue),
                hashlock: cairo.uint256(hashlockBigInt),
                timelocks: timelocks,
                dst_escrow_factory: escrowFactoryAddress,
                src_escrow_factory: escrowFactoryAddress // Use factory address as placeholder
            }
        })

        const invokeResult = await StarknetEscrowFactory.invoke('create_dst_escrow', [
            cairo.uint256(hashlockBigInt),
            '0x07e6062aa6bd572a9e046045d93e52c20b8267bbc9cd89c7156bc9b2853fa20f',
            {
                maker: makerAddr,
                taker: takerAddr,
                token: tokenAddr,
                amount: cairo.uint256(amountValue),
                hashlock: cairo.uint256(hashlockBigInt),
                timelocks: timelocks,
                dst_escrow_factory: escrowFactoryAddress,
                src_escrow_factory: escrowFactoryAddress
            }
        ])

        console.log(`[deployDstEscrow] Invoke result:`, invokeResult)

        // Wait for transaction and get detailed information
        console.log(`[deployDstEscrow] Waiting for transaction ${invokeResult.transaction_hash} to be accepted...`)
        const txReceipt = await StarknetProvider.waitForTransaction(invokeResult.transaction_hash)
        console.log(`[deployDstEscrow] Transaction receipt:`, txReceipt)

        let escrowAddress = '0x0'
        let deployedImmutables = null

        if (txReceipt.isSuccess()) {
            const listEvents = txReceipt.value.events
            console.log(`[deployDstEscrow] Transaction events:`, listEvents)

            const events = StarknetEscrowFactory.parseEvents(txReceipt)
            console.log(`[deployDstEscrow] Parsed events:`, events)

            // Extract escrow address from DstEscrowCreated event
            if (events.length > 0 && events[0]['cross_chain_swap::escrow_factory::EscrowFactory::DstEscrowCreated']) {
                const escrowBigInt =
                    events[0]['cross_chain_swap::escrow_factory::EscrowFactory::DstEscrowCreated'].escrow
                escrowAddress = '0x' + escrowBigInt.toString(16)
                console.log(`[deployDstEscrow] Extracted escrow address: ${escrowAddress}`)

                // Load the escrow contract and get the stored immutables
                const escrowDstContractClass: ContractClass = JSON.parse(
                    readFileSync('./starknet/target/dev/cross_chain_swap_EscrowDst.contract_class.json', 'utf8')
                )
                const escrowDstAbi = escrowDstContractClass.abi
                const escrowContract = new Contract(escrowDstAbi, escrowAddress, StarknetProvider)

                // Call get_immutables to retrieve the stored immutables
                deployedImmutables = await escrowContract.get_immutables()
                console.log(`[deployDstEscrow] Retrieved stored immutables from escrow:`, deployedImmutables)
            }
        }

        // // Get block info for timestamp
        const block = await StarknetProvider.getBlockWithTxs('latest')

        const result = {
            txHash: invokeResult.transaction_hash,
            blockTimestamp: block.timestamp,
            escrowAddress,
            deployedImmutables
        }

        console.log(`[deployDstEscrow] Deploy transaction completed:`, result)
        return result as any
    } catch (error) {
        console.error(`[deployDstEscrow] Error deploying destination escrow:`, error)
        throw error
    }
}

// Get destination escrow address
export async function getDstEscrowAddress(immutables: any, salt: string): Promise<string> {
    try {
        console.log(`[getDstEscrowAddress] Getting escrow address with immutables:`, immutables, `salt:`, salt)

        // Validate and truncate salt if it exceeds felt252 limit
        const FELT252_MAX = BigInt('0x800000000000011000000000000000000000000000000000000000000000000')
        const saltBigInt = BigInt(salt)
        let processedSalt = salt

        if (saltBigInt >= FELT252_MAX) {
            // Truncate the salt to fit within felt252
            processedSalt = '0x' + salt.slice(2, 50) // Keep first 48 hex chars after 0x
            console.log(`[getDstEscrowAddress] Salt exceeds felt252, using truncated: ${processedSalt}`)
        }

        // Extract primitive values from complex objects using the same logic as deployDstEscrow
        const makerAddress = immutables.maker?.val || immutables.maker?.toString() || immutables.maker
        const hashlockValue = immutables.hashlock?.value || immutables.hashlock?.toString() || immutables.hashlock
        const timelocksValue =
            immutables.timelocks?._deployedAt || immutables.timelocks?.toString() || immutables.timelocks
        const amountValue =
            typeof immutables.amount === 'bigint' ? immutables.amount : BigInt(immutables.amount?.toString() || '0')

        // Process addresses similar to deployDstEscrow
        const validateContractAddress = (addr: string, name: string): string => {
            const addrBigInt = BigInt(addr)
            const isValidFelt252 = addrBigInt < FELT252_MAX
            console.log(`[getDstEscrowAddress] ${name}:`, addr, isValidFelt252 ? '✅ felt252' : '❌ EXCEEDS')

            if (!isValidFelt252) {
                const truncatedAddr = '0x' + addr.slice(2, 50)
                console.log(`[getDstEscrowAddress] Using truncated address: ${truncatedAddr}`)
                return truncatedAddr
            }
            return addr
        }

        const processedMaker = validateContractAddress(makerAddress as string, 'maker')
        const processedTaker = validateContractAddress(immutables.taker as string, 'taker')
        const processedToken = validateContractAddress(immutables.token as string, 'token')
        const processedDstFactory = validateContractAddress(immutables.dstEscrowFactory as string, 'dst_escrow_factory')
        const processedSrcFactory = validateContractAddress(immutables.srcEscrowFactory as string, 'src_escrow_factory')

        const result = await StarknetEscrowFactory.get_escrow_address(
            {
                maker: processedMaker,
                taker: processedTaker,
                token: processedToken,
                amount: cairo.uint256(amountValue),
                hashlock: cairo.uint256(BigInt(hashlockValue?.toString() || '0')),
                timelocks: cairo.uint256(BigInt(timelocksValue?.toString() || '0')),
                dst_escrow_factory: processedDstFactory,
                src_escrow_factory: processedSrcFactory
            },
            processedSalt
        )
        console.log(`[getDstEscrowAddress] Escrow address result:`, result)
        return result
    } catch (error) {
        console.error(`[getDstEscrowAddress] Error getting escrow address:`, error)
        throw error
    }
}

// Get immutables from deployed escrow contract
export async function getEscrowImmutables(escrowAddress: string): Promise<any> {
    try {
        console.log(`[getEscrowImmutables] Getting immutables from escrow: ${escrowAddress}`)

        const escrowDstContractClass: ContractClass = JSON.parse(
            readFileSync('./starknet/target/dev/cross_chain_swap_EscrowDst.contract_class.json', 'utf8')
        )
        const escrowDstAbi = escrowDstContractClass.abi
        const escrowContract = new Contract(escrowDstAbi, escrowAddress, StarknetProvider)

        const immutables = await escrowContract.get_immutables()
        console.log(`[getEscrowImmutables] Retrieved immutables:`, immutables)
        console.log(
            `[getEscrowImmutables] Immutables structure:`,
            JSON.stringify(immutables, (key, value) => (typeof value === 'bigint' ? value.toString() : value), 2)
        )

        return immutables
    } catch (error) {
        console.error(`[getEscrowImmutables] Error getting immutables:`, error)
        throw error
    }
}

// Helper function to ensure addresses are in proper Starknet format
function normalizeStarknetAddress(address: string): string {
    // Remove '0x' prefix if present
    let cleaned = address.replace('0x', '')

    // Pad to 64 characters (32 bytes) with leading zeros if needed
    cleaned = cleaned.padStart(64, '0')

    // Add '0x' prefix back
    return '0x' + cleaned
}

// Withdraw from escrow
export async function withdrawFromEscrow(
    escrowAddress: string,
    secret: string,
    immutables?: any
): Promise<{txHash: string; blockTimestamp: number}> {
    try {
        // If immutables not provided, get them from the escrow contract
        if (!immutables) {
            console.log(`[withdrawFromEscrow] No immutables provided, fetching from escrow contract...`)
            immutables = await getEscrowImmutables(escrowAddress)
        } else if (immutables.deployedImmutables) {
            // If we have deployedImmutables from the deployment result, use those
            console.log(`[withdrawFromEscrow] Using deployedImmutables from deployment result`)
            immutables = immutables.deployedImmutables
        }

        console.log(
            `[withdrawFromEscrow] Withdrawing from escrow:`,
            escrowAddress,
            `secret:`,
            secret,
            `immutables:`,
            immutables
        )

        // Load the actual escrow ABI
        const escrowDstContractClass: ContractClass = JSON.parse(
            readFileSync('./starknet/target/dev/cross_chain_swap_EscrowDst.contract_class.json', 'utf8')
        )
        const escrowDstAbi = escrowDstContractClass.abi

        // Create escrow contract instance with the proper ABI
        const escrowContract = new Contract(escrowDstAbi, escrowAddress, StarknetWallet)

        // Get the actual stored immutables from the contract for comparison
        console.log(`[withdrawFromEscrow] Fetching stored immutables from escrow contract...`)
        const storedImmutables = await escrowContract.get_immutables()
        console.log(
            `[withdrawFromEscrow] STORED IMMUTABLES FROM CONTRACT:`,
            JSON.stringify(storedImmutables, (key, value) => (typeof value === 'bigint' ? value.toString() : value), 2)
        )

        // Use the same truncated secret for withdrawal that was used for hashing
        // Convert to BigInt for Cairo contract compatibility

        // Convert immutables to simple values for contract call
        // The timelocks should contain all the timelock values as a nested data structure

        // Use the exact stored immutables from the contract - no reconstruction needed!
        const contractImmutables = storedImmutables

        console.log(
            `[withdrawFromEscrow] CONSTRUCTED IMMUTABLES FOR WITHDRAW:`,
            JSON.stringify(
                contractImmutables,
                (key, value) => (typeof value === 'bigint' ? value.toString() : value),
                2
            )
        )
        console.log(
            `[withdrawFromEscrow] COMPARISON - Input immutables:`,
            JSON.stringify(immutables, (key, value) => (typeof value === 'bigint' ? value.toString() : value), 2)
        )
        console.log(`[withdrawFromEscrow] Using secret: ${secret}`)

        // Check timelock calculations
        const deployedAt = Number(storedImmutables.timelocks.deployed_at)
        const dstPublicWithdrawal = Number(storedImmutables.timelocks.dst_public_withdrawal)
        const dstCancellation = Number(storedImmutables.timelocks.dst_cancellation)
        const currentTime = Math.floor(Date.now() / 1000)

        const withdrawalStartTime = deployedAt + dstPublicWithdrawal
        const withdrawalEndTime = deployedAt + dstCancellation

        console.log(`[withdrawFromEscrow] TIMELOCK ANALYSIS:`)
        console.log(`  Deployed at: ${deployedAt} (${new Date(deployedAt * 1000).toISOString()})`)
        console.log(`  Current time: ${currentTime} (${new Date(currentTime * 1000).toISOString()})`)
        console.log(`  Withdrawal window: ${withdrawalStartTime} to ${withdrawalEndTime}`)
        console.log(`  Window start: ${new Date(withdrawalStartTime * 1000).toISOString()}`)
        console.log(`  Window end: ${new Date(withdrawalEndTime * 1000).toISOString()}`)
        console.log(`  Time until window opens: ${withdrawalStartTime - currentTime} seconds`)
        console.log(`  Window is open: ${currentTime >= withdrawalStartTime && currentTime < withdrawalEndTime}`)

        // Check if within withdrawal timelock (DstWithdrawal stage)
        const dstWithdrawal = Number(storedImmutables.timelocks.dst_withdrawal)
        const withdrawalTime = deployedAt + dstWithdrawal

        console.log(
            `[withdrawFromEscrow] Private withdrawal available after: ${withdrawalTime} (${new Date(withdrawalTime * 1000).toISOString()})`
        )
        console.log(
            `[withdrawFromEscrow] Using private withdraw (10 second window) instead of public (100 second window)`
        )

        // Always wait at least 15 seconds from deployment to ensure blockchain has synced
        const minWaitTime = deployedAt + 15 // 15 seconds minimum
        const actualWaitTime = Math.max(withdrawalTime, minWaitTime)
        if (currentTime < actualWaitTime) {
            const waitTime = (actualWaitTime - currentTime + 2) * 1000 // +2 sec buffer
            console.log(
                `[withdrawFromEscrow] Auto-waiting ${waitTime / 1000} seconds for withdrawal window (min 15s from deployment)...`
            )
            await new Promise((resolve) => setTimeout(resolve, waitTime))
            console.log(`[withdrawFromEscrow] Withdrawal window should now be open. Proceeding with withdrawal...`)
        } else {
            // Even if we think the window is open, add a small buffer to account for timestamp differences
            console.log(`[withdrawFromEscrow] Window should be open, but adding 5 second buffer for blockchain sync...`)
            await new Promise((resolve) => setTimeout(resolve, 5000))
        }

        // Get current block timestamp from Starknet to ensure we're using blockchain time
        const currentBlock = await StarknetProvider.getBlockWithTxs('latest')
        const blockchainTime = currentBlock.timestamp
        console.log(
            `[withdrawFromEscrow] Blockchain timestamp: ${blockchainTime} (${new Date(blockchainTime * 1000).toISOString()})`
        )
        console.log(`[withdrawFromEscrow] Time since deployment: ${blockchainTime - deployedAt} seconds`)
        console.log(`[withdrawFromEscrow] Required wait time: ${dstWithdrawal} seconds`)

        // Convert hex string secret to BigInt for proper u256 conversion
        const secretBigInt = BigInt(secret)
        console.log(`[withdrawFromEscrow] Converting secret: ${secret} -> BigInt: ${secretBigInt.toString()}`)

        const invokeResult = await escrowContract.invoke('withdraw', [
            contractImmutables,
            secretBigInt // Convert secret BigInt to Cairo u256
        ])

        console.log(`[withdrawFromEscrow] Invoke result:`, invokeResult)

        // Wait for transaction and get detailed information
        console.log(`[withdrawFromEscrow] Waiting for transaction ${invokeResult.transaction_hash} to be accepted...`)
        const txReceipt = await StarknetProvider.waitForTransaction(invokeResult.transaction_hash)
        console.log(`[withdrawFromEscrow] Transaction receipt:`, txReceipt)

        return invokeResult as any
    } catch (error) {
        console.error(`[withdrawFromEscrow] Error withdrawing from escrow:`, error)
        throw error
    }
}

// Helper function to convert Ethereum amounts to Starknet format
export function ethToStarknetAmount(ethAmount: bigint, decimals: number = 18): bigint {
    // Convert from Ethereum wei to Starknet units
    if (decimals === 18) {
        return ethAmount
    }
    // Handle different decimal places if needed
    const factor = 10n ** BigInt(18 - decimals)
    return ethAmount / factor
}

// Starknet-specific amount utilities using cairo
export const StarknetAmounts = {
    parseUnits: (value: string, decimals: number): bigint => {
        return parseUnits(value, decimals)
    },

    toUint256: (amount: bigint): ReturnType<typeof cairo.uint256> => {
        return cairo.uint256(amount)
    },

    fromUint256: (uint256Value: {low: bigint; high: bigint}): bigint => {
        return uint256.uint256ToBN(uint256Value)
    }
}

export default {
    StarknetWallet,
    StarknetProvider,
    StarknetErc20,
    StarknetEscrowFactory,
    signAndSubmit,
    getTokenBalance,
    approveToken,
    deployDstEscrow,
    getDstEscrowAddress,
    getEscrowImmutables,
    withdrawFromEscrow,
    ethToStarknetAmount,
    StarknetAmounts
}
