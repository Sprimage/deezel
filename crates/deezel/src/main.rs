//! DEEZEL CLI - A thin wrapper around the deezel-sys library
//!
//! This crate is responsible for parsing command-line arguments and delegating
//! the actual work to the deezel-sys library. This keeps the CLI crate
//! lightweight and focused on its primary role as a user interface.

use anyhow::Result;
use clap::Parser;
use deezel_sys::{SystemDeezel, SystemOrd};
use deezel_common::traits::*;
use futures::future::join_all;
use serde_json::json;

mod commands;
mod pretty_print;
use commands::{Alkanes, AlkanesExecute, Commands, DeezelCommands, MetashrewCommands, Protorunes, Runestone, WalletCommands, AmmCommands};
use deezel_common::alkanes;
use pretty_print::*;


#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Load .env if present
    let _ = dotenvy::dotenv();
    // Parse command-line arguments
    let args = DeezelCommands::parse();

    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    // Handle keystore logic

    // Create a new SystemDeezel instance
    let mut system = SystemDeezel::new(&deezel_common::commands::Args::from(&args)).await?;

    // Execute the command
    execute_command(&mut system, args.command).await
}

async fn execute_command<T: System + SystemOrd + UtxoProvider>(system: &mut T, command: Commands) -> Result<()> {
    match command {
        Commands::Bitcoind(cmd) => system.execute_bitcoind_command(cmd.into()).await.map_err(|e| e.into()),
        Commands::Wallet(cmd) => execute_wallet_command(system, cmd).await,
        Commands::Alkanes(cmd) => execute_alkanes_command(system, cmd).await,
        Commands::Runestone(cmd) => execute_runestone_command(system, cmd).await,
        Commands::Protorunes(cmd) => execute_protorunes_command(system.provider(), cmd).await,
        Commands::Ord(cmd) => execute_ord_command(system.provider(), cmd.into()).await,
        Commands::Esplora(cmd) => execute_esplora_command(system.provider(), cmd.into()).await,
        Commands::Metashrew(cmd) => execute_metashrew_command(system.provider(), cmd).await,
        Commands::Amm(cmd) => execute_amm_command(system.provider(), cmd).await,
    }
}

async fn execute_metashrew_command(provider: &dyn DeezelProvider, command: MetashrewCommands) -> Result<()> {
    match command {
        MetashrewCommands::Height => {
            let height = provider.get_height().await?;
            println!("{height}");
        }
        MetashrewCommands::Getblockhash { height } => {
            let hash = <dyn DeezelProvider as MetashrewProvider>::get_block_hash(provider, height).await?;
            println!("{hash}");
        }
        MetashrewCommands::Getstateroot { height } => {
            let param = match height {
                Some(h) if h.to_lowercase() == "latest" => json!("latest"),
                Some(h) => json!(h.parse::<u64>()?),
                None => json!("latest"),
            };
            let root = provider.get_state_root(param).await?;
            println!("{root}");
        }
    }
    Ok(())
}

fn parse_alkane_id_u64(id: &str) -> anyhow::Result<(u64, u64)> {
    let parts: Vec<&str> = id.split(':').collect();
    if parts.len() != 2 { return Err(anyhow::anyhow!("Invalid alkane ID format. Expected 'block:tx'")); }
    Ok((parts[0].parse()?, parts[1].parse()?))
}

fn decode_get_all_pools(data_hex: &str) -> Option<(usize, Vec<(u64, u64)>)> {
    fn strip_0x(s: &str) -> &str { s.strip_prefix("0x").unwrap_or(s) }
    let clean = strip_0x(data_hex);
    if clean.len() < 32 { return None; }
    let mut count_bytes = hex::decode(&clean[0..32]).ok()?; count_bytes.reverse();
    let count = u128::from_str_radix(&hex::encode(count_bytes), 16).ok()? as usize;
    let mut pools = Vec::new();
    for i in 0..count {
        let off = 32 + i * 64; if clean.len() < off + 64 { break; }
        let block_hex = &clean[off..off+32]; let tx_hex = &clean[off+32..off+64];
        let mut block_b = hex::decode(block_hex).ok()?; block_b.reverse();
        let mut tx_b = hex::decode(tx_hex).ok()?; tx_b.reverse();
        if block_b.len() < 8 || tx_b.len() < 8 { return None; }
        // After reversing to big-endian, the low 8 bytes are at the tail
        let mut bl=[0u8;8]; bl.copy_from_slice(&block_b[block_b.len()-8..]);
        let mut tl=[0u8;8]; tl.copy_from_slice(&tx_b[tx_b.len()-8..]);
        pools.push((u64::from_be_bytes(bl), u64::from_be_bytes(tl)));
    }
    Some((pools.len(), pools))
}

fn decode_pool_details(data_hex: &str) -> Option<((u64,u64),(u64,u64),u64,u64,u64,String)> {
    if data_hex == "0x" { return None; }
    let bytes = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex)).ok()?;
    fn u64_le(b:&[u8], o:usize)->Option<u64>{ if b.len()<o+8 {None} else { let mut x=[0u8;8]; x.copy_from_slice(&b[o..o+8]); Some(u64::from_le_bytes(x)) } }
    let t0 = (u64_le(&bytes,0)?, u64_le(&bytes,16)?);
    let t1 = (u64_le(&bytes,32)?, u64_le(&bytes,48)?);
    let a0 = u64_le(&bytes,64)?; let a1 = u64_le(&bytes,80)?; let supply = u64_le(&bytes,96)?;
    let name = if bytes.len()>116 { String::from_utf8_lossy(&bytes[116..]).to_string() } else { String::new() };
    Some((t0,t1,a0,a1,supply,name))
}

async fn execute_amm_command(
    provider: &dyn DeezelProvider,
    command: AmmCommands,
) -> anyhow::Result<()> {
    match command {
        AmmCommands::GetAllPools { factory_id, raw } => {
            let (b,t) = parse_alkane_id_u64(&factory_id)?;
            let url = std::env::var("SANDSHREW_RPC_URL")
                .or_else(|_| std::env::var("METASHREW_RPC_URL"))
                .unwrap_or_else(|_| "http://localhost:18888".to_string());
            let params = serde_json::json!([{
                "alkanes": [],
                "transaction": "0x",
                "block": "0x",
                "height": "20000",
                "txindex": 0,
                "target": { "block": b.to_string(), "tx": t.to_string() },
                "inputs": ["3"],
                "pointer": 0,
                "refundPointer": 0,
                "vout": 0
            }]);
            let result = provider.call(&url, "alkanes_simulate", params, 1).await?;
            let data_hex = result.get("execution").and_then(|e| e.get("data")).and_then(|v| v.as_str()).unwrap_or("0x");
            if let Some((count, pools)) = decode_get_all_pools(data_hex) {
                if raw { println!("{}", serde_json::to_string_pretty(&serde_json::json!({"count":count,"pools":pools.iter().map(|(bb,tt)| format!("{}:{}",bb,tt)).collect::<Vec<_>>() }))?); }
                else { println!("Found {} pools", count); for (pb,pt) in pools { println!("- {}:{}", pb, pt); } }
            } else { println!("No pools found or failed to decode"); }
        }
        AmmCommands::AllPoolsDetails { factory_id, raw } => {
            let (b,t) = parse_alkane_id_u64(&factory_id)?;
            let url = std::env::var("SANDSHREW_RPC_URL")
                .or_else(|_| std::env::var("METASHREW_RPC_URL"))
                .unwrap_or_else(|_| "http://localhost:18888".to_string());
            let params = serde_json::json!([{
                "alkanes": [],
                "transaction": "0x",
                "block": "0x",
                "height": "20000",
                "txindex": 0,
                "target": { "block": b.to_string(), "tx": t.to_string() },
                "inputs": ["3"],
                "pointer": 0,
                "refundPointer": 0,
                "vout": 0
            }]);
            let result = provider.call(&url, "alkanes_simulate", params, 1).await?;
            let data_hex = result.get("execution").and_then(|e| e.get("data")).and_then(|v| v.as_str()).unwrap_or("0x");
            let mut out = Vec::new();
            if let Some((_, pools)) = decode_get_all_pools(data_hex) {
                for (pb, pt) in pools {
                    let pparams = serde_json::json!([{
                        "alkanes": [],
                        "transaction": "0x",
                        "block": "0x",
                        "height": "20000",
                        "txindex": 0,
                        "target": { "block": pb.to_string(), "tx": pt.to_string() },
                        "inputs": ["999"],
                        "pointer": 0,
                        "refundPointer": 0,
                        "vout": 0
                    }]);
                    if let Ok(res) = provider.call(&url, "alkanes_simulate", pparams, 1).await { // POOL_DETAILS
                        if let Some(data) = res.get("execution").and_then(|e| e.get("data")).and_then(|v| v.as_str()) {
                            if let Some(((t0b,t0t),(t1b,t1t),a0,a1,supply,name)) = decode_pool_details(data) {
                                out.push(serde_json::json!({
                                    "poolId": format!("{}:{}", pb, pt),
                                    "token0": {"block": t0b, "tx": t0t},
                                    "token1": {"block": t1b, "tx": t1t},
                                    "token0Amount": a0,
                                    "token1Amount": a1,
                                    "tokenSupply": supply,
                                    "poolName": name,
                                }));
                            }
                        }
                    }
                }
            }
            let out_json = serde_json::json!({"count": out.len(), "pools": out});
            if raw { println!("{}", serde_json::to_string_pretty(&out_json)?); }
            else { println!("Pools with details: {}", out.len()); println!("{}", serde_json::to_string_pretty(&out_json)?); }
        }
    }
    Ok(())
}

async fn execute_wallet_command<T: System + UtxoProvider>(system: &mut T, command: WalletCommands) -> Result<()> {
    match command {
        WalletCommands::Utxos { addresses, raw, include_frozen } => {
            let resolved_addresses = if let Some(addrs) = addresses {
                let resolved = system.provider().resolve_all_identifiers(&addrs).await?;
                Some(resolved.split(',').map(|s| s.trim().to_string()).collect())
            } else {
                None
            };
            let utxos = system.provider().get_utxos(include_frozen, resolved_addresses).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&utxos)?);
            } else {
                print_utxos(&utxos);
            }
        }
        WalletCommands::Send { address, amount, fee_rate, send_all, from, change_address, auto_confirm } => {
            let params = deezel_common::traits::SendParams {
                address,
                amount,
                fee_rate,
                send_all,
                from,
                change_address,
                auto_confirm,
            };
            let txid = system.provider_mut().send(params).await?;
            println!("Transaction sent: {txid}");
        }
        WalletCommands::Balance { addresses, raw } => {
            let balance = WalletProvider::get_balance(system.provider(), addresses).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&balance)?);
            } else {
                println!("Confirmed: {}", balance.confirmed);
                println!("Pending:   {}", balance.pending);
            }
        }
        WalletCommands::History { count, address, raw } => {
            let history = system.provider().get_history(count, address).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&history)?);
            } else {
                print_history(&history);
            }
        }
        _ => {
            system.execute_wallet_command(command.into()).await?;
        }
    }
    Ok(())
}

async fn execute_alkanes_command<T: System>(system: &mut T, command: Alkanes) -> Result<()> {
    match command {
        Alkanes::Execute(exec_args) => {
            let params = to_enhanced_execute_params(exec_args)?;
            let mut executor = alkanes::execute::EnhancedAlkanesExecutor::new(system.provider_mut());
            let mut state = executor.execute(params.clone()).await?;

            loop {
                state = match state {
                    alkanes::types::ExecutionState::ReadyToSign(s) => {
                        let result = executor.resume_execution(s, &params).await?;
                        println!("✅ Alkanes execution completed successfully!");
                        println!("🔗 Reveal TXID: {}", result.reveal_txid);
                        println!("💰 Reveal Fee: {} sats", result.reveal_fee);
                        if let Some(traces) = result.traces {
                            println!("🔍 Traces: {}", serde_json::to_string_pretty(&traces)?);
                        }
                        break;
                    },
                    alkanes::types::ExecutionState::ReadyToSignCommit(s) => {
                        executor.resume_commit_execution(s).await?
                    },
                    alkanes::types::ExecutionState::ReadyToSignReveal(s) => {
                        let result = executor.resume_reveal_execution(s).await?;
                        println!("✅ Alkanes execution completed successfully!");
                        if let Some(commit_txid) = result.commit_txid {
                            println!("🔗 Commit TXID: {commit_txid}");
                        }
                        println!("🔗 Reveal TXID: {}", result.reveal_txid);
                        if let Some(commit_fee) = result.commit_fee {
                            println!("💰 Commit Fee: {commit_fee} sats");
                        }
                        println!("💰 Reveal Fee: {} sats", result.reveal_fee);
                        if let Some(traces) = result.traces {
                            println!("🔍 Traces: {}", serde_json::to_string_pretty(&traces)?);
                        }
                        break;
                    },
                    alkanes::types::ExecutionState::Complete(result) => {
                        println!("✅ Alkanes execution completed successfully!");
                        if let Some(commit_txid) = result.commit_txid {
                            println!("🔗 Commit TXID: {commit_txid}");
                        }
                        println!("🔗 Reveal TXID: {}", result.reveal_txid);
                        if let Some(commit_fee) = result.commit_fee {
                            println!("💰 Commit Fee: {commit_fee} sats");
                        }
                        println!("💰 Reveal Fee: {} sats", result.reveal_fee);
                        if let Some(traces) = result.traces {
                            println!("🔍 Traces: {}", serde_json::to_string_pretty(&traces)?);
                        }
                        break;
                    }
                };
            }
            Ok(())
        },
        Alkanes::Inspect { outpoint, disasm, fuzz, fuzz_ranges, meta, codehash, raw } => {
            let config = alkanes::types::AlkanesInspectConfig {
                disasm,
                fuzz,
                fuzz_ranges,
                meta,
                codehash,
                raw,
            };
            let result = system.provider().inspect(&outpoint, config).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                pretty_print::print_inspection_result(&result);
            }
            Ok(())
        },
        Alkanes::Trace { outpoint, raw } => {
            let result = system.provider().trace(&outpoint).await;
            match result {
                Ok(trace_val) => {
                    let trace: deezel_common::alkanes::trace::Trace = trace_val.into();
                    if raw {
                        println!("{:?}", trace);
                    } else {
                        println!("{trace}");
                    }
                }
                Err(e) => {
                    println!("Error: {e}");
                }
            }
            Ok(())
        },
        Alkanes::Simulate { contract_id, params, raw } => {
            let result = system.provider().simulate(&contract_id, params.as_deref()).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Simulation result: {}", serde_json::to_string_pretty(&result)?);
            }
            Ok(())
        },
        Alkanes::SimulateRaw { request, request_file, raw } => {
            // Load request JSON from --request or --request-file
            let req_str = if let Some(r) = request {
                if let Some(path) = r.strip_prefix('@') { std::fs::read_to_string(path)? } else { r }
            } else if let Some(path) = request_file {
                std::fs::read_to_string(path)?
            } else {
                return Err(anyhow::anyhow!("Provide --request '<JSON>' or --request-file <path>"));
            };

            let json_val: serde_json::Value = serde_json::from_str(&req_str)?;
            // Ensure it's an array (params array for JSON-RPC)
            let params = match json_val {
                serde_json::Value::Array(a) => serde_json::Value::Array(a),
                _ => serde_json::Value::Array(vec![json_val]),
            };

            // Use single Sandshrew/Metashrew URL (SANDSHREW_RPC_URL env/flag already wired into provider)
            let result = system.provider().call(
                &system.provider().get_esplora_api_url().unwrap_or_else(|| "http://localhost:18888".to_string()),
                "alkanes_simulate",
                params,
                1,
            ).await?;

            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            Ok(())
        },
        Alkanes::Sequence { outpoint, raw } => {
            let parts: Vec<&str> = outpoint.split(':').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid outpoint format. Expected txid:vout"));
            }
            let txid = parts[0];
            let vout = parts[1].parse::<u32>()?;
            let result = system.provider().sequence(txid, vout).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Sequence: {}", serde_json::to_string_pretty(&result)?);
            }
            Ok(())
        },
        Alkanes::Spendables { address, raw } => {
            let result = system.provider().spendables_by_address(&address).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Spendables: {}", serde_json::to_string_pretty(&result)?);
            }
            Ok(())
        },
        Alkanes::TraceBlock { height, raw } => {
            let result = system.provider().trace_block(height).await?;
            if raw {
                println!("{:?}", result);
            } else {
                println!("Trace: {:?}", result);
            }
            Ok(())
        },
        Alkanes::GetBytecode { alkane_id, raw } => {
            let result = AlkanesProvider::get_bytecode(system.provider(), &alkane_id).await?;
            if raw {
                println!("{result}");
            } else {
                println!("Bytecode: {result}");
            }
            Ok(())
        },
        Alkanes::GetBalance { address, raw } => {
            let result = AlkanesProvider::get_balance(system.provider(), address.as_deref()).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                print_alkane_balances(&result);
            }
            Ok(())
        }
    }
}

fn to_enhanced_execute_params(args: AlkanesExecute) -> Result<alkanes::types::EnhancedExecuteParams> {
    let input_requirements = args.inputs.map(|s| alkanes::parsing::parse_input_requirements(&s)).transpose()?.unwrap_or_default();
    let protostones = alkanes::parsing::parse_protostones(&args.protostones.join(" "))?;
    let envelope_data = args.envelope.map(std::fs::read).transpose()?;

    Ok(alkanes::types::EnhancedExecuteParams {
        input_requirements,
        to_addresses: args.to,
        from_addresses: args.from,
        change_address: args.change,
        fee_rate: args.fee_rate,
        envelope_data,
        protostones,
        raw_output: args.raw,
        trace_enabled: args.trace,
        mine_enabled: args.mine,
        auto_confirm: args.auto_confirm,
    })
}

async fn execute_runestone_command<T: System>(system: &mut T, command: Runestone) -> Result<()> {
    match command {
        Runestone::Analyze { txid, raw } => {
            let tx_hex = system.provider().get_transaction_hex(&txid).await?;
            let tx_bytes = hex::decode(tx_hex)?;
            let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)?;
            let result = deezel_common::runestone_enhanced::format_runestone_with_decoded_messages(&tx)?;
            
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                deezel_common::runestone_enhanced::print_human_readable_runestone(&tx, &result);
            }
        }
    }
    Ok(())
}



async fn execute_esplora_command(
    provider: &dyn DeezelProvider,
    command: deezel_common::commands::EsploraCommands,
) -> anyhow::Result<()> {
    match command {
        deezel_common::commands::EsploraCommands::BlocksTipHash { raw } => {
            let hash = provider.get_blocks_tip_hash().await?;
            if raw {
                println!("{hash}");
            } else {
                println!("⛓️ Tip Hash: {hash}");
            }
        }
        deezel_common::commands::EsploraCommands::BlocksTipHeight { raw } => {
            let height = provider.get_blocks_tip_height().await?;
            if raw {
                println!("{height}");
            } else {
                println!("📈 Tip Height: {height}");
            }
        }
        deezel_common::commands::EsploraCommands::Blocks { start_height, raw } => {
            let result = provider.get_blocks(start_height).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("📦 Blocks:\n{}", serde_json::to_string_pretty(&result)?);
            }
        }
        deezel_common::commands::EsploraCommands::BlockHeight { height, raw } => {
            let hash = provider.get_block_by_height(height).await?;
            if raw {
                println!("{hash}");
            } else {
                println!("🔗 Block Hash at {height}: {hash}");
            }
        }
        deezel_common::commands::EsploraCommands::Block { hash, raw } => {
            let block = <dyn EsploraProvider>::get_block(provider, &hash).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&block)?);
            } else {
                println!("📦 Block {}:\n{}", hash, serde_json::to_string_pretty(&block)?);
            }
        }
        deezel_common::commands::EsploraCommands::BlockStatus { hash, raw } => {
            let status = provider.get_block_status(&hash).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("ℹ️ Block Status {}:\n{}", hash, serde_json::to_string_pretty(&status)?);
            }
        }
        deezel_common::commands::EsploraCommands::BlockTxids { hash, raw } => {
            let txids = provider.get_block_txids(&hash).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&txids)?);
            } else {
                println!("📄 Block Txids {}:\n{}", hash, serde_json::to_string_pretty(&txids)?);
            }
        }
        deezel_common::commands::EsploraCommands::BlockHeader { hash, raw } => {
            let header = provider.get_block_header(&hash).await?;
            if raw {
                println!("{header}");
            } else {
                println!("📄 Block Header {hash}: {header}");
            }
        }
        deezel_common::commands::EsploraCommands::BlockRaw { hash, raw } => {
            let raw_block = provider.get_block_raw(&hash).await?;
            if raw {
                println!("{raw_block}");
            } else {
                println!("📦 Raw Block {hash}: {raw_block}");
            }
        }
        deezel_common::commands::EsploraCommands::BlockTxid { hash, index, raw } => {
            let txid = provider.get_block_txid(&hash, index).await?;
            if raw {
                println!("{txid}");
            } else {
                println!("📄 Txid at index {index} in block {hash}: {txid}");
            }
        }
        deezel_common::commands::EsploraCommands::BlockTxs { hash, start_index, raw } => {
            let txs = provider.get_block_txs(&hash, start_index).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&txs)?);
            } else {
                println!("📄 Transactions in block {}:\n{}", hash, serde_json::to_string_pretty(&txs)?);
            }
        }
        deezel_common::commands::EsploraCommands::Address { params, raw } => {
            let result = <dyn EsploraProvider>::get_address(provider, &params).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("🏠 Address {}:\n{}", params, serde_json::to_string_pretty(&result)?);
            }
        }
        deezel_common::commands::EsploraCommands::AddressTxs { params, raw } => {
            let result = provider.get_address_txs(&params).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("📄 Transactions for address {}:\n{}", params, serde_json::to_string_pretty(&result)?);
            }
        }
        deezel_common::commands::EsploraCommands::AddressTxsChain { params, raw } => {
            let result = provider.get_address_txs_chain(&params, None).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("⛓️ Chain transactions for address {}:\n{}", params, serde_json::to_string_pretty(&result)?);
            }
        }
        deezel_common::commands::EsploraCommands::AddressTxsMempool { address, raw } => {
            let result = provider.get_address_txs_mempool(&address).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("⏳ Mempool transactions for address {}:\n{}", address, serde_json::to_string_pretty(&result)?);
            }
        }
        deezel_common::commands::EsploraCommands::AddressUtxo { address, raw } => {
            let result = provider.get_address_utxo(&address).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("💰 UTXOs for address {}:\n{}", address, serde_json::to_string_pretty(&result)?);
            }
        }
        deezel_common::commands::EsploraCommands::AddressPrefix { prefix, raw } => {
            let result = provider.get_address_prefix(&prefix).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("🔍 Addresses with prefix '{}':\n{}", prefix, serde_json::to_string_pretty(&result)?);
            }
        }
        deezel_common::commands::EsploraCommands::Tx { txid, raw } => {
            let tx = provider.get_tx(&txid).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&tx)?);
            } else {
                println!("📄 Transaction {}:\n{}", txid, serde_json::to_string_pretty(&tx)?);
            }
        }
        deezel_common::commands::EsploraCommands::TxHex { txid, .. } => {
            let hex = provider.get_tx_hex(&txid).await?;
            println!("{hex}");
        }
        deezel_common::commands::EsploraCommands::TxRaw { txid, .. } => {
            let raw_tx = provider.get_tx_raw(&txid).await?;
            println!("{}", hex::encode(raw_tx));
        }
        deezel_common::commands::EsploraCommands::TxStatus { txid, raw } => {
            let status = provider.get_tx_status(&txid).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("ℹ️ Status for tx {}:\n{}", txid, serde_json::to_string_pretty(&status)?);
            }
        }
        deezel_common::commands::EsploraCommands::TxMerkleProof { txid, raw } => {
            let proof = provider.get_tx_merkle_proof(&txid).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&proof)?);
            } else {
                println!("🧾 Merkle proof for tx {}:\n{}", txid, serde_json::to_string_pretty(&proof)?);
            }
        }
        deezel_common::commands::EsploraCommands::TxMerkleblockProof { txid, .. } => {
            let proof = provider.get_tx_merkleblock_proof(&txid).await?;
            println!("{proof}");
        }
        deezel_common::commands::EsploraCommands::TxOutspend { txid, index, raw } => {
            let outspend = provider.get_tx_outspend(&txid, index).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&outspend)?);
            } else {
                println!("💸 Outspend for tx {}, vout {}:\n{}", txid, index, serde_json::to_string_pretty(&outspend)?);
            }
        }
        deezel_common::commands::EsploraCommands::TxOutspends { txid, raw } => {
            let outspends = provider.get_tx_outspends(&txid).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&outspends)?);
            } else {
                println!("💸 Outspends for tx {}:\n{}", txid, serde_json::to_string_pretty(&outspends)?);
            }
        }
        deezel_common::commands::EsploraCommands::Broadcast { tx_hex, .. } => {
            let txid = provider.broadcast(&tx_hex).await?;
            println!("✅ Transaction broadcast successfully!");
            println!("🔗 Transaction ID: {txid}");
        }
        deezel_common::commands::EsploraCommands::PostTx { tx_hex, .. } => {
            let txid = provider.broadcast(&tx_hex).await?;
            println!("✅ Transaction posted successfully!");
            println!("🔗 Transaction ID: {txid}");
        }
        deezel_common::commands::EsploraCommands::Mempool { raw } => {
            let mempool = provider.get_mempool().await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&mempool)?);
            } else {
                println!("⏳ Mempool Info:\n{}", serde_json::to_string_pretty(&mempool)?);
            }
        }
        deezel_common::commands::EsploraCommands::MempoolTxids { raw } => {
            let txids = provider.get_mempool_txids().await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&txids)?);
            } else {
                println!("📄 Mempool Txids:\n{}", serde_json::to_string_pretty(&txids)?);
            }
        }
        deezel_common::commands::EsploraCommands::MempoolRecent { raw } => {
            let recent = provider.get_mempool_recent().await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&recent)?);
            } else {
                println!("📄 Recent Mempool Txs:\n{}", serde_json::to_string_pretty(&recent)?);
            }
        }
        deezel_common::commands::EsploraCommands::FeeEstimates { raw } => {
            let estimates = provider.get_fee_estimates().await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&estimates)?);
            } else {
                println!("💰 Fee Estimates:\n{}", serde_json::to_string_pretty(&estimates)?);
            }
        }
    }
    Ok(())
}

async fn execute_ord_command(
    provider: &dyn DeezelProvider,
    command: deezel_common::commands::OrdCommands,
) -> anyhow::Result<()> {
    match command {
        deezel_common::commands::OrdCommands::Inscription { id, raw } => {
            if raw {
                let inscription = provider.get_inscription(&id).await?;
                let json_value = serde_json::to_value(&inscription)?;
                if let Some(s) = json_value.as_str() {
                    println!("{s}");
                } else {
                    println!("{json_value}");
                }
            } else {
                let inscription = provider.get_inscription(&id).await?;
                print_inscription(&inscription);
            }
        }
        deezel_common::commands::OrdCommands::InscriptionsInBlock { hash, raw } => {
            if raw {
                let inscriptions = provider.get_inscriptions_in_block(&hash).await?;
                let json_value = serde_json::to_value(&inscriptions)?;
                if let Some(s) = json_value.as_str() {
                    println!("{s}");
                } else {
                    println!("{json_value}");
                }
            } else {
                let inscriptions = provider.get_inscriptions_in_block(&hash).await?;
                let inscription_futures = inscriptions.ids.into_iter().map(|id| {
                    let provider = provider;
                    async move { provider.get_inscription(&id.to_string()).await }
                });
                let results: Vec<_> = join_all(inscription_futures).await;
                let fetched_inscriptions: Result<Vec<_>, _> = results.into_iter().collect();
                print_inscriptions(&fetched_inscriptions?);
            }
        }
        deezel_common::commands::OrdCommands::AddressInfo { address, raw } => {
            if raw {
                let info = provider.get_ord_address_info(&address).await?;
                let json_value = serde_json::to_value(&info)?;
                if let Some(s) = json_value.as_str() {
                    println!("{s}");
                } else {
                    println!("{json_value}");
                }
            } else {
                let info = provider.get_ord_address_info(&address).await?;
                print_address_info(&info);
            }
        }
        deezel_common::commands::OrdCommands::BlockInfo { query, raw } => {
            if raw {
                let info = provider.get_block_info(&query).await?;
                let json_value = serde_json::to_value(&info)?;
                if let Some(s) = json_value.as_str() {
                    println!("{s}");
                } else {
                    println!("{json_value}");
                }
            } else {
                let info = provider.get_block_info(&query).await?;
                if let Some(info) = info.info {
                    print_block_info(&info);
                } else {
                    println!("Block info not available.");
                }
            }
        }
        deezel_common::commands::OrdCommands::BlockCount => {
            let info = provider.get_ord_block_count().await?;
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        deezel_common::commands::OrdCommands::Blocks { raw } => {
            if raw {
                let info = provider.get_ord_blocks().await?;
                let json_value = serde_json::to_value(&info)?;
                if let Some(s) = json_value.as_str() {
                    println!("{s}");
                } else {
                    println!("{json_value}");
                }
            } else {
                let info = provider.get_ord_blocks().await?;
                print_blocks(&info);
            }
        }
        deezel_common::commands::OrdCommands::Children { id, page, raw } => {
            if raw {
                let children = provider.get_children(&id, page).await?;
                let json_value = serde_json::to_value(&children)?;
                if let Some(s) = json_value.as_str() {
                    println!("{s}");
                } else {
                    println!("{json_value}");
                }
            } else {
                let children = provider.get_children(&id, page).await?;
                let inscription_futures = children.ids.into_iter().map(|id| {
                    let provider = provider;
                    async move { provider.get_inscription(&id.to_string()).await }
                });
                let results: Vec<_> = join_all(inscription_futures).await;
                let fetched_inscriptions: Result<Vec<_>, _> = results.into_iter().collect();
                print_children(&fetched_inscriptions?);
            }
        }
        deezel_common::commands::OrdCommands::Content { id } => {
            let content = provider.get_content(&id).await?;
            use std::io::{self, Write};
            io::stdout().write_all(&content)?;
        }
        deezel_common::commands::OrdCommands::Inscriptions { page, raw } => {
            if raw {
                let inscriptions = provider.get_inscriptions(page).await?;
                let json_value = serde_json::to_value(&inscriptions)?;
                if let Some(s) = json_value.as_str() {
                    println!("{s}");
                } else {
                    println!("{json_value}");
                }
            } else {
                let inscriptions = provider.get_inscriptions(page).await?;
                let inscription_futures = inscriptions.ids.into_iter().map(|id| {
                    let provider = provider;
                    async move { provider.get_inscription(&id.to_string()).await }
                });
                let results: Vec<_> = join_all(inscription_futures).await;
                let fetched_inscriptions: Result<Vec<_>, _> = results.into_iter().collect();
                print_inscriptions(&fetched_inscriptions?);
            }
        }
        deezel_common::commands::OrdCommands::Output { outpoint, raw } => {
            if raw {
                let output = provider.get_output(&outpoint).await?;
                let json_value = serde_json::to_value(&output)?;
                if let Some(s) = json_value.as_str() {
                    println!("{s}");
                } else {
                    println!("{json_value}");
                }
            } else {
                let output = provider.get_output(&outpoint).await?;
                print_output(&output);
            }
        }
        deezel_common::commands::OrdCommands::Parents { id, page, raw } => {
            if raw {
                let parents = provider.get_parents(&id, page).await?;
                let json_value = serde_json::to_value(&parents)?;
                if let Some(s) = json_value.as_str() {
                    println!("{s}");
                } else {
                    println!("{json_value}");
                }
            } else {
                let parents = provider.get_parents(&id, page).await?;
                print_parents(&parents);
            }
        }
        deezel_common::commands::OrdCommands::Rune { rune, raw } => {
            if raw {
                let rune_info = provider.get_rune(&rune).await?;
                let json_value = serde_json::to_value(&rune_info)?;
                if let Some(s) = json_value.as_str() {
                    println!("{s}");
                } else {
                    println!("{json_value}");
                }
            } else {
                let rune_info = provider.get_rune(&rune).await?;
                print_rune(&rune_info);
            }
        }
        deezel_common::commands::OrdCommands::Runes { page, raw } => {
            if raw {
                let runes = provider.get_runes(page).await?;
                let json_value = serde_json::to_value(&runes)?;
                if let Some(s) = json_value.as_str() {
                    println!("{s}");
                } else {
                    println!("{json_value}");
                }
            } else {
                let runes = provider.get_runes(page).await?;
                print_runes(&runes);
            }
        }
        deezel_common::commands::OrdCommands::Sat { sat, raw } => {
            if raw {
                let sat_info = provider.get_sat(sat).await?;
                let json_value = serde_json::to_value(&sat_info)?;
                if let Some(s) = json_value.as_str() {
                    println!("{s}");
                } else {
                    println!("{json_value}");
                }
            } else {
                let sat_info = provider.get_sat(sat).await?;
                print_sat_response(&sat_info);
            }
        }
        deezel_common::commands::OrdCommands::TxInfo { txid, raw } => {
            if raw {
                let tx_info = provider.get_tx_info(&txid).await?;
                let json_value = serde_json::to_value(&tx_info)?;
                if let Some(s) = json_value.as_str() {
                    println!("{s}");
                } else {
                    println!("{json_value}");
                }
            } else {
                let tx_info = provider.get_tx_info(&txid).await?;
                print_tx_info(&tx_info);
            }
        }
    }
    Ok(())
}

async fn execute_protorunes_command(
    provider: &dyn DeezelProvider,
    command: Protorunes,
) -> anyhow::Result<()> {
    match command {
        Protorunes::ByAddress {
            address,
            raw,
            block_tag,
            protocol_tag,
        } => {
            let result = provider
                .protorunes_by_address(&address, block_tag, protocol_tag)
                .await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                pretty_print::print_protorune_wallet_response(&result);
            }
        }
        Protorunes::ByOutpoint {
            outpoint,
            raw,
            block_tag,
            protocol_tag,
        } => {
            let parts: Vec<&str> = outpoint.split(':').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid outpoint format. Expected txid:vout"));
            }
            let txid = parts[0].to_string();
            let vout = parts[1].parse::<u32>()?;
            let result = provider
                .protorunes_by_outpoint(&txid, vout, block_tag, protocol_tag)
                .await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                pretty_print::print_protorune_outpoint_response(&result);
            }
        }
    }
    Ok(())
}
