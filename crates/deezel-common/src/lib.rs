#![cfg_attr(not(feature = "std"), no_std)]

//! Deezel Common Library
//!
//! This library provides the core functionality for the deezel project,
//! designed to be WASM-compatible and platform-agnostic.
//!
//! The library is structured around trait abstractions that allow the same
//! business logic to work across different environments:
//! - Native CLI applications
//! - WASM web applications
//! - Testing environments
//!
//! ## Architecture
//!
//! The library is organized into several key modules:
//! - `traits`: Core trait abstractions for platform independence
//! - `wallet`: Bitcoin wallet functionality with BDK integration
//! - `alkanes`: Smart contract operations and inspection
//! - `runestone`: Runestone analysis and decoding
//! - `network`: Network parameter management
//! - `rpc`: RPC client abstractions
//! - `address_resolver`: Address identifier resolution
//! - `monitor`: Blockchain monitoring
//! - `transaction`: Transaction construction and signing
//! - `utils`: Common utilities
pub mod provider;

extern crate alloc;

#[cfg(not(feature = "std"))]
pub use alloc::{
    string::{String, ToString},
    format,
    vec,
    vec::Vec,
};

#[cfg(feature = "std")]
pub use std::{
    string::{String, ToString},
    format,
    vec,
    vec::Vec,
};

pub mod vendored_ord;

// Core modules
pub mod address;
#[cfg(feature = "std")]
pub mod commands;
pub mod traits;
pub mod network;
pub mod rpc;
pub mod alkanes;
pub mod wallet;
pub mod address_resolver;
pub mod runestone;
pub mod runestone_enhanced;
pub mod transaction;
pub mod monitor;
pub mod utils;
pub mod keystore;
pub mod pgp_rpgp;
pub mod esplora;
pub mod bitcoind;
pub mod ord;

// Re-export key types and traits for convenience
pub use traits::*;
pub use network::NetworkParams;
pub use rpc::{RpcClient, RpcConfig, RpcRequest, RpcResponse};

// Re-export common types for WASM compatibility - already imported above

// Re-export external types for convenience
pub use bitcoin::{Network, Transaction, Address, ScriptBuf};
pub use ordinals::Runestone;
pub use protorune_support::protostone::Protostone;
pub use serde_json::Value as JsonValue;

/// Error types for the deezel-common library
#[derive(Debug)]
pub enum DeezelError {
    JsonRpc(String),
    RpcError(String),
    Storage(String),
    Network(String),
    Wallet(String),
    Alkanes(String),
    Runestone(String),
    Serialization(String),
    Validation(String),
    Configuration(String),
    InvalidParameters(String),
    AddressResolution(String),
    Transaction(String),
    Monitor(String),
    WasmExecution(String),
    Crypto(String),
    Io(String),
    Parse(String),
    Pgp(String),
    Hex(String),
    NotImplemented(String),
    NotConfigured(String),
    Other(String),
}

impl core::fmt::Display for DeezelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DeezelError::JsonRpc(msg) => write!(f, "JSON-RPC error: {}", msg),
            DeezelError::RpcError(msg) => write!(f, "RPC error: {}", msg),
            DeezelError::Storage(msg) => write!(f, "Storage error: {}", msg),
            DeezelError::Network(msg) => write!(f, "Network error: {}", msg),
            DeezelError::Wallet(msg) => write!(f, "Wallet error: {}", msg),
            DeezelError::Alkanes(msg) => write!(f, "Alkanes error: {}", msg),
            DeezelError::Runestone(msg) => write!(f, "Runestone error: {}", msg),
            DeezelError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            DeezelError::Validation(msg) => write!(f, "Validation error: {}", msg),
            DeezelError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            DeezelError::InvalidParameters(msg) => write!(f, "Invalid parameters: {}", msg),
            DeezelError::AddressResolution(msg) => write!(f, "Address resolution error: {}", msg),
            DeezelError::Transaction(msg) => write!(f, "Transaction error: {}", msg),
            DeezelError::Monitor(msg) => write!(f, "Monitoring error: {}", msg),
            DeezelError::WasmExecution(msg) => write!(f, "WASM execution error: {}", msg),
            DeezelError::Crypto(msg) => write!(f, "Cryptography error: {}", msg),
            DeezelError::Io(msg) => write!(f, "I/O error: {}", msg),
            DeezelError::Parse(msg) => write!(f, "Parse error: {}", msg),
            DeezelError::Pgp(msg) => write!(f, "PGP error: {}", msg),
            DeezelError::Hex(msg) => write!(f, "Hex error: {}", msg),
            DeezelError::NotImplemented(msg) => write!(f, "Not implemented: {}", msg),
            DeezelError::NotConfigured(msg) => write!(f, "Not configured: {}", msg),
            DeezelError::Other(msg) => write!(f, "Other error: {}", msg),
        }
    }
}

// WASM-compatible error trait implementation
#[cfg(target_arch = "wasm32")]
impl DeezelError {
    /// Get the error source (WASM-compatible alternative to std::error::Error::source)
    pub fn source(&self) -> Option<&dyn core::fmt::Display> {
        None // For now, we don't chain errors in WASM
    }
}

// Implement error trait for both WASM and non-WASM targets
// This is needed for anyhow compatibility
#[cfg(feature = "std")]
impl std::error::Error for DeezelError {}

// For anyhow compatibility, we need to implement conversion from DeezelError to anyhow::Error
// This is needed for the ? operator to work with anyhow::Result

/// Result type for deezel-common operations
pub type Result<T> = core::result::Result<T, DeezelError>;

/// Convert anyhow::Error to DeezelError
impl From<anyhow::Error> for DeezelError {
    fn from(err: anyhow::Error) -> Self {
        DeezelError::Wallet(alloc::format!("{}", err))
    }
}

/// Convert serde_json::Error to DeezelError
impl From<serde_json::Error> for DeezelError {
    fn from(err: serde_json::Error) -> Self {
        DeezelError::Serialization(alloc::format!("{}", err))
    }
}

impl From<protobuf::Error> for DeezelError {
    fn from(err: protobuf::Error) -> Self {
        DeezelError::Serialization(alloc::format!("Protobuf error: {}", err))
    }
}

impl From<protobuf_json_mapping::PrintError> for DeezelError {
    fn from(err: protobuf_json_mapping::PrintError) -> Self {
        DeezelError::Serialization(format!("Protobuf JSON mapping error: {}", err))
    }
}

impl From<bitcoin::address::ParseError> for DeezelError {
    fn from(err: bitcoin::address::ParseError) -> Self {
        DeezelError::AddressResolution(format!("{:?}", err))
    }
}

impl From<bitcoin::address::FromScriptError> for DeezelError {
    fn from(err: bitcoin::address::FromScriptError) -> Self {
        DeezelError::AddressResolution(format!("{:?}", err))
    }
}


impl From<bitcoin::sighash::TaprootError> for DeezelError {
    fn from(err: bitcoin::sighash::TaprootError) -> Self {
        DeezelError::Transaction(format!("{:?}", err))
    }
}

impl From<bitcoin::sighash::P2wpkhError> for DeezelError {
    fn from(err: bitcoin::sighash::P2wpkhError) -> Self {
        DeezelError::Transaction(format!("{:?}", err))
    }
}

/// Convert bitcoin::consensus::encode::Error to DeezelError
impl From<bitcoin::consensus::encode::Error> for DeezelError {
    fn from(err: bitcoin::consensus::encode::Error) -> Self {
        DeezelError::Transaction(alloc::format!("{}", err))
    }
}

impl From<bitcoin::blockdata::transaction::ParseOutPointError> for DeezelError {
    fn from(err: bitcoin::blockdata::transaction::ParseOutPointError) -> Self {
        DeezelError::Transaction(format!("{:?}", err))
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for DeezelError {
    fn from(err: std::io::Error) -> Self {
        DeezelError::Io(format!("{:?}", err))
    }
}

impl From<bitcoin::psbt::Error> for DeezelError {
    fn from(err: bitcoin::psbt::Error) -> Self {
        DeezelError::Transaction(format!("PSBT error: {}", err))
    }
}

impl From<bitcoin::psbt::ExtractTxError> for DeezelError {
    fn from(err: bitcoin::psbt::ExtractTxError) -> Self {
        DeezelError::Transaction(format!("PSBT extraction error: {}", err))
    }
}


impl From<hex::FromHexError> for DeezelError {
    fn from(err: hex::FromHexError) -> Self {
        DeezelError::Hex(format!("{:?}", err))
    }
}

impl From<core::num::ParseIntError> for DeezelError {
    fn from(err: core::num::ParseIntError) -> Self {
        DeezelError::Parse(format!("Failed to parse integer: {}", err))
    }
}

impl From<bitcoin::hashes::hex::HexToBytesError> for DeezelError {
    fn from(err: bitcoin::hashes::hex::HexToBytesError) -> Self {
        DeezelError::Hex(format!("{:?}", err))
    }
}

impl From<bitcoin::bip32::Error> for DeezelError {
    fn from(err: bitcoin::bip32::Error) -> Self {
        DeezelError::Wallet(format!("{:?}", err))
    }
}

impl From<bip39::ErrorKind> for DeezelError {
    fn from(err: bip39::ErrorKind) -> Self {
        DeezelError::Wallet(format!("BIP39 error: {:?}", err))
    }
}

impl From<bitcoin::secp256k1::Error> for DeezelError {
    fn from(err: bitcoin::secp256k1::Error) -> Self {
        DeezelError::Crypto(format!("{:?}", err))
    }
}

impl From<bitcoin::hashes::hex::HexToArrayError> for DeezelError {
    fn from(err: bitcoin::hashes::hex::HexToArrayError) -> Self {
        DeezelError::Hex(format!("{:?}", err))
    }
}

#[cfg(feature = "native-deps")]
impl From<reqwest::Error> for DeezelError {
    fn from(err: reqwest::Error) -> Self {
        DeezelError::Network(format!("{:?}", err))
    }
}

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Initialize the library (for WASM compatibility)
#[cfg(target_arch = "wasm32")]
pub fn init() {
    // WASM initialization would go here
    // Set up panic hook, logging, etc.
}

/// Initialize the library (no-op for native)
#[cfg(not(target_arch = "wasm32"))]
pub fn init() {
    // No initialization needed for native
}

/// Utility functions for common operations
pub mod prelude {
    pub use crate::traits::*;
    pub use crate::{DeezelError, Result};
    pub use crate::address::{DeezelAddress, NetworkConfig};
    pub use crate::network::NetworkParams;
    pub use crate::rpc::{RpcClient, RpcConfig};
    pub use bitcoin::{Network, Transaction, Address, ScriptBuf};
    pub use ordinals::Runestone;
    pub use protorune_support::protostone::Protostone;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_version_info() {
        // The version is a constant and will never be empty.
        // This assert is for demonstration purposes.
        assert_eq!(NAME, "deezel-common");
    }
    
    #[test]
    fn test_error_conversions() {
        let anyhow_err = anyhow::anyhow!("test error");
        let deezel_err: DeezelError = anyhow_err.into();
        assert!(matches!(deezel_err, DeezelError::Wallet(_)));
        
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let deezel_err: DeezelError = json_err.into();
        assert!(matches!(deezel_err, DeezelError::Serialization(_)));
    }
}