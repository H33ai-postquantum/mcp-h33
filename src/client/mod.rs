//! H33 backend HTTP client.
//!
//! Wraps the H33 REST API exposed by `scif-backend` and `auth1-delivery-rs`.
//! All MCP tool dispatch ultimately routes through this client.

pub mod h33_api;

pub use h33_api::H33ApiClient;
