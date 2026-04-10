//! Model Context Protocol implementation.
//!
//! MCP uses JSON-RPC 2.0 over a stdio transport with newline-delimited
//! messages. Each message is a complete JSON-RPC envelope on its own line.
//!
//! Reference: <https://spec.modelcontextprotocol.io/>

pub mod jsonrpc;
pub mod messages;
pub mod stdio;

pub use jsonrpc::{Request, Response, ResponseError, Notification};
pub use messages::{
    InitializeParams, InitializeResult, ServerInfo, ServerCapabilities,
    ListToolsResult, Tool, ToolInputSchema,
    CallToolParams, CallToolResult, ToolContent,
};
pub use stdio::StdioTransport;
