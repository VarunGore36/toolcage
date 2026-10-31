//! Fuzz target: the MCP JSON-RPC layer.
//!
//! Untrusted frames are parsed into RpcReq and validated (the supervisor
//! serves this over stdio to a guest-controlled client). Any panic is a
//! parser bug; any response must serialize as valid JSON-RPC 2.0 — exactly
//! one of `result`/`error`, never both, never neither.
#![no_main]
use libfuzzer_sys::fuzz_target;
use serde_json::from_slice;
use toolcage_mcp::{RpcReq, RpcResp};

fuzz_target!(|data: &[u8]| {
    // Malformed frames must Err, never panic.
    if let Ok(req) = from_slice::<RpcReq>(data) {
        let _ = req.validate();
        let id = req.id.clone().unwrap_or(serde_json::Value::Null);
        for resp in [
            RpcResp::ok(id.clone(), serde_json::Value::Null),
            RpcResp::deny(id.clone(), &["r".into()]),
            RpcResp::error(id, -32600, "bad"),
        ] {
            let s = serde_json::to_string(&resp).expect("response serializes");
            let v: serde_json::Value = from_slice(s.as_bytes()).expect("response is JSON");
            let has_result = v.get("result").is_some();
            let has_error = v.get("error").is_some();
            assert!(
                has_result ^ has_error,
                "JSON-RPC 2.0: exactly one of result/error, got {s}"
            );
        }
    }
});
