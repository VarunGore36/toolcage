#![no_main]
use libfuzzer_sys::fuzz_target;
use toolcage_proxy::{decode_response_body, header_values, parse_status};

fuzz_target!(|data: &[u8]| {
    // Split head/body at the first \r\n\r\n, then exercise the response
    // parsing path: status line, header extraction, body decoding.
    let head_end = data.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
    let (head, body) = if let Some(p) = head_end {
        (&data[..p], &data[p..])
    } else {
        (data, &b""[..])
    };
    let _ = parse_status(head);
    let _ = header_values(head, "content-encoding");
    let _ = header_values(head, "transfer-encoding");
    let _ = decode_response_body(head, body);
});
