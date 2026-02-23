use std::fs;

use serde::Deserialize;
use vibetunnel_rs::protocol::{control_sock, snapshot, socket_protocol, ws_v3};

#[derive(Debug, Deserialize)]
struct FixtureSet {
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
struct FixtureCase {
    name: String,
    hex: String,
}

fn read_fixture(path: &str) -> FixtureSet {
    let root = env!("CARGO_MANIFEST_DIR");
    let full = format!("{root}/fixtures/{path}");
    let raw = fs::read_to_string(full).expect("read fixture");
    serde_json::from_str(&raw).expect("parse fixture json")
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let s = hex.trim();
    assert_eq!(s.len() % 2, 0, "hex length must be even");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn ws_v3_fixture_roundtrip() {
    let fx = read_fixture("ws_v3.json");

    for case in fx.cases {
        let bytes = hex_to_bytes(&case.hex);
        let decoded = ws_v3::decode_frame(&bytes).expect("decode ws frame");
        let reencoded = ws_v3::encode_frame(&decoded);
        assert_eq!(reencoded, bytes, "fixture mismatch: {}", case.name);
    }
}

#[test]
fn ws_v3_subscribe_payload_parity() {
    let payload = ws_v3::encode_subscribe_payload(7, Some(10), Some(20));
    let decoded = ws_v3::decode_subscribe_payload(&payload).expect("decode subscribe payload");
    assert_eq!(decoded.flags, 7);
    assert_eq!(decoded.snapshot_min_interval_ms, 10);
    assert_eq!(decoded.snapshot_max_interval_ms, 20);

    let payload = ws_v3::encode_subscribe_payload(7, None, None);
    let decoded = ws_v3::decode_subscribe_payload(&payload).expect("decode subscribe payload");
    assert_eq!(decoded.flags, 7);
    assert_eq!(decoded.snapshot_min_interval_ms, 0);
    assert_eq!(decoded.snapshot_max_interval_ms, 0);
}

#[test]
fn ws_v3_resize_payload_parity() {
    let payload = ws_v3::encode_resize_payload(120, 40);
    let decoded = ws_v3::decode_resize_payload(&payload).expect("decode resize payload");
    assert_eq!(decoded.cols, 120);
    assert_eq!(decoded.rows, 40);

    assert!(ws_v3::decode_resize_payload(&payload[..4]).is_none());
}

#[test]
fn ws_v3_decode_accepts_unknown_type_for_forward_compat() {
    let raw = vec![
        0x54, 0x56, // magic LE
        0x03, // version
        0xff, // unknown type
        0x00, 0x00, 0x00, 0x00, // empty session id
        0x00, 0x00, 0x00, 0x00, // empty payload
    ];

    let frame = ws_v3::decode_frame(&raw).expect("decode unknown type frame");
    assert!(matches!(frame.ty, ws_v3::WsV3MessageType::Unknown(0xff)));
    assert_eq!(ws_v3::encode_frame(&frame), raw);
}

#[test]
fn api_socket_fixture_parse_and_encode() {
    let fx = read_fixture("api_socket.json");

    for case in fx.cases {
        let bytes = hex_to_bytes(&case.hex);
        assert!(bytes.len() >= 5, "frame too short for {}", case.name);

        let mut parser = socket_protocol::MessageParser::new();
        parser.add_data(&bytes);
        let parsed = parser.parse_messages();
        assert_eq!(parsed.len(), 1, "expected exactly one message for {}", case.name);

        let msg = &parsed[0];
        let re = socket_protocol::frame_message(msg.ty, &msg.payload);
        assert_eq!(re, bytes, "fixture mismatch: {}", case.name);
    }
}

#[test]
fn api_socket_parser_handles_large_announced_payload_without_dropping_header() {
    let mut parser = socket_protocol::MessageParser::new();
    let header = [
        socket_protocol::MessageType::StdinData.as_u8(),
        0xff,
        0xff,
        0xff,
        0xff,
    ];
    parser.add_data(&header);

    let parsed = parser.parse_messages();
    assert!(parsed.is_empty());
    assert_eq!(parser.pending_bytes(), 5);
}

#[test]
fn api_socket_parser_keeps_unknown_message_type() {
    let bytes = [
        0xff, // unknown type
        0x00, 0x00, 0x00, 0x03, // len=3
        0x61, 0x62, 0x63, // payload "abc"
    ];

    let mut parser = socket_protocol::MessageParser::new();
    parser.add_data(&bytes);
    let parsed = parser.parse_messages();

    assert_eq!(parsed.len(), 1);
    assert!(matches!(parsed[0].ty, socket_protocol::MessageType::Unknown(0xff)));
    assert_eq!(parsed[0].payload, b"abc");
    assert_eq!(socket_protocol::frame_message(parsed[0].ty, &parsed[0].payload), bytes);
}

#[test]
fn control_socket_fixture_parse_and_encode() {
    let fx = read_fixture("control_socket.json");

    for case in fx.cases {
        let bytes = hex_to_bytes(&case.hex);

        let mut parser = control_sock::ControlMessageParser::new();
        parser.add_data(&bytes);
        let parsed = parser.parse_messages();
        assert_eq!(parsed.len(), 1, "expected one control message for {}", case.name);

        let re = control_sock::encode_control_message(&parsed[0]);
        assert_eq!(re, bytes, "fixture mismatch: {}", case.name);

        let single = control_sock::parse_single_message(&bytes).expect("single parse result");
        assert_eq!(single, Some(parsed[0].clone()));
    }
}

#[test]
fn control_socket_parser_rejects_invalid_lengths() {
    // zero-length payload (invalid)
    let mut parser = control_sock::ControlMessageParser::new();
    parser.add_data(&[0, 0, 0, 0]);
    let parsed = parser.parse_messages();
    assert!(parsed.is_empty());

    // too-large payload (invalid)
    let too_large = (control_sock::MAX_MESSAGE_SIZE as u32 + 1).to_be_bytes();
    let mut parser = control_sock::ControlMessageParser::new();
    parser.add_data(&too_large);
    let parsed = parser.parse_messages();
    assert!(parsed.is_empty());
}

#[test]
fn snapshot_known_vectors() {
    let fx = read_fixture("snapshot.json");

    let empty = snapshot::BufferSnapshot {
        cols: 1,
        rows: 1,
        viewport_y: 0,
        cursor_x: 0,
        cursor_y: 0,
        cells: vec![vec![snapshot::BufferCell {
            ch: " ".to_string(),
            width: 1,
            fg: None,
            bg: None,
            attributes: None,
        }]],
    };

    let styled = snapshot::BufferSnapshot {
        cols: 2,
        rows: 1,
        viewport_y: 0,
        cursor_x: 1,
        cursor_y: 0,
        cells: vec![vec![
            snapshot::BufferCell {
                ch: "A".to_string(),
                width: 1,
                fg: None,
                bg: None,
                attributes: None,
            },
            snapshot::BufferCell {
                ch: "B".to_string(),
                width: 1,
                fg: Some(196),
                bg: Some(17),
                attributes: Some(1),
            },
        ]],
    };

    let unicode = snapshot::BufferSnapshot {
        cols: 1,
        rows: 1,
        viewport_y: 0,
        cursor_x: 0,
        cursor_y: 0,
        cells: vec![vec![snapshot::BufferCell {
            ch: "λ".to_string(),
            width: 1,
            fg: Some(0x112233),
            bg: None,
            attributes: None,
        }]],
    };

    let vectors = vec![
        ("single_empty_cell", snapshot::encode_snapshot(&empty)),
        ("ascii_with_style", snapshot::encode_snapshot(&styled)),
        ("unicode_rgb_fg", snapshot::encode_snapshot(&unicode)),
    ];

    for (name, got) in vectors {
        let expected = fx
            .cases
            .iter()
            .find(|c| c.name == name)
            .map(|c| hex_to_bytes(&c.hex))
            .expect("fixture exists");
        assert_eq!(got, expected, "snapshot fixture mismatch for {name}");
    }
}
