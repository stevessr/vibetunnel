pub const WS_V3_MAGIC: u16 = 0x5654;
pub const WS_V3_VERSION: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsV3MessageType {
    Hello,
    Welcome,
    Subscribe,
    Unsubscribe,
    Stdout,
    SnapshotVt,
    Event,
    Error,
    InputText,
    InputKey,
    Resize,
    Kill,
    ResetSize,
    Ping,
    Pong,
    Unknown(u8),
}

impl WsV3MessageType {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Hello => 1,
            Self::Welcome => 2,
            Self::Subscribe => 10,
            Self::Unsubscribe => 11,
            Self::Stdout => 20,
            Self::SnapshotVt => 21,
            Self::Event => 22,
            Self::Error => 23,
            Self::InputText => 30,
            Self::InputKey => 31,
            Self::Resize => 32,
            Self::Kill => 33,
            Self::ResetSize => 34,
            Self::Ping => 40,
            Self::Pong => 41,
            Self::Unknown(value) => value,
        }
    }
}

impl From<u8> for WsV3MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Hello,
            2 => Self::Welcome,
            10 => Self::Subscribe,
            11 => Self::Unsubscribe,
            20 => Self::Stdout,
            21 => Self::SnapshotVt,
            22 => Self::Event,
            23 => Self::Error,
            30 => Self::InputText,
            31 => Self::InputKey,
            32 => Self::Resize,
            33 => Self::Kill,
            34 => Self::ResetSize,
            40 => Self::Ping,
            41 => Self::Pong,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsV3Frame {
    pub ty: WsV3MessageType,
    pub session_id: String,
    pub payload: Vec<u8>,
}

pub fn encode_frame(frame: &WsV3Frame) -> Vec<u8> {
    let session_bytes = frame.session_id.as_bytes();
    let payload = &frame.payload;

    let mut out = Vec::with_capacity(2 + 1 + 1 + 4 + session_bytes.len() + 4 + payload.len());
    out.extend_from_slice(&WS_V3_MAGIC.to_le_bytes());
    out.push(WS_V3_VERSION);
    out.push(frame.ty.as_u8());
    out.extend_from_slice(&(session_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(session_bytes);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn decode_frame(data: &[u8]) -> Option<WsV3Frame> {
    if data.len() < 12 {
        return None;
    }

    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != WS_V3_MAGIC {
        return None;
    }

    if data[2] != WS_V3_VERSION {
        return None;
    }

    let ty = WsV3MessageType::from(data[3]);

    let session_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let mut offset = 8usize;
    if offset + session_len + 4 > data.len() {
        return None;
    }

    let session = String::from_utf8_lossy(&data[offset..offset + session_len]).into_owned();
    offset += session_len;

    let payload_len = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + payload_len > data.len() {
        return None;
    }

    let payload = data[offset..offset + payload_len].to_vec();
    Some(WsV3Frame {
        ty,
        session_id: session,
        payload,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WsV3SubscribeFlags {
    Stdout = 1 << 0,
    Snapshots = 1 << 1,
    Events = 1 << 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsV3SubscribePayload {
    pub flags: u32,
    pub snapshot_min_interval_ms: u32,
    pub snapshot_max_interval_ms: u32,
}

pub fn encode_subscribe_payload(
    flags: u32,
    snapshot_min_interval_ms: Option<u32>,
    snapshot_max_interval_ms: Option<u32>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&snapshot_min_interval_ms.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&snapshot_max_interval_ms.unwrap_or(0).to_le_bytes());
    out
}

pub fn decode_subscribe_payload(payload: &[u8]) -> Option<WsV3SubscribePayload> {
    if payload.len() < 12 {
        return None;
    }

    Some(WsV3SubscribePayload {
        flags: u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
        snapshot_min_interval_ms: u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]),
        snapshot_max_interval_ms: u32::from_le_bytes([
            payload[8],
            payload[9],
            payload[10],
            payload[11],
        ]),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsV3ResizePayload {
    pub cols: u32,
    pub rows: u32,
}

pub fn encode_resize_payload(cols: u32, rows: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&cols.to_le_bytes());
    out.extend_from_slice(&rows.to_le_bytes());
    out
}

pub fn decode_resize_payload(payload: &[u8]) -> Option<WsV3ResizePayload> {
    if payload.len() < 8 {
        return None;
    }

    Some(WsV3ResizePayload {
        cols: u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
        rows: u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]),
    })
}
