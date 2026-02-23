pub const MAX_BUFFER_SIZE: usize = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    StdinData,
    ControlCmd,
    StatusUpdate,
    Heartbeat,
    Error,
    StdoutSubscribe,
    Metrics,
    StatusRequest,
    StatusResponse,
    GitFollowRequest,
    GitFollowResponse,
    GitEventNotify,
    GitEventAck,
    Unknown(u8),
}

impl MessageType {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::StdinData => 0x01,
            Self::ControlCmd => 0x02,
            Self::StatusUpdate => 0x03,
            Self::Heartbeat => 0x04,
            Self::Error => 0x05,
            Self::StdoutSubscribe => 0x10,
            Self::Metrics => 0x11,
            Self::StatusRequest => 0x20,
            Self::StatusResponse => 0x21,
            Self::GitFollowRequest => 0x30,
            Self::GitFollowResponse => 0x31,
            Self::GitEventNotify => 0x32,
            Self::GitEventAck => 0x33,
            Self::Unknown(value) => value,
        }
    }
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Self::StdinData,
            0x02 => Self::ControlCmd,
            0x03 => Self::StatusUpdate,
            0x04 => Self::Heartbeat,
            0x05 => Self::Error,
            0x10 => Self::StdoutSubscribe,
            0x11 => Self::Metrics,
            0x20 => Self::StatusRequest,
            0x21 => Self::StatusResponse,
            0x30 => Self::GitFollowRequest,
            0x31 => Self::GitFollowResponse,
            0x32 => Self::GitEventNotify,
            0x33 => Self::GitEventAck,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedMessage {
    pub ty: MessageType,
    pub payload: Vec<u8>,
}

pub fn frame_message(ty: MessageType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + payload.len());
    out.push(ty.as_u8());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub struct MessageParser {
    buffer: Vec<u8>,
}

impl MessageParser {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn add_data(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);

        if self.buffer.len() > MAX_BUFFER_SIZE {
            let keep = 1024usize;
            if self.buffer.len() > keep {
                let drain_len = self.buffer.len() - keep;
                self.buffer.drain(0..drain_len);
            }
        }
    }

    pub fn pending_bytes(&self) -> usize {
        self.buffer.len()
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    pub fn parse_messages(&mut self) -> Vec<FramedMessage> {
        let mut out = Vec::new();

        loop {
            if self.buffer.len() < 5 {
                break;
            }

            let ty_raw = self.buffer[0];
            let len = u32::from_be_bytes([
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
                self.buffer[4],
            ]) as usize;

            if self.buffer.len() < 5 + len {
                break;
            }

            let payload = self.buffer[5..5 + len].to_vec();
            let ty = MessageType::from(ty_raw);

            self.buffer.drain(0..5 + len);
            out.push(FramedMessage { ty, payload });
        }

        out
    }
}
