use anyhow::{anyhow, Result};

pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

pub fn encode_control_message(json_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + json_payload.len());
    out.extend_from_slice(&(json_payload.len() as u32).to_be_bytes());
    out.extend_from_slice(json_payload);
    out
}

pub struct ControlMessageParser {
    buffer: Vec<u8>,
}

impl ControlMessageParser {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn add_data(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn parse_messages(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();

        loop {
            if self.buffer.len() < 4 {
                break;
            }

            let len = u32::from_be_bytes([
                self.buffer[0],
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
            ]) as usize;

            if len == 0 {
                self.buffer.clear();
                break;
            }

            if len > MAX_MESSAGE_SIZE {
                self.buffer.clear();
                break;
            }

            if self.buffer.len() < 4 + len {
                break;
            }

            let payload = self.buffer[4..4 + len].to_vec();
            self.buffer.drain(0..4 + len);
            out.push(payload);
        }

        out
    }
}

pub fn parse_single_message(data: &[u8]) -> Result<Option<Vec<u8>>> {
    if data.len() < 4 {
        return Ok(None);
    }

    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if len == 0 {
        return Err(anyhow!("invalid control message length: {len}"));
    }
    if len > MAX_MESSAGE_SIZE {
        return Err(anyhow!("invalid control message length: {len}"));
    }

    if data.len() < 4 + len {
        return Ok(None);
    }

    Ok(Some(data[4..4 + len].to_vec()))
}
