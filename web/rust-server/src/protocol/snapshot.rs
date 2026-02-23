use std::io::Write;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferCell {
    pub ch: String,
    pub width: u8,
    pub fg: Option<u32>,
    pub bg: Option<u32>,
    pub attributes: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferSnapshot {
    pub cols: u32,
    pub rows: u32,
    pub viewport_y: i32,
    pub cursor_x: i32,
    pub cursor_y: i32,
    pub cells: Vec<Vec<BufferCell>>,
}

pub fn encode_snapshot(snapshot: &BufferSnapshot) -> Vec<u8> {
    // Exact wire parity target from terminal-manager.ts encodeSnapshot
    let mut out = Vec::new();

    // Header (32 bytes)
    out.write_all(&0x5654u16.to_le_bytes()).unwrap(); // magic VT
    out.write_all(&[0x01]).unwrap(); // version
    out.write_all(&[0x00]).unwrap(); // reserved
    out.write_all(&snapshot.cols.to_le_bytes()).unwrap();
    out.write_all(&snapshot.rows.to_le_bytes()).unwrap();
    out.write_all(&snapshot.viewport_y.to_le_bytes()).unwrap();
    out.write_all(&snapshot.cursor_x.to_le_bytes()).unwrap();
    out.write_all(&snapshot.cursor_y.to_le_bytes()).unwrap();
    out.write_all(&0u32.to_le_bytes()).unwrap(); // reserved

    for row in &snapshot.cells {
        if row.is_empty() || is_single_empty_space(row) {
            out.write_all(&[0xfe, 0x01]).unwrap();
            continue;
        }

        out.write_all(&[0xfd]).unwrap();
        out.write_all(&(row.len() as u16).to_le_bytes()).unwrap();

        for cell in row {
            encode_cell(cell, &mut out);
        }
    }

    out
}

fn is_single_empty_space(row: &[BufferCell]) -> bool {
    if row.len() != 1 {
        return false;
    }
    let c = &row[0];
    c.ch == " " && c.fg.is_none() && c.bg.is_none() && c.attributes.is_none()
}

fn encode_cell(cell: &BufferCell, out: &mut Vec<u8>) {
    let ch = cell.ch.chars().next().unwrap_or(' ');
    let is_space = ch == ' ';
    let has_attrs = cell.attributes.unwrap_or(0) != 0;
    let has_fg = cell.fg.is_some();
    let has_bg = cell.bg.is_some();
    let is_ascii = (ch as u32) <= 0x7f;

    if is_space && !has_attrs && !has_fg && !has_bg {
        out.push(0x00);
        return;
    }

    let mut type_byte = 0u8;
    if has_attrs || has_fg || has_bg {
        type_byte |= 0x80;
    }

    if !is_ascii {
        type_byte |= 0x40;
        type_byte |= 0x02; // utf8 marker
    } else if !is_space {
        type_byte |= 0x01;
    }

    if let Some(fg) = cell.fg {
        type_byte |= 0x20;
        if fg > 255 {
            type_byte |= 0x08;
        }
    }

    if let Some(bg) = cell.bg {
        type_byte |= 0x10;
        if bg > 255 {
            type_byte |= 0x04;
        }
    }

    out.push(type_byte);

    if !is_ascii {
        let utf8 = cell.ch.as_bytes();
        out.push(utf8.len() as u8);
        out.extend_from_slice(utf8);
    } else if !is_space {
        out.push(ch as u8);
    }

    if type_byte & 0x80 != 0 {
        // attrs byte is always present when style bit is set
        out.push(cell.attributes.unwrap_or(0));

        if let Some(fg) = cell.fg {
            if fg > 255 {
                out.push(((fg >> 16) & 0xff) as u8);
                out.push(((fg >> 8) & 0xff) as u8);
                out.push((fg & 0xff) as u8);
            } else {
                out.push(fg as u8);
            }
        }

        if let Some(bg) = cell.bg {
            if bg > 255 {
                out.push(((bg >> 16) & 0xff) as u8);
                out.push(((bg >> 8) & 0xff) as u8);
                out.push((bg & 0xff) as u8);
            } else {
                out.push(bg as u8);
            }
        }
    }
}
