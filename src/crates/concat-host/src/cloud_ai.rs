// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 VIDCUT contributors

//! VIDCUT Ultra-Secure Dedicated Cloud AI Engine Connector.
//!
//! Offloads heavy AI background removal and cutout computation to the
//! dedicated VIDCUT cloud engine over HTTPS / WSS, preserving client hardware
//! resources (0% CPU/GPU load on mobile/desktop).

use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use concat_core::frame::Frame;
use concat_project::model::Subject;
use concat_vision::Mask;
use sha2::{Digest, Sha256};

use crate::net;

/// Official Dedicated Cloud AI Endpoint.
pub const CLOUD_AI_BASE_URL: &str = "https://bg.seaofink.org";

/// Secret HMAC Key for VIDCUT authentication.
const HMAC_SECRET: &str = "vidcut_ultra_secure_hmac_secret_key_2026_x89a";

/// Client device identifier.
const DEVICE_ID: &str = "vidcut-official-client-v2";

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Computes HMAC-SHA256 according to RFC 2104.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hash = Sha256::digest(key);
        k[..32].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().into()
}

/// Converts a frame to PNG bytes in memory.
pub fn encode_frame_png(frame: &Frame) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut encoder = png::Encoder::new(&mut buf, frame.width(), frame.height());
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().map_err(|e| e.to_string())?;
    writer
        .write_image_data(frame.pixels())
        .map_err(|e| e.to_string())?;
    drop(writer);
    Ok(buf)
}

/// Decodes received PNG mask bytes into a `Mask`.
fn decode_png_mask(bytes: &[u8]) -> Result<Mask, String> {
    let decoder = png::Decoder::new(Cursor::new(bytes));
    let mut reader = decoder.read_info().map_err(|e| e.to_string())?;
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).map_err(|e| e.to_string())?;

    let width = info.width;
    let height = info.height;
    let pixel_count = (width * height) as usize;

    let mask_bytes = match info.color_type {
        png::ColorType::Grayscale => {
            if buf.len() < pixel_count {
                return Err("cloud mask: incomplete grayscale data".to_string());
            }
            buf[..pixel_count].to_vec()
        }
        png::ColorType::Rgba => {
            // Extract the alpha channel (4th byte of each RGBA pixel)
            buf.chunks_exact(4).map(|chunk| chunk[3]).collect()
        }
        png::ColorType::Rgb => {
            // Luminance fallback
            buf.chunks_exact(3).map(|chunk| chunk[0]).collect()
        }
        _ => return Err("cloud mask: unsupported color type".to_string()),
    };

    Mask::from_bytes(width, height, mask_bytes)
        .ok_or_else(|| "cloud mask: failed to build mask from decoded bytes".to_string())
}

/// Calls the VIDCUT Cloud AI engine to remove background and extract the mask.
pub fn cloud_cutout_mask(frame: &Frame, subject: Subject) -> Result<Mask, String> {
    let png_bytes = encode_frame_png(frame)?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let nonce = format!(
        "{:x}{:x}",
        ts,
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let message = format!("{ts}:{nonce}:{DEVICE_ID}");
    let sig_bytes = hmac_sha256(HMAC_SECRET.as_bytes(), message.as_bytes());
    let sig = sig_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();

    let mode_param = match subject {
        Subject::Person => "human",
        Subject::Object => "object",
        Subject::Auto => "auto",
    };

    let url = format!("{CLOUD_AI_BASE_URL}/api/v1/cutout/mask-raw?mode={mode_param}");
    let agent = net::agent(Duration::from_secs(8), Duration::from_secs(30));

    let response = agent
        .post(&url)
        .set("Content-Type", "image/png")
        .set("X-VIDCUT-Timestamp", &ts.to_string())
        .set("X-VIDCUT-Nonce", &nonce)
        .set("X-VIDCUT-Device-ID", DEVICE_ID)
        .set("X-VIDCUT-Signature", &sig)
        .send_bytes(&png_bytes)
        .map_err(|e| format!("VIDCUT Cloud AI error: {e}"))?;

    let mut response_bytes = Vec::new();
    let mut reader = response.into_reader();
    std::io::copy(&mut reader, &mut response_bytes)
        .map_err(|e| format!("Failed to read Cloud AI response: {e}"))?;

    decode_png_mask(&response_bytes)
}
