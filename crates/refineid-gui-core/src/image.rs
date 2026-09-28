// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Toolkit-independent image buffers and decoding for card portraits and handwritten ink.

use std::sync::Arc;

use image::{ImageDecoder, ImageFormat};
use refineid_lib_core::emrtd::DocumentImage;
use refineid_lib_core::sign::pades::SignatureInk;

use crate::error::GuiCoreError;

/// Toolkit-independent RGBA8 image buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgbaImageBuffer {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

impl RgbaImageBuffer {
    /// Create a new RGBA8 image buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte vector length does not match `width * height * 4`.
    pub fn new(width: u32, height: u32, rgba: Vec<u8>) -> Result<Self, GuiCoreError> {
        let expected = (width as usize)
            .checked_mul(height as usize)
            .and_then(|px| px.checked_mul(4))
            .ok_or_else(|| GuiCoreError::Image("image dimensions overflow".into()))?;

        if rgba.len() != expected {
            return Err(GuiCoreError::Image(format!(
                "invalid buffer size: expected {expected}, got {}",
                rgba.len()
            )));
        }

        Ok(Self {
            width,
            height,
            rgba,
        })
    }

    /// Image width in pixels.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Image height in pixels.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Raw RGBA bytes (4 bytes per pixel: Red, Green, Blue, Alpha).
    pub fn rgba_bytes(&self) -> &[u8] {
        &self.rgba
    }

    /// Convert to RGB24 bytes (3 bytes per pixel: Red, Green, Blue).
    ///
    /// Useful for toolkit renderers such as FLTK's `RgbImage`.
    pub fn to_rgb_bytes(&self) -> Vec<u8> {
        let pixel_count = (self.width as usize) * (self.height as usize);
        let mut rgb = Vec::with_capacity(pixel_count * 3);
        for chunk in self.rgba.chunks_exact(4) {
            rgb.extend_from_slice(&chunk[0..3]);
        }
        rgb
    }

    /// Extract signature ink from the RGBA pixels for PAdES visual stamps.
    pub fn signature_ink(&self) -> Option<SignatureInk> {
        SignatureInk::from_rgba(self.width, self.height, &self.rgba)
    }

    /// Encode buffer as PNG bytes.
    pub fn to_png_bytes(&self) -> Result<Vec<u8>, GuiCoreError> {
        let img = image::RgbaImage::from_raw(self.width, self.height, self.rgba.clone())
            .ok_or_else(|| GuiCoreError::Image("invalid image buffer".into()))?;
        let mut out = Vec::new();
        let mut cursor = std::io::Cursor::new(&mut out);
        img.write_to(&mut cursor, ImageFormat::Png)
            .map_err(|e| GuiCoreError::Image(format!("PNG encode: {e}")))?;
        Ok(out)
    }
}

/// Decode an eMRTD card document image (JPEG or JPEG2000) into an RGBA8 buffer.
pub fn decode_document_image(
    document: &DocumentImage,
) -> Result<Arc<RgbaImageBuffer>, GuiCoreError> {
    let decoded = match document {
        DocumentImage::Jpeg(bytes) => image::load_from_memory_with_format(bytes, ImageFormat::Jpeg)
            .map_err(|e| GuiCoreError::Image(format!("decode JPEG card image: {e}")))?,
        DocumentImage::Jpeg2000(bytes) => {
            let decoder =
                pdfluent_jpeg2000::integration::Jp2Decoder::new(std::io::Cursor::new(bytes))
                    .map_err(|e| GuiCoreError::Image(format!("decode JPEG2000 header: {e}")))?;
            let (width, height) = decoder.dimensions();
            let color = decoder.color_type();
            let raw_len = usize::try_from(decoder.total_bytes())
                .map_err(|_| GuiCoreError::Image("JPEG2000 card image is too large".into()))?;
            let mut raw = vec![0_u8; raw_len];
            decoder
                .read_image(&mut raw)
                .map_err(|e| GuiCoreError::Image(format!("decode JPEG2000 payload: {e}")))?;
            match color {
                image::ColorType::L8 => image::GrayImage::from_raw(width, height, raw)
                    .map(image::DynamicImage::ImageLuma8),
                image::ColorType::La8 => image::GrayAlphaImage::from_raw(width, height, raw)
                    .map(image::DynamicImage::ImageLumaA8),
                image::ColorType::Rgb8 => image::RgbImage::from_raw(width, height, raw)
                    .map(image::DynamicImage::ImageRgb8),
                image::ColorType::Rgba8 => image::RgbaImage::from_raw(width, height, raw)
                    .map(image::DynamicImage::ImageRgba8),
                other => {
                    return Err(GuiCoreError::Image(format!(
                        "unsupported JPEG2000 output color type {other:?}"
                    )));
                }
            }
            .ok_or_else(|| GuiCoreError::Image("JPEG2000 invalid buffer length".into()))?
        }
    };

    let rgba_image = decoded.to_rgba8();
    let (width, height) = rgba_image.dimensions();
    let buf = RgbaImageBuffer::new(width, height, rgba_image.into_raw())?;
    Ok(Arc::new(buf))
}
