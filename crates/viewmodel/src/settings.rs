//! Display settings (theme, font, address format) with clamping.



#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Dark,
    Light,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFormat {
    /// Zero-padded to the pointer width, e.g. `0000000140001000`.
    Padded,
    /// No padding, e.g. `140001000`.
    Short,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Settings {
    pub theme: Theme,
    pub font_size: f32,
    pub line_spacing: f32,
    pub address_format: AddressFormat,
    pub colored_mnemonics: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { theme: Theme::Dark, font_size: 14.0, line_spacing: 2.0, address_format: AddressFormat::Padded, colored_mnemonics: true }
    }
}

pub const MIN_FONT: f32 = 8.0;
pub const MAX_FONT: f32 = 32.0;
pub const MAX_SPACING: f32 = 12.0;

impl Settings {
    /// Clamps user-entered values into the supported ranges (NaN becomes the default).
    pub fn sanitized(mut self) -> Self {
        let d = Self::default();
        self.font_size = if self.font_size.is_finite() { self.font_size.clamp(MIN_FONT, MAX_FONT) } else { d.font_size };
        self.line_spacing = if self.line_spacing.is_finite() { self.line_spacing.clamp(0.0, MAX_SPACING) } else { d.line_spacing };
        self
    }

    pub fn format_address(&self, addr: u64, bits: u8) -> String {
        match self.address_format {
            AddressFormat::Short => format!("{addr:x}"),
            AddressFormat::Padded => {
                let width = if bits >= 64 { 16 } else { 8 };
                format!("{addr:0width$x}")
            }
        }
    }
}
