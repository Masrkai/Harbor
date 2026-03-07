const RESET: &str = "\x1b[0m";

pub const fn parse_hex(hex: &[u8]) -> (u8, u8, u8) {
    assert!(
        hex.len() == 7 || hex.len() == 9,
        "color must be '#RRGGBB' or '#RRGGBBAA' (7 or 9 chars)"
    );
    assert!(hex[0] == b'#', "color must start with '#'");

    const fn val(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("invalid hex digit"),
        }
    }

    let r = (val(hex[1]) << 4) | val(hex[2]);
    let g = (val(hex[3]) << 4) | val(hex[4]);
    let b = (val(hex[5]) << 4) | val(hex[6]);
    // alpha (hex[7..=8]) is silently ignored — terminals don't support it
    (r, g, b)
}

pub struct Color(pub u8, pub u8, pub u8);

impl Color {
    pub const fn from_hex(hex: &[u8]) -> Self {
        let (r, g, b) = parse_hex(hex);
        Self(r, g, b)
    }

    pub fn paint(&self, text: &str) -> String {
        let Self(r, g, b) = self;
        format!("\x1b[38;2;{r};{g};{b}m{text}{RESET}")
    }

    pub fn paint_fmt(&self, args: std::fmt::Arguments) -> String {
        let Self(r, g, b) = self;
        format!("\x1b[38;2;{r};{g};{b}m{args}{RESET}")
    }
}

// Macro so you can use it like format!() but with a color
#[macro_export]
macro_rules! paint {
    ($color:expr, $($arg:tt)*) => {
        $color.paint_fmt(format_args!($($arg)*))
    };
}
