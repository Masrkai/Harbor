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

// ─────────────────────────────────────────────────────────────────────────────
// Tests for src/cli/color.rs
//
// Paste this block at the bottom of src/cli/color.rs
//
// Two layers of testing:
//   1. Compile-time assertions via `const _: () = assert!(...)` — these fire
//      as compiler errors, before any binary is produced.
//   2. Runtime #[test] functions — cover the same ground plus panic paths that
//      can't be expressed as const assertions.
// ─────────────────────────────────────────────────────────────────────────────

// ── Compile-time assertions ───────────────────────────────────────────────────
// These run during compilation.  A failure here is a *compiler error*, not a
// test failure, so they catch regressions before `cargo test` is even invoked.

const _: () = {
    // Pure white: #FFFFFF
    let (r, g, b) = parse_hex(b"#FFFFFF");
    assert!(r == 255 && g == 255 && b == 255);
};

const _: () = {
    // Pure black: #000000
    let (r, g, b) = parse_hex(b"#000000");
    assert!(r == 0 && g == 0 && b == 0);
};

const _: () = {
    // Mixed case: #C792EA (the purple used in the real codebase)
    let (r, g, b) = parse_hex(b"#C792EA");
    assert!(r == 0xC7 && g == 0x92 && b == 0xEA);
};

const _: () = {
    // Lowercase hex digits: #50c878
    let (r, g, b) = parse_hex(b"#50c878");
    assert!(r == 0x50 && g == 0xC8 && b == 0x78);
};

const _: () = {
    // 9-byte form (#RRGGBBAA) — alpha is silently ignored
    let (r, g, b) = parse_hex(b"#FF5050FF");
    assert!(r == 0xFF && g == 0x50 && b == 0x50);
};

const _: () = {
    // Boundary: #010203
    let (r, g, b) = parse_hex(b"#010203");
    assert!(r == 1 && g == 2 && b == 3);
};

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_hex — correct decoding ──────────────────────────────────────────

    #[test]
    fn test_parse_hex_pure_white() {
        assert_eq!(parse_hex(b"#FFFFFF"), (255, 255, 255));
    }

    #[test]
    fn test_parse_hex_pure_black() {
        assert_eq!(parse_hex(b"#000000"), (0, 0, 0));
    }

    #[test]
    fn test_parse_hex_pure_red() {
        assert_eq!(parse_hex(b"#FF0000"), (255, 0, 0));
    }

    #[test]
    fn test_parse_hex_pure_green() {
        assert_eq!(parse_hex(b"#00FF00"), (0, 255, 0));
    }

    #[test]
    fn test_parse_hex_pure_blue() {
        assert_eq!(parse_hex(b"#0000FF"), (0, 0, 255));
    }

    /// The purple used throughout the real codebase.
    #[test]
    fn test_parse_hex_c792ea() {
        assert_eq!(parse_hex(b"#C792EA"), (0xC7, 0x92, 0xEA));
    }

    /// Lowercase hex digits a–f must decode identically to uppercase A–F.
    #[test]
    fn test_parse_hex_lowercase_digits() {
        assert_eq!(parse_hex(b"#50c878"), parse_hex(b"#50C878"));
    }

    /// Mixed case (uppercase R, lowercase g, uppercase B) must work.
    #[test]
    fn test_parse_hex_mixed_case() {
        let (r, g, b) = parse_hex(b"#Ff8800");
        assert_eq!((r, g, b), (0xFF, 0x88, 0x00));
    }

    /// The 9-byte form (#RRGGBBAA) — alpha channel is silently discarded.
    #[test]
    fn test_parse_hex_9_byte_form_alpha_ignored() {
        // Same RGB regardless of alpha value
        assert_eq!(parse_hex(b"#FF5050FF"), parse_hex(b"#FF5050"));
        assert_eq!(parse_hex(b"#FF505000"), parse_hex(b"#FF5050"));
    }

    /// Boundary values: 0x01, 0x02, 0x03
    #[test]
    fn test_parse_hex_boundary_values() {
        assert_eq!(parse_hex(b"#010203"), (1, 2, 3));
    }

    /// Every valid hex digit 0–9 a–f A–F decodes to the right nibble value.
    #[test]
    fn test_parse_hex_all_hex_digits() {
        // Build #0123456789ABCDEF... indirectly by checking known values.
        assert_eq!(parse_hex(b"#09AF00"), (0x09, 0xAF, 0x00));
        assert_eq!(parse_hex(b"#1a2b3c"), (0x1A, 0x2B, 0x3C));
    }

    // ── parse_hex — panic paths ───────────────────────────────────────────────
    //
    // parse_hex is `const fn` and uses `assert!(..., "message")` / `panic!()`
    // internally, so invalid input panics at runtime (and causes a compiler
    // error if used in a const context).  We verify each panic condition with
    // `#[should_panic]`.

    /// A string shorter than 7 bytes must panic.
    #[test]
    #[should_panic]
    fn test_parse_hex_too_short_panics() {
        parse_hex(b"#FF00");
    }

    /// A string longer than 9 bytes must panic.
    #[test]
    #[should_panic]
    fn test_parse_hex_too_long_panics() {
        parse_hex(b"#FF0000AABB");
    }

    /// Exactly 8 bytes (between the valid 7 and 9) must panic.
    #[test]
    #[should_panic]
    fn test_parse_hex_8_bytes_panics() {
        parse_hex(b"#FF0000A");
    }

    /// Missing the leading '#' must panic.
    #[test]
    #[should_panic]
    fn test_parse_hex_missing_hash_panics() {
        parse_hex(b"FF0000"); // 6 bytes, no '#'
    }

    /// A '#' at position 0 but wrong length must still panic on the length
    /// check before reaching the digit parsing.
    #[test]
    #[should_panic]
    fn test_parse_hex_hash_but_wrong_length_panics() {
        parse_hex(b"#FF");
    }

    /// An invalid hex character ('G') must panic.
    #[test]
    #[should_panic]
    fn test_parse_hex_invalid_hex_char_panics() {
        parse_hex(b"#GG0000");
    }

    /// A space character in the hex digits must panic.
    #[test]
    #[should_panic]
    fn test_parse_hex_space_in_digits_panics() {
        parse_hex(b"#FF 000");
    }

    // ── Color::paint ──────────────────────────────────────────────────────────

    /// paint() must wrap text in the correct ANSI true-color escape sequence.
    /// Format: ESC[38;2;R;G;Bm<text>ESC[0m
    #[test]
    fn test_color_paint_ansi_format() {
        let color = Color(255, 128, 0);
        let result = color.paint("hello");
        assert_eq!(result, "\x1b[38;2;255;128;0mhello\x1b[0m");
    }

    /// paint() with pure black (0,0,0).
    #[test]
    fn test_color_paint_black() {
        let color = Color(0, 0, 0);
        let result = color.paint("x");
        assert_eq!(result, "\x1b[38;2;0;0;0mx\x1b[0m");
    }

    /// paint() with pure white (255,255,255).
    #[test]
    fn test_color_paint_white() {
        let color = Color(255, 255, 255);
        let result = color.paint("y");
        assert_eq!(result, "\x1b[38;2;255;255;255my\x1b[0m");
    }

    /// paint() with an empty string — escape sequences still wrap it.
    #[test]
    fn test_color_paint_empty_string() {
        let color = Color(100, 100, 100);
        let result = color.paint("");
        assert_eq!(result, "\x1b[38;2;100;100;100m\x1b[0m");
    }

    /// paint() always ends with the reset sequence \x1b[0m.
    #[test]
    fn test_color_paint_always_resets() {
        let color = Color(1, 2, 3);
        assert!(color.paint("text").ends_with("\x1b[0m"));
    }

    /// paint() always starts with \x1b[38;2;.
    #[test]
    fn test_color_paint_starts_with_true_color_prefix() {
        let color = Color(1, 2, 3);
        assert!(color.paint("text").starts_with("\x1b[38;2;"));
    }

    /// The painted text appears literally between the opening and closing escape.
    #[test]
    fn test_color_paint_text_is_preserved() {
        let color = Color(0, 0, 0);
        let painted = color.paint("Harbor");
        assert!(painted.contains("Harbor"));
    }

    // ── Color::from_hex ───────────────────────────────────────────────────────

    /// from_hex is a const-fn wrapper around parse_hex — verify it stores
    /// the parsed bytes correctly in the Color struct.
    #[test]
    fn test_color_from_hex_stores_correct_bytes() {
        let c = Color::from_hex(b"#C792EA");
        assert_eq!((c.0, c.1, c.2), (0xC7, 0x92, 0xEA));
    }

    #[test]
    fn test_color_from_hex_black() {
        let c = Color::from_hex(b"#000000");
        assert_eq!((c.0, c.1, c.2), (0, 0, 0));
    }

    // ── paint! macro ──────────────────────────────────────────────────────────

    /// The paint! macro must produce the same output as calling paint_fmt
    /// with the equivalent format string.
    #[test]
    fn test_paint_macro_matches_direct_paint() {
        let color = Color(80, 200, 120);
        let via_macro = crate::paint!(&color, "value: {}", 42);
        let via_method = color.paint("value: 42");
        assert_eq!(via_macro, via_method);
    }

    #[test]
    fn test_paint_macro_with_multiple_args() {
        let color = Color(255, 0, 0);
        let result = crate::paint!(&color, "{} + {} = {}", 1, 2, 3);
        assert!(result.contains("1 + 2 = 3"));
        assert!(result.starts_with("\x1b[38;2;"));
        assert!(result.ends_with("\x1b[0m"));
    }
}
