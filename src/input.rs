//! Keyboard and pointer input for the screen tools: the US keymap for
//! `type_text`, the chord parser for `key`, pointer coordinate mapping and
//! the PNG header that gives the screen size. Pure functions; `vm.rs`
//! sends the results to QEMU.

use anyhow::{Result, bail, ensure};

/// Longest `type_text` input. Typing takes ~15 ms per key and holds the
/// VM's input for that long; bulk text belongs in `file_write`.
pub const MAX_TEXT: usize = 1024;
/// Most keys pressed together in one chord.
const MAX_CHORD: usize = 6;
/// QEMU's absolute pointer axes run from 0 to this value.
const ABS_MAX: u64 = 0x7fff;

/// QEMU key codes (`QKeyCode`) to press together for one character on a US
/// layout, or `None` if the character cannot be typed. Only printable
/// ASCII, newline and tab: other text belongs in `file_write`.
pub fn char_keys(c: char) -> Option<Vec<&'static str>> {
    const SHIFTED: &str = "~!@#$%^&*()_+{}|:\"<>?";
    const PLAIN: &str = "`1234567890-=[]\\;',./";
    if let Some(i) = SHIFTED.find(c) {
        let base = PLAIN.as_bytes()[i] as char;
        return Some(vec!["shift", plain_key(base)?]);
    }
    if c.is_ascii_uppercase() {
        return Some(vec!["shift", plain_key(c.to_ascii_lowercase())?]);
    }
    Some(vec![plain_key(c)?])
}

/// The key for a character typed without shift.
fn plain_key(c: char) -> Option<&'static str> {
    const ALNUM: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
    if let Some(i) = ALNUM.find(c).filter(|_| c.is_ascii_alphanumeric()) {
        return Some(&ALNUM[i..i + 1]);
    }
    Some(match c {
        ' ' => "spc",
        '\n' => "ret",
        '\t' => "tab",
        '`' => "grave_accent",
        '-' => "minus",
        '=' => "equal",
        '[' => "bracket_left",
        ']' => "bracket_right",
        '\\' => "backslash",
        ';' => "semicolon",
        '\'' => "apostrophe",
        ',' => "comma",
        '.' => "dot",
        '/' => "slash",
        _ => return None,
    })
}

/// Checks `text` for `type_text` and returns the keys for each character.
pub fn text_keys(text: &str) -> Result<Vec<Vec<&'static str>>> {
    ensure!(
        text.len() <= MAX_TEXT,
        "text is longer than {MAX_TEXT} bytes"
    );
    text.chars()
        .map(|c| match char_keys(c) {
            Some(k) => Ok(k),
            None => bail!(
                "cannot type {c:?}: type_text takes printable ASCII, newline and tab; use file_write for other text"
            ),
        })
        .collect()
}

/// Longest chord spec accepted.
const MAX_CHORD_SPEC: usize = 64;
const MODIFIERS: [&str; 5] = ["ctrl", "alt", "alt_r", "shift", "meta_l"];

/// Parses a chord such as `ctrl+alt+t`, `shift+F10`, `ctrl+plus` or
/// `enter` into QEMU key codes, modifiers first. A shifted character
/// (`ctrl+?`) adds `shift`; letters are case-insensitive.
pub fn chord(spec: &str) -> Result<Vec<&'static str>> {
    ensure!(
        spec.len() <= MAX_CHORD_SPEC,
        "key chord is longer than {MAX_CHORD_SPEC} bytes"
    );
    let mut keys: Vec<&'static str> = Vec::new();
    for part in spec.split('+') {
        let part = part.trim();
        let lower = part.to_ascii_lowercase();
        let mut chars = lower.chars();
        let new = match (named_key(&lower), chars.next(), chars.next()) {
            (Some(k), _, _) => vec![k],
            _ if lower == "plus" => char_keys('+').unwrap_or_default(),
            (None, Some(c), None) => char_keys(c).unwrap_or_default(),
            _ => Vec::new(),
        };
        ensure!(
            !new.is_empty(),
            "unknown key {part:?} in {spec:?}; use e.g. ctrl+alt+t, enter, esc, f1, up, plus"
        );
        for k in new {
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
    }
    ensure!(keys.len() <= MAX_CHORD, "at most {MAX_CHORD} keys at once");
    // `a+ctrl` would type "a" before ctrl is down.
    keys.sort_by_key(|k| !MODIFIERS.contains(k));
    Ok(keys)
}

fn named_key(name: &str) -> Option<&'static str> {
    Some(match name {
        "f1" => "f1",
        "f2" => "f2",
        "f3" => "f3",
        "f4" => "f4",
        "f5" => "f5",
        "f6" => "f6",
        "f7" => "f7",
        "f8" => "f8",
        "f9" => "f9",
        "f10" => "f10",
        "f11" => "f11",
        "f12" => "f12",
        "ctrl" | "control" => "ctrl",
        "alt" => "alt",
        "altgr" => "alt_r",
        "shift" => "shift",
        "super" | "meta" | "win" | "cmd" => "meta_l",
        "enter" | "return" => "ret",
        "esc" | "escape" => "esc",
        "tab" => "tab",
        "space" => "spc",
        "backspace" => "backspace",
        "delete" | "del" => "delete",
        "insert" | "ins" => "insert",
        "home" => "home",
        "end" => "end",
        "pageup" | "pgup" => "pgup",
        "pagedown" | "pgdn" => "pgdn",
        "up" => "up",
        "down" => "down",
        "left" => "left",
        "right" => "right",
        // The PC context-menu key is `compose` in QEMU's key codes.
        "menu" => "compose",
        "printscreen" | "print" => "print",
        _ => return None,
    })
}

/// Maps a screen coordinate to QEMU's absolute axis (0..=0x7fff), aiming
/// at the centre of the pixel so guests that scale back with either
/// `v * size / 0x8000` or `v * (size - 1) / 0x7fff` land on `pos`. Fails if
/// `pos` is off screen.
pub fn abs_axis(pos: u32, size: u32) -> Result<u32> {
    ensure!(
        pos < size,
        "coordinate {pos} is off screen (the screen is {size} pixels)"
    );
    let v = (2 * u64::from(pos) + 1) * (ABS_MAX + 1) / (2 * u64::from(size));
    Ok(v.min(ABS_MAX) as u32)
}

/// Largest screen side accepted from a PNG header.
const MAX_SIDE: u32 = 16384;

/// Width and height from a PNG's IHDR chunk.
pub fn png_size(png: &[u8]) -> Result<(u32, u32)> {
    const SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
    ensure!(
        png.len() >= 24 && png.starts_with(SIGNATURE) && &png[8..16] == b"\0\0\0\x0dIHDR",
        "not a PNG image"
    );
    let be = |i: usize| u32::from_be_bytes(png[i..i + 4].try_into().unwrap());
    let (w, h) = (be(16), be(20));
    ensure!(
        (1..=MAX_SIDE).contains(&w) && (1..=MAX_SIDE).contains(&h),
        "PNG size {w}x{h} is out of range"
    );
    Ok((w, h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keymap_covers_printable_ascii() {
        for c in (' '..='~').chain(['\n', '\t']) {
            let keys = char_keys(c).unwrap_or_else(|| panic!("{c:?}"));
            assert!(!keys.is_empty() && keys.len() <= 2, "{c:?}");
        }
        assert_eq!(char_keys('a').unwrap(), ["a"]);
        assert_eq!(char_keys('A').unwrap(), ["shift", "a"]);
        assert_eq!(char_keys('!').unwrap(), ["shift", "1"]);
        assert_eq!(char_keys('"').unwrap(), ["shift", "apostrophe"]);
        assert_eq!(char_keys('?').unwrap(), ["shift", "slash"]);
        assert_eq!(char_keys('~').unwrap(), ["shift", "grave_accent"]);
        assert_eq!(char_keys('|').unwrap(), ["shift", "backslash"]);
        assert_eq!(char_keys('\n').unwrap(), ["ret"]);
        // The whole table, so a shifted pair can never slip.
        let table = [
            ("`~", "grave_accent"),
            ("1!", "1"),
            ("2@", "2"),
            ("3#", "3"),
            ("4$", "4"),
            ("5%", "5"),
            ("6^", "6"),
            ("7&", "7"),
            ("8*", "8"),
            ("9(", "9"),
            ("0)", "0"),
            ("-_", "minus"),
            ("=+", "equal"),
            ("[{", "bracket_left"),
            ("]}", "bracket_right"),
            ("\\|", "backslash"),
            (";:", "semicolon"),
            ("'\"", "apostrophe"),
            (",<", "comma"),
            (".>", "dot"),
            ("/?", "slash"),
        ];
        for (pair, key) in table {
            let mut c = pair.chars();
            assert_eq!(char_keys(c.next().unwrap()).unwrap(), [key], "{pair}");
            assert_eq!(
                char_keys(c.next().unwrap()).unwrap(),
                ["shift", key],
                "{pair}"
            );
        }
        for c in 'a'..='z' {
            let k = c.to_string();
            assert_eq!(char_keys(c).unwrap(), [k.as_str()]);
            assert_eq!(
                char_keys(c.to_ascii_uppercase()).unwrap(),
                ["shift", k.as_str()]
            );
        }
        for bad in ['é', '\r', '\u{7f}', '\0', '€'] {
            assert!(char_keys(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn text_is_checked() {
        assert_eq!(text_keys("ls -l\n").unwrap().len(), 6);
        let err = text_keys("café").unwrap_err().to_string();
        assert!(err.contains("file_write"), "{err}");
        assert!(text_keys(&"a".repeat(MAX_TEXT)).is_ok());
        assert!(text_keys(&"a".repeat(MAX_TEXT + 1)).is_err());
    }

    #[test]
    fn chords() {
        assert_eq!(chord("ctrl+alt+t").unwrap(), ["ctrl", "alt", "t"]);
        assert_eq!(chord("Ctrl + C").unwrap(), ["ctrl", "c"]);
        assert_eq!(chord("enter").unwrap(), ["ret"]);
        assert_eq!(chord("shift+F10").unwrap(), ["shift", "f10"]);
        assert_eq!(chord("super").unwrap(), ["meta_l"]);
        assert_eq!(chord("ctrl+?").unwrap(), ["ctrl", "shift", "slash"]);
        assert_eq!(chord("shift+?").unwrap(), ["shift", "slash"]);
        assert_eq!(chord("ctrl+/").unwrap(), ["ctrl", "slash"]);
        assert_eq!(chord("ctrl+T").unwrap(), ["ctrl", "t"]);
        assert_eq!(chord("ctrl+plus").unwrap(), ["ctrl", "shift", "equal"]);
        assert_eq!(chord("a+ctrl").unwrap(), ["ctrl", "a"]);
        assert_eq!(chord("t+alt+ctrl").unwrap(), ["alt", "ctrl", "t"]);
        assert_eq!(chord("menu").unwrap(), ["compose"]);
        assert!(chord(&"a+".repeat(40)).is_err());
        for bad in ["", "ctrl+", "hyper", "ctrl+é", "a+b+c+d+e+f+g", "ctrl+tt"] {
            assert!(chord(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn coordinates() {
        // Round trip through both ways a guest may scale back.
        for size in [1, 2, 800, 1024, 1280, 1920, 16384] {
            for pos in 0..size {
                let v = u64::from(abs_axis(pos, size).unwrap());
                assert!(v <= 0x7fff);
                assert_eq!(v * u64::from(size) / 0x8000, u64::from(pos), "{pos}/{size}");
                let back = (v * u64::from(size - 1) + 0x7fff / 2) / 0x7fff;
                assert_eq!(back, u64::from(pos), "{pos}/{size}");
            }
        }
        assert!(abs_axis(1280, 1280).is_err());
        assert!(abs_axis(0, 0).is_err());
    }

    #[test]
    fn png_header() {
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
        png.extend(1280u32.to_be_bytes());
        png.extend(800u32.to_be_bytes());
        assert_eq!(png_size(&png).unwrap(), (1280, 800));
        assert!(png_size(&png[..20]).is_err());
        assert!(png_size(b"P6\n1280 800\n255\n").is_err());
        let mut zero = png.clone();
        zero[16..20].copy_from_slice(&[0; 4]);
        assert!(png_size(&zero).is_err());
        let mut huge = png.clone();
        huge[20..24].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(png_size(&huge).is_err());
        let mut bad_len = png.clone();
        bad_len[11] = 12;
        assert!(png_size(&bad_len).is_err());
    }
}
