//! A small RFB (VNC) client for a VM's screen: RFB 3.8, no authentication,
//! raw pixels, over the VM's local VNC Unix socket. It runs on the I/O
//! runtime; the GTK side gets frames from a watch channel and sends input
//! through [`Session::send`]. Everything the server sends is untrusted: sizes
//! are capped and checked, and anything unexpected ends the session.

#![expect(dead_code, reason = "the Screen tab (GUI-8) is the first user")]

use std::cell::Cell;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// From connecting up to and including the server's init message.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// For the rest of a server message once its first byte is in; the server
/// may stay quiet for as long as the screen does not change.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);
/// For one message to the server.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// The largest framebuffer we accept (4096 x 4096), 64 MiB as BGRx.
const MAX_PIXELS: u64 = 16 << 20;
const MAX_NAME: u32 = 1024;
const MAX_CUT_TEXT: u32 = 1 << 20;
/// Input waiting to be written.
const QUEUE: usize = 256;
/// Free slots kept for keys and button changes: motion is dropped first.
const KEEP_FREE: usize = 64;

const VERSION: &[u8; 12] = b"RFB 003.008\n";
const SECURITY_NONE: u8 = 1;
const ENC_RAW: i32 = 0;
const ENC_DESKTOP_SIZE: i32 = -223;
const ENC_QEMU_KEY: i32 = -258;

/// A changed area of the screen, in pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

/// The screen as of one framebuffer update.
#[derive(Debug, Clone)]
pub struct Frame {
    pub width: u16,
    pub height: u16,
    /// 4 bytes a pixel, B G R x (`GDK_MEMORY_B8G8R8X8`); rows of `width * 4`
    /// bytes with no padding. A copy of its own: the session keeps writing.
    pub pixels: Arc<[u8]>,
    /// What changed since the frame with `serial - 1`. When a reader skips
    /// a serial (the watch keeps only the latest), it must redraw it all.
    pub damage: Vec<Rect>,
    /// 0 for the black frame from before the first update, then +1 each.
    pub serial: u64,
}

/// Input for the guest. Pointer coordinates are framebuffer pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// Absolute position and the buttons held (bit 0 left, 1 middle,
    /// 2 right, 3/4 wheel up/down).
    Pointer { x: u16, y: u16, buttons: u8 },
    /// `keycode` is the hardware keycode as GTK reports it (evdev + 8),
    /// `keysym` the X keysym, used only when the server or the keymap
    /// cannot take the keycode.
    Key {
        keycode: u32,
        keysym: u32,
        down: bool,
    },
}

/// What the writer sends: input, or a framebuffer update request.
#[derive(Debug)]
enum Out {
    Input(Input),
    Update {
        incremental: bool,
        width: u16,
        height: u16,
    },
}

/// An open connection. Dropping it closes the connection.
#[derive(Debug)]
pub struct Session {
    out: mpsc::Sender<Out>,
    task: JoinHandle<Result<()>>,
    buttons: Cell<u8>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Session {
    /// Connects to a VNC Unix socket and completes the handshake. Must run
    /// on the I/O runtime. The receiver closes when the session ends.
    pub async fn connect(path: &Path) -> Result<(Session, watch::Receiver<Frame>)> {
        let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, UnixStream::connect(path))
            .await
            .context("timed out connecting to the VM's display")?
            .context("cannot connect to the VM's display")?;
        Self::start(stream).await
    }

    async fn start(mut stream: UnixStream) -> Result<(Session, watch::Receiver<Frame>)> {
        let (width, height) = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut stream))
            .await
            .context("the VM's display did not answer in time")??;
        let (rd, mut wr) = stream.into_split();
        write(&mut wr, &set_pixel_format()).await?;
        write(&mut wr, &set_encodings()).await?;
        write(&mut wr, &update_request(false, width, height)).await?;

        let fb = vec![0; frame_len(width, height)];
        let (frames, rx) = watch::channel(Frame {
            width,
            height,
            pixels: Arc::from(&fb[..]),
            damage: Vec::new(),
            serial: 0,
        });
        let (out, out_rx) = mpsc::channel(QUEUE);
        let screen = Screen {
            width,
            height,
            fb,
            serial: 0,
        };
        let qemu_keys = Arc::new(AtomicBool::new(false));
        let reader = read_loop(rd, screen, frames, out.clone(), qemu_keys.clone());
        let writer = write_loop(wr, out_rx, qemu_keys);
        let task = tokio::spawn(async move {
            tokio::select! {
                r = reader => r,
                r = writer => r,
            }
        });
        let session = Session {
            out,
            task,
            buttons: Cell::new(0),
        };
        Ok((session, rx))
    }

    /// Queues input without blocking. When the queue fills up, pointer
    /// motion goes first; a key or button change that finds no room ends
    /// the session rather than leaving a key held down in the guest.
    pub fn send(&self, input: Input) {
        let motion = match input {
            Input::Pointer { buttons, .. } => self.buttons.replace(buttons) == buttons,
            Input::Key { .. } => false,
        };
        if motion && self.out.capacity() <= KEEP_FREE {
            return;
        }
        if self.out.try_send(Out::Input(input)).is_err() && !motion {
            self.task.abort();
        }
    }
}

/// RFB 3.8 with security type None, up to and including ServerInit.
/// Returns the framebuffer size.
async fn handshake(s: &mut UnixStream) -> Result<(u16, u16)> {
    let mut version = [0; 12];
    s.read_exact(&mut version).await?;
    ensure!(
        &version == VERSION,
        "the VM's display does not speak RFB 3.8"
    );
    s.write_all(VERSION).await?;

    let n = s.read_u8().await?;
    // 0 types: the server refuses us; its reason is not ours to show.
    ensure!(n > 0, "the VM's display refused the connection");
    let mut types = vec![0; n.into()];
    s.read_exact(&mut types).await?;
    ensure!(
        types.contains(&SECURITY_NONE),
        "the VM's display asks for a password, which Stallo does not set up"
    );
    s.write_all(&[SECURITY_NONE]).await?;
    ensure!(
        s.read_u32().await? == 0,
        "the VM's display refused the connection"
    );

    s.write_all(&[1]).await?; // ClientInit: shared
    let width = s.read_u16().await?;
    let height = s.read_u16().await?;
    check_size(width, height)?;
    let mut pixel_format = [0; 16];
    s.read_exact(&mut pixel_format).await?;
    let name = s.read_u32().await?;
    ensure!(name <= MAX_NAME, "the VM's display sent a name too long");
    let mut name_buf = vec![0; name as usize];
    s.read_exact(&mut name_buf).await?; // never shown
    Ok((width, height))
}

fn check_size(width: u16, height: u16) -> Result<()> {
    ensure!(
        u64::from(width) * u64::from(height) <= MAX_PIXELS,
        "the VM's display is too large: {width}x{height}"
    );
    Ok(())
}

fn frame_len(width: u16, height: u16) -> usize {
    usize::from(width) * usize::from(height) * 4
}

/// 32 bits a pixel, depth 24, little-endian, true colour 0x00RRGGBB:
/// B G R x in memory.
fn set_pixel_format() -> [u8; 20] {
    [
        0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0,
    ]
}

fn set_encodings() -> Vec<u8> {
    let encodings = [ENC_RAW, ENC_DESKTOP_SIZE, ENC_QEMU_KEY];
    let mut m = vec![2, 0];
    m.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
    for e in encodings {
        m.extend_from_slice(&e.to_be_bytes());
    }
    m
}

fn update_request(incremental: bool, width: u16, height: u16) -> Vec<u8> {
    let mut m = vec![3, incremental.into(), 0, 0, 0, 0];
    m.extend_from_slice(&width.to_be_bytes());
    m.extend_from_slice(&height.to_be_bytes());
    m
}

/// The wire bytes for input; `qemu_keys` once the server took the QEMU
/// extended key event. `None` for a key with nothing to send.
fn input_message(input: Input, qemu_keys: bool) -> Option<Vec<u8>> {
    match input {
        Input::Pointer { x, y, buttons } => {
            Some([&[5, buttons][..], &x.to_be_bytes(), &y.to_be_bytes()].concat())
        }
        Input::Key {
            keycode,
            keysym,
            down,
        } => {
            let scancode = keycode
                .checked_sub(8)
                .and_then(qemu_scancode)
                .filter(|_| qemu_keys);
            let sym = keysym.to_be_bytes();
            match scancode {
                Some(code) => {
                    Some([&[255, 0, 0, down.into()][..], &sym, &code.to_be_bytes()].concat())
                }
                None if keysym != 0 => Some([&[4, down.into(), 0, 0][..], &sym].concat()),
                None => None,
            }
        }
    }
}

/// An evdev key code to the XT scancode QEMU expects: one byte, or for
/// `E0 xx` keys `xx | 0x80`. `None` for keys not in the table.
// ponytail: the keys of a PC keyboard plus common Japanese ones; extend
// from the Linux input and XT tables when a missing key is reported.
pub fn qemu_scancode(evdev: u32) -> Option<u32> {
    Some(match evdev {
        // Esc to F10, the number pad, F11/F12 and the extra key on ISO
        // keyboards: the XT codes are the evdev codes.
        1..=83 | 86..=88 => evdev,
        85 => 0x76,  // Zenkaku/Hankaku
        89 => 0x73,  // Ro
        92 => 0x79,  // Henkan
        93 => 0x70,  // Katakana/Hiragana
        94 => 0x7b,  // Muhenkan
        96 => 0x9c,  // keypad Enter
        97 => 0x9d,  // right Ctrl
        98 => 0xb5,  // keypad /
        99 => 0x54,  // SysRq / Print Screen
        100 => 0xb8, // right Alt
        102 => 0xc7, // Home
        103 => 0xc8, // Up
        104 => 0xc9, // Page Up
        105 => 0xcb, // Left
        106 => 0xcd, // Right
        107 => 0xcf, // End
        108 => 0xd0, // Down
        109 => 0xd1, // Page Down
        110 => 0xd2, // Insert
        111 => 0xd3, // Delete
        113 => 0xa0, // Mute
        114 => 0xae, // Volume Down
        115 => 0xb0, // Volume Up
        116 => 0xde, // Power
        117 => 0x59, // keypad =
        119 => 0xc6, // Pause
        121 => 0x7e, // keypad ,
        124 => 0x7d, // Yen
        125 => 0xdb, // left Super
        126 => 0xdc, // right Super
        127 => 0xdd, // Menu
        _ => return None,
    })
}

async fn write<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<()> {
    tokio::time::timeout(WRITE_TIMEOUT, w.write_all(bytes))
        .await
        .context("the VM's display stopped reading")??;
    Ok(())
}

async fn write_loop<W: AsyncWrite + Unpin>(
    mut w: W,
    mut rx: mpsc::Receiver<Out>,
    qemu_keys: Arc<AtomicBool>,
) -> Result<()> {
    while let Some(out) = rx.recv().await {
        let bytes = match out {
            Out::Update {
                incremental,
                width,
                height,
            } => update_request(incremental, width, height),
            Out::Input(input) => match input_message(input, qemu_keys.load(Ordering::Relaxed)) {
                Some(m) => m,
                None => continue,
            },
        };
        write(&mut w, &bytes).await?;
    }
    Ok(())
}

/// The framebuffer as the reader keeps it.
struct Screen {
    width: u16,
    height: u16,
    fb: Vec<u8>,
    serial: u64,
}

async fn read_loop<R: AsyncRead + Unpin>(
    rd: R,
    mut screen: Screen,
    frames: watch::Sender<Frame>,
    out: mpsc::Sender<Out>,
    qemu_keys: Arc<AtomicBool>,
) -> Result<()> {
    let mut r = BufReader::with_capacity(64 << 10, rd);
    loop {
        // No limit here: a still screen sends nothing.
        let kind = r.read_u8().await?;
        let message = read_message(&mut r, kind, &mut screen, &qemu_keys);
        let Some((damage, resized)) = tokio::time::timeout(MESSAGE_TIMEOUT, message)
            .await
            .context("the VM's display stalled mid-message")??
        else {
            continue;
        };
        if !damage.is_empty() {
            screen.serial += 1;
            frames.send_replace(Frame {
                width: screen.width,
                height: screen.height,
                // ponytail: one copy of the screen per update; share the
                // buffer copy-on-write if this shows up in a profile.
                pixels: Arc::from(&screen.fb[..]),
                damage,
                serial: screen.serial,
            });
        }
        // One request outstanding: the next one after each update.
        // ponytail: an unsolicited update (QEMU's key extension ack, a
        // resize) adds a request; QEMU folds pending requests into one.
        let next = Out::Update {
            incremental: !resized,
            width: screen.width,
            height: screen.height,
        };
        out.send(next).await.context("the session is closing")?;
    }
}

/// Reads the rest of one server message. `Some((damage, resized))` after
/// a framebuffer update, `None` after anything else we can let pass.
async fn read_message<R: AsyncRead + Unpin>(
    r: &mut R,
    kind: u8,
    screen: &mut Screen,
    qemu_keys: &AtomicBool,
) -> Result<Option<(Vec<Rect>, bool)>> {
    match kind {
        0 => {
            r.read_u8().await?;
            let rects = r.read_u16().await?;
            let mut damage = Vec::new();
            let mut resized = false;
            for _ in 0..rects {
                let rect = Rect {
                    x: r.read_u16().await?,
                    y: r.read_u16().await?,
                    w: r.read_u16().await?,
                    h: r.read_u16().await?,
                };
                match r.read_i32().await? {
                    ENC_RAW => {
                        read_raw(r, screen, rect).await?;
                        damage.push(rect);
                    }
                    ENC_DESKTOP_SIZE => {
                        check_size(rect.w, rect.h)?;
                        screen.width = rect.w;
                        screen.height = rect.h;
                        screen.fb = vec![0; frame_len(rect.w, rect.h)];
                        damage = vec![Rect {
                            x: 0,
                            y: 0,
                            w: rect.w,
                            h: rect.h,
                        }];
                        resized = true;
                    }
                    ENC_QEMU_KEY => qemu_keys.store(true, Ordering::Relaxed),
                    e => bail!("the VM's display sent an unknown encoding {e}"),
                }
            }
            Ok(Some((damage, resized)))
        }
        2 => Ok(None), // Bell
        3 => {
            // ServerCutText: never reaches the host clipboard.
            let mut pad = [0; 3];
            r.read_exact(&mut pad).await?;
            let len = r.read_u32().await?;
            ensure!(len <= MAX_CUT_TEXT, "the VM's display sent too much text");
            let skipped = tokio::io::copy(&mut r.take(len.into()), &mut tokio::io::sink()).await?;
            ensure!(skipped == u64::from(len), "the VM's display closed");
            Ok(None)
        }
        // SetColourMapEntries (we asked for true colour) or a message we
        // cannot know the length of.
        k => bail!("the VM's display sent an unexpected message {k}"),
    }
}

/// Reads a raw rectangle straight into the framebuffer, row by row.
async fn read_raw<R: AsyncRead + Unpin>(r: &mut R, screen: &mut Screen, rect: Rect) -> Result<()> {
    ensure!(
        u32::from(rect.x) + u32::from(rect.w) <= u32::from(screen.width)
            && u32::from(rect.y) + u32::from(rect.h) <= u32::from(screen.height),
        "the VM's display drew outside the screen"
    );
    let stride = usize::from(screen.width) * 4;
    let row = usize::from(rect.w) * 4;
    for y in usize::from(rect.y)..usize::from(rect.y) + usize::from(rect.h) {
        let start = y * stride + usize::from(rect.x) * 4;
        r.read_exact(&mut screen.fb[start..start + row]).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    async fn read_n(s: &mut UnixStream, n: usize) -> Vec<u8> {
        let mut b = vec![0; n];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut b))
            .await
            .expect("the client did not write")
            .unwrap();
        b
    }

    /// The server side of a good handshake, through the client's first
    /// update request.
    async fn serve_handshake(s: &mut UnixStream, w: u16, h: u16) {
        s.write_all(VERSION).await.unwrap();
        assert_eq!(read_n(s, 12).await, VERSION);
        s.write_all(&[2, 2, SECURITY_NONE]).await.unwrap();
        assert_eq!(read_n(s, 1).await, [SECURITY_NONE]);
        s.write_all(&[0, 0, 0, 0]).await.unwrap();
        assert_eq!(read_n(s, 1).await, [1], "shared");
        let mut init = Vec::new();
        init.extend_from_slice(&w.to_be_bytes());
        init.extend_from_slice(&h.to_be_bytes());
        init.extend_from_slice(&[0; 16]);
        init.extend_from_slice(&4u32.to_be_bytes());
        init.extend_from_slice(b"name");
        s.write_all(&init).await.unwrap();
        assert_eq!(read_n(s, 20).await, set_pixel_format());
        assert_eq!(
            read_n(s, 16).await,
            [
                2, 0, 0, 3, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x21, 0xff, 0xff, 0xfe, 0xfe
            ]
        );
        assert_eq!(read_n(s, 10).await, update_request(false, w, h));
    }

    async fn connected(w: u16, h: u16) -> (Session, watch::Receiver<Frame>, UnixStream) {
        let (client, mut server) = UnixStream::pair().unwrap();
        let (start, ()) = tokio::join!(Session::start(client), serve_handshake(&mut server, w, h));
        let (session, rx) = start.unwrap();
        (session, rx, server)
    }

    fn update(rects: &[(Rect, i32, &[u8])]) -> Vec<u8> {
        let mut m = vec![0, 0];
        m.extend_from_slice(&(rects.len() as u16).to_be_bytes());
        for (r, enc, data) in rects {
            for v in [r.x, r.y, r.w, r.h] {
                m.extend_from_slice(&v.to_be_bytes());
            }
            m.extend_from_slice(&enc.to_be_bytes());
            m.extend_from_slice(data);
        }
        m
    }

    fn rect(x: u16, y: u16, w: u16, h: u16) -> Rect {
        Rect { x, y, w, h }
    }

    /// The session's end: its error, failing on a panic or a hang.
    async fn ended(session: &mut Session) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(5), &mut session.task)
            .await
            .expect("the session did not end")
            .expect("the session panicked")
    }

    async fn start_err(server_bytes: Vec<u8>) -> String {
        let (client, mut server) = UnixStream::pair().unwrap();
        let serve = async move {
            server.write_all(&server_bytes).await.unwrap();
            // Keep the socket open so the client must decide by itself.
            let mut sink = Vec::new();
            let _ = server.read_to_end(&mut sink).await;
        };
        let start = async { Session::start(client).await.map(|_| ()) };
        tokio::select! {
            r = start => format!("{:#}", r.unwrap_err()),
            () = serve => panic!("the client hung up without an answer"),
        }
    }

    #[test]
    fn handshake_ok_and_raw_update() {
        rt().block_on(async {
            let (_session, mut rx, mut server) = connected(4, 3).await;
            {
                let f = rx.borrow();
                assert_eq!((f.width, f.height, f.serial), (4, 3, 0));
                assert_eq!(f.pixels.len(), 4 * 3 * 4);
            }
            // A 2x2 rect at (1, 1).
            let px: Vec<u8> = (1..=16).collect();
            server
                .write_all(&update(&[(rect(1, 1, 2, 2), ENC_RAW, &px)]))
                .await
                .unwrap();
            assert_eq!(read_n(&mut server, 10).await, update_request(true, 4, 3));
            rx.changed().await.unwrap();
            let f = rx.borrow_and_update().clone();
            assert_eq!(f.serial, 1);
            assert_eq!(f.damage, [rect(1, 1, 2, 2)]);
            let stride = 16;
            assert_eq!(f.pixels[stride + 4..stride + 12], px[..8]);
            assert_eq!(f.pixels[2 * stride + 4..2 * stride + 12], px[8..]);
            assert!(f.pixels[..stride].iter().all(|&b| b == 0));
            assert!(f.pixels[stride..stride + 4].iter().all(|&b| b == 0));
        });
    }

    #[test]
    fn bell_and_cut_text_are_ignored() {
        rt().block_on(async {
            let (_session, mut rx, mut server) = connected(2, 2).await;
            let mut m = vec![2, 3, 0, 0, 0, 0, 0, 0, 5];
            m.extend_from_slice(b"hello");
            m.extend(update(&[(rect(0, 0, 1, 1), ENC_RAW, &[9, 9, 9, 0])]));
            server.write_all(&m).await.unwrap();
            rx.changed().await.unwrap();
            assert_eq!(rx.borrow().pixels[..4], [9, 9, 9, 0]);
        });
    }

    #[test]
    fn refuses_other_versions() {
        rt().block_on(async {
            for v in [&b"RFB 003.003\n"[..], b"RFB 003.007\n", b"RFB 004.001\n"] {
                let e = start_err(v.to_vec()).await;
                assert!(e.contains("RFB 3.8"), "{e}");
            }
        });
    }

    #[test]
    fn refuses_security_other_than_none() {
        rt().block_on(async {
            let mut m = VERSION.to_vec();
            m.extend_from_slice(&[2, 2, 19]); // VNC auth, VeNCrypt
            let e = start_err(m).await;
            assert!(e.contains("password"), "{e}");
            let mut m = VERSION.to_vec();
            m.extend_from_slice(&[0, 0, 0, 0, 4]);
            let e = start_err(m).await;
            assert!(e.contains("refused"), "{e}");
        });
    }

    #[test]
    fn refuses_oversize_framebuffer_and_long_name() {
        rt().block_on(async {
            let head = [VERSION.to_vec(), vec![1, 1, 0, 0, 0, 0]].concat();
            let mut m = head.clone();
            m.extend_from_slice(&[0x10, 0x01, 0x10, 0x00]); // 4097 x 4096
            assert!(start_err(m).await.contains("too large"));
            let mut m = head;
            m.extend_from_slice(&[0, 1, 0, 1]);
            m.extend_from_slice(&[0; 16]);
            m.extend_from_slice(&(MAX_NAME + 1).to_be_bytes());
            assert!(start_err(m).await.contains("name too long"));
        });
    }

    #[test]
    fn handshake_times_out() {
        rt().block_on(async {
            tokio::time::pause();
            let (client, _server) = UnixStream::pair().unwrap();
            let e = Session::start(client).await.unwrap_err();
            assert!(format!("{e:#}").contains("in time"), "{e:#}");
        });
    }

    #[test]
    fn desktop_size_resizes() {
        rt().block_on(async {
            let (_session, mut rx, mut server) = connected(4, 3).await;
            server
                .write_all(&update(&[(rect(0, 0, 640, 480), ENC_DESKTOP_SIZE, &[])]))
                .await
                .unwrap();
            assert_eq!(
                read_n(&mut server, 10).await,
                update_request(false, 640, 480)
            );
            rx.changed().await.unwrap();
            let f = rx.borrow();
            assert_eq!((f.width, f.height), (640, 480));
            assert_eq!(f.pixels.len(), 640 * 480 * 4);
            assert_eq!(f.damage, [rect(0, 0, 640, 480)]);
        });
    }

    #[test]
    fn key_events() {
        rt().block_on(async {
            let (session, _rx, mut server) = connected(4, 3).await;
            // Before the server takes the extension: the X keysym.
            let a = Input::Key {
                keycode: 30 + 8,
                keysym: 0x61,
                down: true,
            };
            session.send(a);
            assert_eq!(read_n(&mut server, 8).await, [4, 1, 0, 0, 0, 0, 0, 0x61]);
            // QEMU acks the extension with a pseudo-rect.
            server
                .write_all(&update(&[(rect(0, 0, 4, 3), ENC_QEMU_KEY, &[])]))
                .await
                .unwrap();
            assert_eq!(read_n(&mut server, 10).await, update_request(true, 4, 3));
            session.send(a);
            assert_eq!(
                read_n(&mut server, 12).await,
                [255, 0, 0, 1, 0, 0, 0, 0x61, 0, 0, 0, 0x1e]
            );
            // Right Ctrl up: an E0 key.
            session.send(Input::Key {
                keycode: 97 + 8,
                keysym: 0xffe4,
                down: false,
            });
            assert_eq!(
                read_n(&mut server, 12).await,
                [255, 0, 0, 0, 0, 0, 0xff, 0xe4, 0, 0, 0, 0x9d]
            );
            // No scancode: the keysym after all.
            session.send(Input::Key {
                keycode: 600,
                keysym: 0x1008ff13,
                down: true,
            });
            assert_eq!(
                read_n(&mut server, 8).await,
                [4, 1, 0, 0, 0x10, 0x08, 0xff, 0x13]
            );
        });
    }

    #[test]
    fn scancodes() {
        assert_eq!(qemu_scancode(1), Some(0x01)); // Esc
        assert_eq!(qemu_scancode(28), Some(0x1c)); // Enter
        assert_eq!(qemu_scancode(88), Some(0x58)); // F12
        assert_eq!(qemu_scancode(103), Some(0xc8)); // Up
        assert_eq!(qemu_scancode(125), Some(0xdb)); // Super
        assert_eq!(qemu_scancode(0), None);
        assert_eq!(qemu_scancode(84), None);
        assert_eq!(qemu_scancode(u32::MAX), None);
    }

    #[test]
    fn pointer_events() {
        rt().block_on(async {
            let (session, _rx, mut server) = connected(400, 300).await;
            session.send(Input::Pointer {
                x: 300,
                y: 200,
                buttons: 1,
            });
            assert_eq!(read_n(&mut server, 6).await, [5, 1, 1, 44, 0, 200]);
        });
    }

    #[test]
    fn motion_is_dropped_before_keys() {
        rt().block_on(async {
            // A server that never reads: the writer gets stuck.
            let (mut session, _rx, _server) = connected(4, 3).await;
            for i in 0..1000 {
                session.send(Input::Pointer {
                    x: i,
                    y: 0,
                    buttons: 0,
                });
            }
            assert!(session.out.capacity() >= KEEP_FREE);
            for _ in 0..KEEP_FREE / 2 {
                session.send(Input::Key {
                    keycode: 38,
                    keysym: 0x61,
                    down: true,
                });
            }
            assert!(!session.task.is_finished());
            // A key with no room left ends the session.
            for _ in 0..=KEEP_FREE / 2 {
                session.send(Input::Key {
                    keycode: 38,
                    keysym: 0x61,
                    down: false,
                });
            }
            let end = tokio::time::timeout(Duration::from_secs(5), &mut session.task).await;
            assert!(end.unwrap().unwrap_err().is_cancelled());
        });
    }

    #[test]
    fn hostile_messages_end_the_session() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (
                update(&[(rect(3, 0, 2, 1), ENC_RAW, &[0; 8])]),
                "outside the screen",
            ),
            (
                update(&[(rect(0, 0xffff, 1, 2), ENC_RAW, &[0; 8])]),
                "outside the screen",
            ),
            (
                update(&[(rect(0, 0, 4097, 4096), ENC_DESKTOP_SIZE, &[])]),
                "too large",
            ),
            (update(&[(rect(0, 0, 1, 1), 5, &[])]), "unknown encoding"),
            (vec![3, 0, 0, 0, 0, 0x10, 0, 1], "too much text"),
            (vec![1, 0, 0, 0, 0, 1], "unexpected message 1"),
            (vec![9], "unexpected message 9"),
        ];
        rt().block_on(async {
            for (bytes, want) in cases {
                let (mut session, mut rx, mut server) = connected(4, 3).await;
                server.write_all(&bytes).await.unwrap();
                let e = format!("{:#}", ended(&mut session).await.unwrap_err());
                assert!(e.contains(want), "{want}: {e}");
                assert!(rx.changed().await.is_err());
            }
        });
    }

    #[test]
    fn garbage_never_panics() {
        let mut seed: u64 = 0x5eed;
        let mut next = move || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as u8
        };
        rt().block_on(async {
            for _ in 0..300 {
                let (mut session, _rx, mut server) = connected(64, 48).await;
                // Mostly small valid-looking messages, often zeros so that
                // raw rects and small sizes come up.
                let mut bytes = Vec::new();
                for _ in 0..next() % 16 {
                    bytes.push(next() % 5);
                    for _ in 0..next() % 64 {
                        let b = next();
                        bytes.push(if b < 128 { 0 } else { next() });
                    }
                }
                let _ = server.write_all(&bytes).await;
                drop(server);
                let _ = ended(&mut session).await;
            }
        });
    }
}
