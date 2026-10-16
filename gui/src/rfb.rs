//! A small RFB (VNC) client for a VM's screen: RFB 3.8, no authentication,
//! raw pixels, over the VM's local VNC Unix socket. It runs on the I/O
//! runtime; the GTK side gets frames from a watch channel and sends input
//! through [`Session::send`]. Everything the server sends is untrusted: sizes
//! are capped and checked, and anything unexpected ends the session.

#![expect(dead_code, reason = "the Screen tab (GUI-8) is the first user")]

use std::cell::Cell;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot, watch};

/// From connecting up to and including the server's init message.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// For the rest of a server message once its first byte is in; the server
/// may stay quiet for as long as the screen does not change.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);
/// For one message to the server, and for letting go of held keys and
/// buttons when the session ends.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// The longest side we accept: at most 64 MiB of BGRx.
const MAX_SIDE: u16 = 4096;
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
    /// The whole screen, 4 bytes a pixel, B G R x (`GDK_MEMORY_B8G8R8X8`);
    /// rows of `width * 4` bytes with no padding. Never changes once
    /// published. The session reuses the buffer two frames later, so drop a
    /// frame once a newer one is shown: while it is still held, the session
    /// has to copy it.
    pub pixels: Arc<Vec<u8>>,
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

/// An open connection. Dropping it ends the session: the guest gets a
/// release for every key and button still held (within `WRITE_TIMEOUT`),
/// then the connection closes.
pub struct Session {
    out: mpsc::Sender<Out>,
    /// Sent to on overload; dropped with the session.
    stop: Cell<Option<oneshot::Sender<()>>>,
    end: Arc<OnceLock<String>>,
    buttons: Cell<u8>,
    #[cfg(test)]
    task: tokio::task::JoinHandle<()>,
}

impl Session {
    /// Connects to a VNC Unix socket and completes the handshake. Must run
    /// on the I/O runtime. The receiver closes when the session ends; then
    /// [`Session::end_reason`] says why.
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

        let black = || Arc::new(vec![0; frame_len(width, height)]);
        let (frames, rx) = watch::channel(Frame {
            width,
            height,
            pixels: black(),
            damage: Vec::new(),
            serial: 0,
        });
        let screen = Screen {
            width,
            height,
            back: black(),
            behind: Vec::new(),
            damage: Vec::new(),
            content: false,
            serial: 0,
        };
        let (out, out_rx) = mpsc::channel(QUEUE);
        let (stop, stop_rx) = oneshot::channel();
        let end = Arc::new(OnceLock::new());
        let io = Io {
            rd,
            wr,
            screen,
            frames,
            out: out.clone(),
            out_rx,
            stop: stop_rx,
        };
        let task = tokio::spawn(run(io, end.clone()));
        #[cfg(not(test))]
        drop(task);
        let session = Session {
            out,
            stop: Cell::new(Some(stop)),
            end,
            buttons: Cell::new(0),
            #[cfg(test)]
            task,
        };
        Ok((session, rx))
    }

    /// Queues input without blocking. When the queue fills up, pointer
    /// motion is dropped first; a key or button change that finds no room
    /// ends the session, which then lets go of everything it holds down.
    pub fn send(&self, input: Input) {
        let motion = match input {
            Input::Pointer { buttons, .. } => self.buttons.replace(buttons) == buttons,
            Input::Key { .. } => false,
        };
        if motion && self.out.capacity() <= KEEP_FREE {
            return;
        }
        if self.out.try_send(Out::Input(input)).is_err()
            && !motion
            && let Some(stop) = self.stop.take()
        {
            let _ = stop.send(());
        }
    }

    /// Why the session ended; `None` while it runs.
    pub fn end_reason(&self) -> Option<&str> {
        self.end.get().map(String::as_str)
    }
}

/// Everything the session task owns.
struct Io {
    rd: OwnedReadHalf,
    wr: OwnedWriteHalf,
    screen: Screen,
    frames: watch::Sender<Frame>,
    out: mpsc::Sender<Out>,
    out_rx: mpsc::Receiver<Out>,
    stop: oneshot::Receiver<()>,
}

/// The session task: reads until something ends it, lets go of held keys
/// and buttons, and records why it ended before the frames close.
async fn run(mut io: Io, end: Arc<OnceLock<String>>) {
    let qemu_keys = AtomicBool::new(false);
    let mut writer = Writer {
        w: io.wr,
        keys: HashMap::new(),
        pointer: (0, 0, 0),
        dirty: false,
    };
    let result = tokio::select! {
        r = read_loop(io.rd, &mut io.screen, &io.frames, &io.out, &qemu_keys) => r,
        r = writer.run(&mut io.out_rx, &qemu_keys) => r,
        stop = io.stop => match stop {
            Ok(()) => Err(anyhow!("the VM's display did not keep up with the input")),
            Err(_) => Ok(()), // the session was dropped
        },
    };
    // Not after a write cut off half-way: the stream is out of step.
    if !writer.dirty {
        let _ = tokio::time::timeout(WRITE_TIMEOUT, writer.release()).await;
    }
    let reason = match result {
        Ok(()) => "closed".to_owned(),
        Err(e) => {
            let e = format!("{e:#}");
            tracing::warn!("VM display session ended: {e}");
            e
        }
    };
    let _ = end.set(reason);
    // `io.frames` drops here, after the reason is in.
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
        (1..=MAX_SIDE).contains(&width) && (1..=MAX_SIDE).contains(&height),
        "the VM's display has an unsupported size: {width}x{height}"
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

fn pointer_message(x: u16, y: u16, buttons: u8) -> Vec<u8> {
    [&[5, buttons][..], &x.to_be_bytes(), &y.to_be_bytes()].concat()
}

/// How a key went to the server at key-down; its key-up goes the same way.
#[derive(Debug, Clone, Copy)]
enum Sent {
    /// The QEMU extended key event.
    Qemu { keysym: u32, scancode: u32 },
    /// A plain KeyEvent.
    Keysym(u32),
}

impl Sent {
    /// The scancode once the server took the QEMU extension and the key is
    /// in the table, else the keysym. `None` with neither.
    fn choose(keycode: u32, keysym: u32, qemu_keys: bool) -> Option<Sent> {
        let scancode = keycode
            .checked_sub(8)
            .and_then(qemu_scancode)
            .filter(|_| qemu_keys);
        match scancode {
            Some(scancode) => Some(Sent::Qemu { keysym, scancode }),
            None if keysym != 0 => Some(Sent::Keysym(keysym)),
            None => None,
        }
    }

    fn message(self, down: bool) -> Vec<u8> {
        match self {
            Sent::Qemu { keysym, scancode } => [
                &[255, 0, 0, down.into()][..],
                &keysym.to_be_bytes(),
                &scancode.to_be_bytes(),
            ]
            .concat(),
            Sent::Keysym(keysym) => [&[4, down.into(), 0, 0][..], &keysym.to_be_bytes()].concat(),
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

/// Writes to the server and remembers what the guest sees held down.
struct Writer<W> {
    w: W,
    /// Keys down, by GTK keycode, with how they were sent.
    keys: HashMap<u32, Sent>,
    /// The last pointer event written: x, y, buttons.
    pointer: (u16, u16, u8),
    /// A write is under way; if it is cut off, the stream is out of step.
    dirty: bool,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    async fn run(&mut self, rx: &mut mpsc::Receiver<Out>, qemu_keys: &AtomicBool) -> Result<()> {
        while let Some(out) = rx.recv().await {
            let bytes = match out {
                Out::Update {
                    incremental,
                    width,
                    height,
                } => update_request(incremental, width, height),
                Out::Input(Input::Pointer { x, y, buttons }) => {
                    self.pointer = (x, y, buttons);
                    pointer_message(x, y, buttons)
                }
                Out::Input(Input::Key {
                    keycode,
                    keysym,
                    down: true,
                }) => {
                    // A repeat goes the way the first key-down went.
                    let sent = match self.keys.get(&keycode) {
                        Some(&sent) => sent,
                        None => {
                            let qemu = qemu_keys.load(Ordering::Relaxed);
                            let Some(sent) = Sent::choose(keycode, keysym, qemu) else {
                                continue;
                            };
                            self.keys.insert(keycode, sent);
                            sent
                        }
                    };
                    sent.message(true)
                }
                // A key-up for a key the guest never saw go down is dropped.
                Out::Input(Input::Key { keycode, .. }) => match self.keys.remove(&keycode) {
                    Some(sent) => sent.message(false),
                    None => continue,
                },
            };
            self.write(&bytes).await?;
        }
        Ok(())
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.dirty = true;
        write(&mut self.w, bytes).await?;
        self.dirty = false;
        Ok(())
    }

    /// Lets go of every key and button the guest sees held.
    async fn release(&mut self) -> Result<()> {
        for sent in std::mem::take(&mut self.keys).into_values() {
            self.write(&sent.message(false)).await?;
        }
        let (x, y, buttons) = self.pointer;
        if buttons != 0 {
            self.pointer.2 = 0;
            self.write(&pointer_message(x, y, 0)).await?;
        }
        Ok(())
    }
}

/// The reader's side of the screen: it writes into `back` while the watch
/// holds the front, and the two swap on each publish.
struct Screen {
    width: u16,
    height: u16,
    back: Arc<Vec<u8>>,
    /// What `back` misses from the front: the damage last published.
    behind: Vec<Rect>,
    /// Changes not published yet, and whether any of them is content.
    damage: Vec<Rect>,
    content: bool,
    serial: u64,
}

impl Screen {
    /// The buffer to draw into, caught up with the front. Copies it whole
    /// only while a reader still holds it.
    fn back(&mut self, frames: &watch::Sender<Frame>) -> &mut Vec<u8> {
        let back = Arc::make_mut(&mut self.back);
        if !self.behind.is_empty() {
            let front = frames.borrow();
            if back.len() == front.pixels.len() {
                let stride = usize::from(front.width) * 4;
                for r in &self.behind {
                    let row = usize::from(r.w) * 4;
                    for y in usize::from(r.y)..usize::from(r.y) + usize::from(r.h) {
                        let start = y * stride + usize::from(r.x) * 4;
                        back[start..start + row].copy_from_slice(&front.pixels[start..start + row]);
                    }
                }
            } else {
                back.clone_from(&front.pixels);
            }
            self.behind.clear();
        }
        back
    }

    fn resize(&mut self, width: u16, height: u16) -> Result<()> {
        check_size(width, height)?;
        self.width = width;
        self.height = height;
        self.back = Arc::new(vec![0; frame_len(width, height)]);
        self.behind.clear();
        self.damage = vec![Rect {
            x: 0,
            y: 0,
            w: width,
            h: height,
        }];
        Ok(())
    }

    /// Publishes `back` once it has content: a resize alone would show a
    /// black screen.
    fn publish(&mut self, frames: &watch::Sender<Frame>) {
        if !self.content {
            return;
        }
        self.content = false;
        self.serial += 1;
        let damage = std::mem::take(&mut self.damage);
        let old = frames.send_replace(Frame {
            width: self.width,
            height: self.height,
            pixels: std::mem::take(&mut self.back),
            damage: damage.clone(),
            serial: self.serial,
        });
        self.back = old.pixels;
        self.behind = damage;
    }
}

async fn read_loop<R: AsyncRead + Unpin>(
    rd: R,
    screen: &mut Screen,
    frames: &watch::Sender<Frame>,
    out: &mpsc::Sender<Out>,
    qemu_keys: &AtomicBool,
) -> Result<()> {
    let mut r = BufReader::with_capacity(64 << 10, rd);
    loop {
        // No limit here: a still screen sends nothing.
        let kind = r.read_u8().await?;
        let message = read_message(&mut r, kind, screen, frames, qemu_keys);
        let Some(resized) = tokio::time::timeout(MESSAGE_TIMEOUT, message)
            .await
            .context("the VM's display stalled mid-message")??
        else {
            continue;
        };
        screen.publish(frames);
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

/// Reads the rest of one server message. `Some(resized)` after a
/// framebuffer update, `None` after anything else we can let pass.
async fn read_message<R: AsyncRead + Unpin>(
    r: &mut R,
    kind: u8,
    screen: &mut Screen,
    frames: &watch::Sender<Frame>,
    qemu_keys: &AtomicBool,
) -> Result<Option<bool>> {
    match kind {
        0 => {
            r.read_u8().await?;
            let rects = r.read_u16().await?;
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
                        read_raw(r, screen, frames, rect).await?;
                        screen.damage.push(rect);
                        screen.content = true;
                    }
                    ENC_DESKTOP_SIZE => {
                        screen.resize(rect.w, rect.h)?;
                        screen.content = false;
                        resized = true;
                    }
                    ENC_QEMU_KEY => qemu_keys.store(true, Ordering::Relaxed),
                    e => bail!("the VM's display sent an unknown encoding {e}"),
                }
            }
            Ok(Some(resized))
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
async fn read_raw<R: AsyncRead + Unpin>(
    r: &mut R,
    screen: &mut Screen,
    frames: &watch::Sender<Frame>,
    rect: Rect,
) -> Result<()> {
    ensure!(
        u32::from(rect.x) + u32::from(rect.w) <= u32::from(screen.width)
            && u32::from(rect.y) + u32::from(rect.h) <= u32::from(screen.height),
        "the VM's display drew outside the screen"
    );
    let stride = usize::from(screen.width) * 4;
    let row = usize::from(rect.w) * 4;
    let fb = screen.back(frames);
    for y in usize::from(rect.y)..usize::from(rect.y) + usize::from(rect.h) {
        let start = y * stride + usize::from(rect.x) * 4;
        r.read_exact(&mut fb[start..start + row]).await?;
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

    /// Why the session ended, failing on a panic or a hang.
    async fn ended(session: &mut Session) -> String {
        tokio::time::timeout(Duration::from_secs(5), &mut session.task)
            .await
            .expect("the session did not end")
            .expect("the session panicked");
        session.end_reason().unwrap().to_owned()
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
    fn refuses_bad_framebuffer_sizes_and_long_names() {
        rt().block_on(async {
            let head = [VERSION.to_vec(), vec![1, 1, 0, 0, 0, 0]].concat();
            for size in [
                [0x10, 0x01, 0x10, 0x00],
                [0x20, 0, 0, 1],
                [0, 0, 0, 1],
                [0, 1, 0, 0],
            ] {
                let e = start_err([&head[..], &size].concat()).await;
                assert!(e.contains("unsupported size"), "{size:?}: {e}");
            }
            let mut m = head;
            m.extend_from_slice(&[0x10, 0, 0x10, 0]); // 4096 x 4096 is fine
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
            let Err(e) = Session::start(client).await else {
                panic!("the handshake did not time out");
            };
            assert!(format!("{e:#}").contains("in time"), "{e:#}");
        });
    }

    #[test]
    fn desktop_size_waits_for_content() {
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
            // No black frame for the resize alone.
            assert!(!rx.has_changed().unwrap());
            server
                .write_all(&update(&[(rect(0, 0, 1, 1), ENC_RAW, &[7; 4])]))
                .await
                .unwrap();
            assert_eq!(
                read_n(&mut server, 10).await,
                update_request(true, 640, 480)
            );
            let f = rx.borrow_and_update().clone();
            assert_eq!((f.width, f.height, f.serial), (640, 480, 1));
            assert_eq!(f.pixels.len(), 640 * 480 * 4);
            assert_eq!(f.pixels[..4], [7; 4]);
            assert_eq!(f.damage, [rect(0, 0, 640, 480), rect(0, 0, 1, 1)]);
        });
    }

    /// One pixel at `x` of a 4x1 screen, and the frame it makes.
    async fn draw(server: &mut UnixStream, rx: &mut watch::Receiver<Frame>, x: u16) -> Frame {
        let v = x as u8 + 1;
        server
            .write_all(&update(&[(rect(x, 0, 1, 1), ENC_RAW, &[v; 4])]))
            .await
            .unwrap();
        assert_eq!(read_n(server, 10).await, update_request(true, 4, 1));
        rx.borrow_and_update().clone()
    }

    fn row(px: [u8; 4]) -> Vec<u8> {
        px.iter().flat_map(|&v| [v; 4]).collect()
    }

    #[test]
    fn frames_are_whole_and_buffers_reused() {
        rt().block_on(async {
            let (_session, mut rx, mut server) = connected(4, 1).await;
            // Holding every frame: each stays as it was published.
            let f1 = draw(&mut server, &mut rx, 0).await;
            let f2 = draw(&mut server, &mut rx, 1).await;
            let f3 = draw(&mut server, &mut rx, 2).await;
            assert_eq!(*f1.pixels, row([1, 0, 0, 0]));
            assert_eq!(*f2.pixels, row([1, 2, 0, 0]));
            assert_eq!(*f3.pixels, row([1, 2, 3, 0]));
            assert_eq!(f3.damage, [rect(2, 0, 1, 1)]);
            // Dropping them: the session draws into the same two buffers.
            let p3 = Arc::as_ptr(&f3.pixels);
            drop((f1, f2, f3));
            let f4 = draw(&mut server, &mut rx, 3).await;
            assert_eq!(*f4.pixels, row([1, 2, 3, 4]));
            drop(f4);
            let f5 = draw(&mut server, &mut rx, 0).await;
            assert_eq!(Arc::as_ptr(&f5.pixels), p3);
            assert_eq!(*f5.pixels, row([1, 2, 3, 4]));
            assert_eq!(f5.serial, 5);
        });
    }

    #[test]
    fn key_events() {
        rt().block_on(async {
            let (session, _rx, mut server) = connected(4, 3).await;
            let a = |down| Input::Key {
                keycode: 30 + 8,
                keysym: 0x61,
                down,
            };
            // Before the server takes the extension: the X keysym.
            session.send(a(true));
            assert_eq!(read_n(&mut server, 8).await, [4, 1, 0, 0, 0, 0, 0, 0x61]);
            // QEMU acks the extension with a pseudo-rect.
            server
                .write_all(&update(&[(rect(0, 0, 4, 3), ENC_QEMU_KEY, &[])]))
                .await
                .unwrap();
            assert_eq!(read_n(&mut server, 10).await, update_request(true, 4, 3));
            // The key-up goes the way its key-down went.
            session.send(a(false));
            assert_eq!(read_n(&mut server, 8).await, [4, 0, 0, 0, 0, 0, 0, 0x61]);
            // Now as scancodes, repeats included.
            let ext = |down: u8| [255, 0, 0, down, 0, 0, 0, 0x61, 0, 0, 0, 0x1e];
            session.send(a(true));
            assert_eq!(read_n(&mut server, 12).await, ext(1));
            session.send(a(true));
            assert_eq!(read_n(&mut server, 12).await, ext(1));
            session.send(a(false));
            assert_eq!(read_n(&mut server, 12).await, ext(0));
            // Right Ctrl: an E0 key.
            session.send(Input::Key {
                keycode: 97 + 8,
                keysym: 0xffe4,
                down: true,
            });
            assert_eq!(
                read_n(&mut server, 12).await,
                [255, 0, 0, 1, 0, 0, 0xff, 0xe4, 0, 0, 0, 0x9d]
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
            // A key-up without a key-down sends nothing.
            session.send(a(false));
            session.send(Input::Pointer {
                x: 1,
                y: 2,
                buttons: 0,
            });
            assert_eq!(read_n(&mut server, 6).await, [5, 0, 0, 1, 0, 2]);
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
    fn dropping_releases_held_keys_and_buttons() {
        rt().block_on(async {
            let (session, _rx, mut server) = connected(4, 3).await;
            session.send(Input::Key {
                keycode: 38,
                keysym: 0x61,
                down: true,
            });
            session.send(Input::Pointer {
                x: 2,
                y: 1,
                buttons: 4,
            });
            assert_eq!(read_n(&mut server, 8).await, [4, 1, 0, 0, 0, 0, 0, 0x61]);
            assert_eq!(read_n(&mut server, 6).await, [5, 4, 0, 2, 0, 1]);
            drop(session);
            assert_eq!(read_n(&mut server, 8).await, [4, 0, 0, 0, 0, 0, 0, 0x61]);
            assert_eq!(read_n(&mut server, 6).await, [5, 0, 0, 2, 0, 1]);
            let mut rest = Vec::new();
            server.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty(), "{rest:?}");
        });
    }

    #[test]
    fn motion_is_dropped_before_keys() {
        rt().block_on(async {
            // No await between the sends, so the writer cannot drain the
            // queue in the meantime.
            let (mut session, _rx, _server) = connected(4, 3).await;
            for i in 0..1000 {
                session.send(Input::Pointer {
                    x: i,
                    y: 0,
                    buttons: 0,
                });
            }
            assert_eq!(session.out.capacity(), KEEP_FREE);
            for _ in 0..KEEP_FREE {
                session.send(Input::Key {
                    keycode: 38,
                    keysym: 0x61,
                    down: true,
                });
            }
            assert_eq!(session.out.capacity(), 0);
            assert!(session.end_reason().is_none());
            // A key with no room left ends the session.
            session.send(Input::Key {
                keycode: 38,
                keysym: 0x61,
                down: false,
            });
            let e = ended(&mut session).await;
            assert!(e.contains("keep up"), "{e}");
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
                "unsupported size",
            ),
            (
                update(&[(rect(0, 0, 8192, 1), ENC_DESKTOP_SIZE, &[])]),
                "unsupported size",
            ),
            (
                update(&[(rect(0, 0, 0, 480), ENC_DESKTOP_SIZE, &[])]),
                "unsupported size",
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
                let e = ended(&mut session).await;
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
                ended(&mut session).await;
            }
        });
    }
}
