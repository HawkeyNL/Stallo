//! The Files tab: copies a file into a running VM or out of it with the
//! daemon's `file_write` and `file_read`, as `stallo cp` does. Host files
//! are read and written off the GTK thread a chunk at a time, so the tab
//! shows progress and can cancel between chunks. The window keeps the
//! copies ([`model::Copies`]), so a VM's page opened again shows its copy.

use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::sync::Arc;

use adw::prelude::*;
use adw::{gdk, gio, glib, gtk};
use libadwaita as adw;
use stallo::api::{FILE_WRITE_CHUNK, VmInfo};

use super::Vms;
use crate::client;
use crate::model::{self, CallError, Copies, CopyJob, Op, Transfer};

pub(super) struct Files {
    name: String,
    vms: Weak<Vms>,
    /// "status" while the VM does not run, else "files".
    pub root: gtk::Stack,
    status: adw::StatusPage,
    start: gtk::Button,
    upload: gtk::Button,
    download: gtk::Button,
    admin: adw::SwitchRow,
    progress: adw::PreferencesGroup,
    row: adw::ActionRow,
    bar: gtk::ProgressBar,
    cancel: gtk::Button,
    /// No new copy while an action on the VM runs or the daemon is away.
    blocked: Cell<bool>,
    /// A copy on this VM runs: one at a time.
    copying: Cell<bool>,
}

impl Files {
    pub fn new(vm: &VmInfo, vms: &Rc<Vms>) -> Rc<Self> {
        let start = gtk::Button::builder()
            .label("Start")
            .halign(gtk::Align::Center)
            .css_classes(["pill", "suggested-action"])
            .build();
        let status = adw::StatusPage::builder().child(&start).build();

        let button = |label: &str| {
            gtk::Button::builder()
                .label(label)
                .valign(gtk::Align::Center)
                .build()
        };
        let (upload, download) = (button("Upload…"), button("Download…"));
        let row = |title: &str, subtitle: &str, button: &gtk::Button| {
            let row = adw::ActionRow::builder()
                .title(title)
                .subtitle(subtitle)
                .activatable_widget(button)
                .build();
            row.add_suffix(button);
            row
        };
        // Fixed text only: descriptions are markup.
        let copy = adw::PreferencesGroup::builder()
            .title("Copy Files")
            .description("Needs qemu-guest-agent running in the VM.")
            .build();
        copy.add(&row(
            "Upload a File",
            "From this computer into the VM. You can also drop a file here.",
            &upload,
        ));
        copy.add(&row(
            "Download a File",
            "From the VM to this computer.",
            &download,
        ));
        let admin = adw::SwitchRow::builder()
            .title("As Root")
            .subtitle("Read and write as root instead of the VM's normal user, for system files.")
            .build();
        let advanced = adw::ExpanderRow::builder().title("Advanced").build();
        advanced.add_row(&admin);
        copy.add(&advanced);

        let bar = gtk::ProgressBar::builder()
            .valign(gtk::Align::Center)
            .width_request(96)
            .build();
        bar.update_property(&[gtk::accessible::Property::Label("Copy progress")]);
        let cancel = button("Cancel");
        let progress_row = adw::ActionRow::builder().use_markup(false).build();
        progress_row.add_suffix(&bar);
        progress_row.add_suffix(&cancel);
        let progress = adw::PreferencesGroup::builder().visible(false).build();
        progress.add(&progress_row);

        let page = adw::PreferencesPage::new();
        page.add(&copy);
        page.add(&progress);
        let root = gtk::Stack::new();
        root.add_named(&status, Some("status"));
        root.add_named(&page, Some("files"));

        let files = Rc::new(Self {
            name: vm.name.clone(),
            vms: Rc::downgrade(vms),
            root,
            status,
            start,
            upload,
            download,
            admin,
            progress,
            row: progress_row,
            bar,
            cancel,
            blocked: Cell::new(true),
            copying: Cell::new(false),
        });
        files.connect_signals(&page);
        files
    }

    /// Weak: the widgets must not keep the tab alive.
    fn connect_signals(self: &Rc<Self>, page: &adw::PreferencesPage) {
        let f = Rc::downgrade(self);
        self.start.connect_clicked(move |_| {
            if let Some(f) = f.upgrade()
                && let Some(v) = f.vms.upgrade()
            {
                v.ask(Op::Start, &f.name);
            }
        });
        let f = Rc::downgrade(self);
        self.upload.connect_clicked(move |_| {
            if let Some(f) = f.upgrade() {
                f.pick_upload();
            }
        });
        let f = Rc::downgrade(self);
        self.download.connect_clicked(move |_| {
            if let Some(f) = f.upgrade() {
                f.ask_download();
            }
        });
        let f = Rc::downgrade(self);
        self.cancel.connect_clicked(move |_| {
            if let Some(f) = f.upgrade()
                && let Some(v) = f.vms.upgrade()
            {
                v.copies.borrow_mut().cancel(&f.name);
                v.show_copy(&f.name);
            }
        });
        let drop = gtk::DropTarget::new(gio::File::static_type(), gdk::DragAction::COPY);
        let f = Rc::downgrade(self);
        drop.connect_drop(move |_, value, _, _| {
            let (Some(f), Ok(file)) = (f.upgrade(), value.get::<gio::File>()) else {
                return false;
            };
            if !f.idle() {
                return false;
            }
            f.ask_upload(&file);
            true
        });
        page.add_controller(drop);
    }

    /// Shows `vm` and its copy, if any, as they are now; `blocked` as for
    /// the VM's buttons.
    pub fn update(&self, vm: &VmInfo, blocked: bool, copy: Option<&CopyJob>) {
        self.blocked.set(blocked);
        match model::files_status(vm, copy.is_some()) {
            Some(s) => {
                self.status.set_icon_name(s.icon);
                self.status.set_title(s.title);
                self.status.set_description(Some(s.description));
                self.start.set_visible(s.button.is_some());
                self.start.set_sensitive(!blocked);
                self.root.set_visible_child_name("status");
            }
            None => self.root.set_visible_child_name("files"),
        }
        self.show_copy(copy);
    }

    /// Shows the VM's copy, or hides the progress row if none runs.
    pub fn show_copy(&self, copy: Option<&CopyJob>) {
        self.copying.set(copy.is_some());
        self.progress.set_visible(copy.is_some());
        if let Some(c) = copy {
            self.row.set_title(&c.transfer.title());
            self.row.set_subtitle(&c.subtitle());
            match c.transfer.fraction() {
                Some(f) => self.bar.set_fraction(f),
                None => self.bar.pulse(),
            }
            self.cancel.set_sensitive(!c.cancelled);
        }
        let idle = self.idle();
        self.upload.set_sensitive(idle);
        self.download.set_sensitive(idle);
        // A copy keeps the user it started with.
        self.admin.set_sensitive(!self.copying.get());
    }

    fn idle(&self) -> bool {
        !self.blocked.get() && !self.copying.get()
    }

    fn toast(&self, text: &str) {
        if let Some(v) = self.vms.upgrade() {
            v.ui.toast(text);
        }
    }

    fn window(&self) -> Option<gtk::Window> {
        self.root.root().and_downcast()
    }

    fn pick_upload(self: &Rc<Self>) {
        let dialog = gtk::FileDialog::builder()
            .title("Upload a File")
            .modal(true)
            .build();
        let (f, window) = (Rc::downgrade(self), self.window());
        glib::spawn_future_local(async move {
            // Dismissed (or no portal): nothing to copy.
            let Ok(file) = dialog.open_future(window.as_ref()).await else {
                return;
            };
            if let Some(f) = f.upgrade() {
                f.ask_upload(&file);
            }
        });
    }

    fn ask_upload(self: &Rc<Self>, file: &gio::File) {
        let Some(host) = file.path() else {
            return self.toast("Only files on this computer can be uploaded");
        };
        let name = host
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text = format!("{}{name}", model::guest_home(self.admin.is_active()));
        let heading = format!("Upload {}", stallo::printable(&name, 64));
        let body = Some("A file with this name in the VM is replaced.");
        self.ask_path(
            &heading,
            body,
            &text,
            Some(name),
            "Upload",
            move |f, guest| f.start(|v, name, admin| v.upload(name, host.clone(), guest, admin)),
        );
    }

    fn ask_download(self: &Rc<Self>) {
        let text = model::guest_home(self.admin.is_active());
        self.ask_path(
            "Download a File",
            None,
            &text,
            None,
            "Download…",
            |f, guest| f.pick_target(guest),
        );
    }

    /// Starts a copy on this VM, unless one runs or the VM is busy.
    fn start(&self, copy: impl FnOnce(&Rc<Vms>, &str, bool)) {
        if let Some(v) = self.vms.upgrade().filter(|_| self.idle()) {
            copy(&v, &self.name, self.admin.is_active());
        }
    }

    /// Asks for a path in the VM, prefilled with `text` and checked as
    /// the daemon checks it. `upload` is the host file's name.
    fn ask_path(
        self: &Rc<Self>,
        heading: &str,
        body: Option<&str>,
        text: &str,
        upload: Option<String>,
        button: &str,
        then: impl Fn(&Rc<Self>, String) + 'static,
    ) {
        let entry = adw::EntryRow::builder()
            .title("Path in the VM")
            .text(text)
            .activates_default(true)
            .build();
        let list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .css_classes(["boxed-list"])
            .build();
        list.append(&entry);
        // Shown only while the path is refused, and read out with the entry.
        let hint = gtk::Label::builder()
            .wrap(true)
            .xalign(0.0)
            .visible(false)
            .css_classes(["caption", "error"])
            .build();
        entry
            .upcast_ref::<gtk::Widget>()
            .update_relation(&[gtk::accessible::Relation::DescribedBy(&[hint.upcast_ref()])]);
        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(6)
            .build();
        content.append(&list);
        content.append(&hint);
        let dialog = adw::AlertDialog::builder()
            .heading(heading)
            .heading_use_markup(false)
            .body(body.unwrap_or_default())
            .body_use_markup(false)
            .extra_child(&content)
            .build();
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("go", button);
        dialog.set_response_appearance("go", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("go"));
        dialog.set_close_response("cancel");
        dialog.set_response_enabled("go", model::guest_path(text, upload.as_deref()).is_ok());
        // Weak: the dialog owns the entry and so this handler.
        let (d, name) = (dialog.downgrade(), upload.clone());
        entry.connect_changed(move |e| {
            let checked = model::guest_path(&e.text(), name.as_deref());
            if let Some(d) = d.upgrade() {
                d.set_response_enabled("go", checked.is_ok());
            }
            match checked {
                Ok(_) => {
                    e.remove_css_class("error");
                    hint.set_visible(false);
                }
                Err(why) => {
                    e.add_css_class("error");
                    hint.set_label(why);
                    hint.set_visible(true);
                }
            }
        });
        let (f, typed) = (Rc::downgrade(self), entry.clone());
        dialog.connect_response(Some("go"), move |_, _| {
            if let (Some(f), Ok(path)) = (
                f.upgrade(),
                model::guest_path(&typed.text(), upload.as_deref()),
            ) {
                then(&f, path);
            }
        });
        dialog.set_focus(Some(&entry));
        entry.set_position(-1);
        dialog.present(Some(&self.root));
    }

    fn pick_target(self: &Rc<Self>, guest: String) {
        let dialog = gtk::FileDialog::builder()
            .title("Save File")
            .modal(true)
            .build();
        dialog.set_initial_name(model::file_name(&guest));
        let (f, window) = (Rc::downgrade(self), self.window());
        glib::spawn_future_local(async move {
            let Ok(file) = dialog.save_future(window.as_ref()).await else {
                return;
            };
            if let Some(f) = f.upgrade() {
                match file.path() {
                    Some(host) => f.start(|v, name, admin| v.download(name, guest, host, admin)),
                    None => f.toast("Only folders on this computer can be saved to"),
                }
            }
        });
    }
}

impl Vms {
    /// The open page shows `vm`'s copy as it is now.
    pub(super) fn show_copy(&self, vm: &str) {
        if let Some(d) = self.detail.borrow().as_ref().filter(|d| d.name == vm) {
            d.files.show_copy(self.copies.borrow().get(vm));
        }
    }

    /// Claims `vm` for copy `t`; false if a copy runs there already.
    fn claim(&self, vm: &str, t: &Transfer) -> bool {
        let claimed = self.copies.borrow_mut().start(vm, t.clone());
        self.show_copy(vm);
        claimed
    }

    fn upload(self: &Rc<Self>, vm: &str, host: PathBuf, guest: String, admin: bool) {
        let t = Transfer::new(true, &host.to_string_lossy());
        if !self.claim(vm, &t) {
            return;
        }
        let (v, ui, socket, vm) = (
            Rc::downgrade(self),
            self.ui.clone(),
            self.socket.clone(),
            vm.to_owned(),
        );
        glib::spawn_future_local(async move {
            let end = async {
                let path = host.clone();
                let (file, size) = io(client::blocking(move || open_upload(&path))).await?;
                let mut offset = 0;
                if !step(&v, &vm, |c| c.sized(&vm, size)) {
                    return Ok(false);
                }
                loop {
                    let (f, s, name, g, path) = (
                        file.clone(),
                        socket.clone(),
                        vm.clone(),
                        guest.clone(),
                        host.clone(),
                    );
                    let n = io(async move {
                        let chunk = client::blocking(move || {
                            read_chunk(&f).map_err(|e| host_error("read", &path, e))
                        })
                        .await?;
                        if let Some(r) = model::write_request(&name, &g, offset, &chunk, admin) {
                            client::file(&s, r).await?;
                        }
                        Ok(chunk.len())
                    })
                    .await?;
                    offset += n as u64;
                    let go_on = step(&v, &vm, |c| c.copied(&vm, n as u64));
                    if model::last_chunk(n) {
                        return Ok(true);
                    }
                    if !go_on {
                        return Ok(false);
                    }
                }
            }
            .await;
            finish(&v, &ui, &vm, &t, end);
        });
    }

    /// Into `<host>.part` first, renamed when complete, as `stallo cp`
    /// does: a failure never clobbers the chosen file.
    fn download(self: &Rc<Self>, vm: &str, guest: String, host: PathBuf, admin: bool) {
        let t = Transfer::new(false, &guest);
        if !self.claim(vm, &t) {
            return;
        }
        let (v, ui, socket, vm) = (
            Rc::downgrade(self),
            self.ui.clone(),
            self.socket.clone(),
            vm.to_owned(),
        );
        let part = part_path(&host);
        glib::spawn_future_local(async move {
            let p = part.clone();
            let end = match io(client::blocking(move || create_part(&p))).await {
                Err(e) => Err(e),
                Ok(file) => {
                    let file = Arc::new(file);
                    let end = async {
                        let mut offset = 0;
                        loop {
                            if !step(&v, &vm, |_| {}) {
                                return Ok(false);
                            }
                            let (f, s, name, g, p) = (
                                file.clone(),
                                socket.clone(),
                                vm.clone(),
                                guest.clone(),
                                part.clone(),
                            );
                            let (n, more) = io(async move {
                                let request = model::read_request(&name, &g, offset, admin);
                                let data = client::file(&s, request).await?;
                                let (bytes, more) =
                                    model::read_answer(data, offset).map_err(CallError::Failed)?;
                                let n = bytes.len() as u64;
                                client::blocking(move || {
                                    (&*f)
                                        .write_all(&bytes)
                                        .map_err(|e| host_error("write", &p, e))
                                })
                                .await?;
                                Ok((n, more))
                            })
                            .await?;
                            offset += n;
                            step(&v, &vm, |c| c.copied(&vm, n));
                            if !more {
                                let (f, p, h) = (file.clone(), part.clone(), host.clone());
                                io(client::blocking(move || finish_part(&f, &p, &h))).await?;
                                return Ok(true);
                            }
                        }
                    }
                    .await;
                    if end != Ok(true) {
                        let p = part.clone();
                        let _ = io(client::blocking(move || {
                            drop_part(&p);
                            Ok(())
                        }))
                        .await;
                    }
                    end
                }
            };
            finish(&v, &ui, &vm, &t, end);
        });
    }
}

/// Updates `vm`'s copy with `f` and shows it; false once it should stop:
/// cancelled, or the window shows another page.
fn step(v: &Weak<Vms>, vm: &str, f: impl FnOnce(&mut Copies)) -> bool {
    let Some(v) = v.upgrade() else {
        return false;
    };
    f(&mut v.copies.borrow_mut());
    v.show_copy(vm);
    !v.copies.borrow().stops(vm)
}

/// The copy is over: frees the VM for the next one; a toast says how.
fn finish(v: &Weak<Vms>, ui: &crate::Ui, vm: &str, t: &Transfer, end: Result<bool, CallError>) {
    if let Some(v) = v.upgrade() {
        v.copies.borrow_mut().finish(vm);
        // All of the page: a VM that stopped meanwhile shows its status.
        v.refresh_open();
    }
    match end {
        Ok(true) => ui.toast(&t.done_text(vm)),
        Ok(false) => ui.toast(&t.cancelled()),
        Err(e) => ui.fail(&t.failed(&e)),
    }
}

/// Runs `fut` on the I/O thread; a panic there is an error like any other.
async fn io<T: Send + 'static>(
    fut: impl Future<Output = Result<T, CallError>> + Send + 'static,
) -> Result<T, CallError> {
    client::spawn(fut)
        .await
        .unwrap_or_else(|e| Err(CallError::Failed(e.to_string())))
}

fn host_error(what: &str, path: &Path, e: io::Error) -> CallError {
    CallError::Failed(format!("cannot {what} {}: {e}", path.display()))
}

/// Opens a host file to upload, with its size. Regular files only, as
/// the open file says (no race with a path swapped meanwhile): a device
/// never ends. Non-blocking, so opening a FIFO returns at once; reads of
/// a regular file ignore the flag.
fn open_upload(path: &Path) -> Result<(Arc<File>, u64), CallError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(path)
        .map_err(|e| host_error("open", path, e))?;
    let meta = file.metadata().map_err(|e| host_error("open", path, e))?;
    if !meta.is_file() {
        return Err(CallError::Failed(
            "Only regular files can be uploaded.".to_owned(),
        ));
    }
    Ok((Arc::new(file), meta.len()))
}

/// The next chunk to send: at most [`FILE_WRITE_CHUNK`] bytes.
fn read_chunk(file: &File) -> io::Result<Vec<u8>> {
    let mut chunk = Vec::with_capacity(FILE_WRITE_CHUNK);
    file.take(FILE_WRITE_CHUNK as u64).read_to_end(&mut chunk)?;
    Ok(chunk)
}

fn part_path(target: &Path) -> PathBuf {
    let mut part = target.as_os_str().to_owned();
    part.push(".part");
    PathBuf::from(part)
}

/// A new `.part` file; one left over is never reused or removed.
fn create_part(part: &Path) -> Result<File, CallError> {
    match OpenOptions::new().write(true).create_new(true).open(part) {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(CallError::Failed(format!(
            "{} is left from an earlier download; delete it or save under another name.",
            part.file_name().unwrap_or_default().to_string_lossy()
        ))),
        Err(e) => Err(host_error("create", part, e)),
    }
}

/// On disk first, then under the chosen name.
fn finish_part(file: &File, part: &Path, target: &Path) -> Result<(), CallError> {
    file.sync_all().map_err(|e| host_error("write", part, e))?;
    std::fs::rename(part, target).map_err(|e| host_error("write", target, e))
}

/// Removes a `.part` this copy created, after a failure or a cancel.
fn drop_part(part: &Path) {
    let _ = std::fs::remove_file(part);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("notes.txt");
        let part = part_path(&target);
        assert_eq!(part, dir.path().join("notes.txt.part"));
        // Completed: on disk under the chosen name, no part left.
        let file = create_part(&part).unwrap();
        (&file).write_all(b"hello").unwrap();
        finish_part(&file, &part, &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
        assert!(!part.exists());
        // Failed or cancelled: the part goes, the chosen file stays.
        let file = create_part(&part).unwrap();
        (&file).write_all(b"half").unwrap();
        drop_part(&part);
        assert!(!part.exists());
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
        // A part from before is neither reused nor removed.
        std::fs::write(&part, b"old").unwrap();
        match create_part(&part) {
            Err(CallError::Failed(e)) => assert_eq!(
                e,
                "notes.txt.part is left from an earlier download; delete it or save under another name."
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(std::fs::read(&part).unwrap(), b"old");
        assert!(matches!(
            create_part(&dir.path().join("missing/x.part")),
            Err(CallError::Failed(e)) if e.starts_with("cannot create ")
        ));
    }

    #[test]
    fn upload_sources() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big");
        let len = FILE_WRITE_CHUNK + 10;
        std::fs::write(&path, vec![7u8; len]).unwrap();
        let (file, size) = open_upload(&path).unwrap();
        assert_eq!(size, len as u64);
        assert_eq!(read_chunk(&file).unwrap().len(), FILE_WRITE_CHUNK);
        assert_eq!(read_chunk(&file).unwrap().len(), 10);
        assert!(read_chunk(&file).unwrap().is_empty());
        // A FIFO with no writer: refused at once, not a hang in open().
        let fifo = dir.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        for not_regular in [dir.path(), Path::new("/dev/null"), &fifo] {
            assert_eq!(
                open_upload(not_regular).err(),
                Some(CallError::Failed(
                    "Only regular files can be uploaded.".to_owned()
                )),
                "{not_regular:?}"
            );
        }
        assert!(matches!(
            open_upload(&dir.path().join("missing")),
            Err(CallError::Failed(e)) if e.starts_with("cannot open ")
        ));
    }
}
