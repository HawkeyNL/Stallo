//! The Files tab: copies a file into a running VM or out of it with the
//! daemon's `file_write` and `file_read`, as `stallo cp` does. Host files
//! are read and written off the GTK thread a chunk at a time, so the tab
//! shows progress and can cancel between chunks.

use std::cell::{Cell, RefCell};
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::rc::{Rc, Weak};
use std::sync::Arc;

use adw::prelude::*;
use adw::{gdk, gio, glib, gtk};
use libadwaita as adw;
use stallo::api::{FILE_WRITE_CHUNK, VmInfo};

use super::Vms;
use crate::Ui;
use crate::client;
use crate::model::{self, CallError, Op, Transfer};

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
    /// The copy that runs: set it to cancel after the chunk in flight.
    running: RefCell<Option<Rc<Cell<bool>>>>,
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
            running: RefCell::default(),
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
        self.cancel.connect_clicked(move |b| {
            if let Some(f) = f.upgrade()
                && let Some(cancel) = f.running.borrow().as_ref()
            {
                cancel.set(true);
                b.set_sensitive(false);
                f.row.set_subtitle("Cancelling…");
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

    /// Shows `vm` as it is now; `blocked` as for the VM's buttons.
    pub fn update(&self, vm: &VmInfo, blocked: bool) {
        self.blocked.set(blocked);
        match model::files_status(vm) {
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
        self.sync();
    }

    fn idle(&self) -> bool {
        !self.blocked.get() && self.running.borrow().is_none()
    }

    fn sync(&self) {
        let idle = self.idle();
        self.upload.set_sensitive(idle);
        self.download.set_sensitive(idle);
        // A copy keeps the user it started with.
        self.admin.set_sensitive(self.running.borrow().is_none());
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
        self.ask_path(&heading, &text, Some(name), "Upload", move |f, guest| {
            f.upload(host.clone(), guest)
        });
    }

    fn ask_download(self: &Rc<Self>) {
        let text = model::guest_home(self.admin.is_active());
        self.ask_path("Download a File", &text, None, "Download…", |f, guest| {
            f.pick_target(guest)
        });
    }

    /// Asks for a path in the VM, prefilled with `text` and checked as
    /// the daemon checks it. `upload` is the host file's name.
    fn ask_path(
        self: &Rc<Self>,
        heading: &str,
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
                    Some(host) => f.download(guest, host),
                    None => f.toast("Only folders on this computer can be saved to"),
                }
            }
        });
    }

    /// Shows the copy and claims the tab for it; returns its cancel flag.
    fn begin(&self, t: &Transfer) -> Rc<Cell<bool>> {
        let cancel = Rc::new(Cell::new(false));
        *self.running.borrow_mut() = Some(cancel.clone());
        self.cancel.set_sensitive(true);
        self.bar.set_fraction(0.0);
        self.show(t);
        self.progress.set_visible(true);
        self.sync();
        cancel
    }

    fn show(&self, t: &Transfer) {
        self.row.set_title(&t.title());
        if !self.running.borrow().as_ref().is_some_and(|c| c.get()) {
            self.row.set_subtitle(&t.progress());
        }
        match t.fraction() {
            Some(f) => self.bar.set_fraction(f),
            None => self.bar.pulse(),
        }
    }

    /// The copy is over: a toast says how.
    fn end(&self, ui: &Ui, t: &Transfer, vm: &str, end: Result<bool, CallError>) {
        self.running.take();
        self.progress.set_visible(false);
        self.sync();
        match end {
            Ok(true) => ui.toast(&t.done_text(vm)),
            Ok(false) => ui.toast(&t.cancelled()),
            Err(e) => ui.fail(&t.failed(&e)),
        }
    }

    fn upload(self: &Rc<Self>, host: PathBuf, guest: String) {
        let Some(v) = self.vms.upgrade().filter(|_| self.idle()) else {
            return;
        };
        let (socket, vm, admin) = (v.socket.clone(), self.name.clone(), self.admin.is_active());
        // The toast comes even if the window shows another page by then.
        let ui = v.ui.clone();
        let mut t = Transfer::new(true, &host.to_string_lossy());
        let cancel = self.begin(&t);
        // Strong: a copy runs to its end even if another VM is opened.
        let f = self.clone();
        glib::spawn_future_local(async move {
            let end = async {
                let what = format!("open {}", host.display());
                let path = host.clone();
                let (file, size) = io(client::blocking(what, move || {
                    let file = File::open(&path)?;
                    let size = file.metadata()?.len();
                    Ok((Arc::new(file), size))
                }))
                .await?;
                t.total = Some(size);
                f.show(&t);
                loop {
                    if cancel.get() {
                        return Ok(false);
                    }
                    let (file, socket, vm, guest) =
                        (file.clone(), socket.clone(), vm.clone(), guest.clone());
                    let (what, offset) = (format!("read {}", host.display()), t.done);
                    let n = io(async move {
                        let chunk = client::blocking(what, move || {
                            let mut chunk = Vec::with_capacity(FILE_WRITE_CHUNK);
                            (&*file)
                                .take(FILE_WRITE_CHUNK as u64)
                                .read_to_end(&mut chunk)?;
                            Ok(chunk)
                        })
                        .await?;
                        if let Some(r) = model::write_request(&vm, &guest, offset, &chunk, admin) {
                            client::file(&socket, r).await?;
                        }
                        Ok(chunk.len())
                    })
                    .await?;
                    t.done += n as u64;
                    f.show(&t);
                    if model::last_chunk(n) {
                        return Ok(true);
                    }
                }
            }
            .await;
            f.end(&ui, &t, &vm, end);
        });
    }

    /// Into `<host>.part` first, renamed when complete, as `stallo cp`
    /// does: a failure never clobbers the chosen file.
    fn download(self: &Rc<Self>, guest: String, host: PathBuf) {
        let Some(v) = self.vms.upgrade().filter(|_| self.idle()) else {
            return;
        };
        let (socket, vm, admin) = (v.socket.clone(), self.name.clone(), self.admin.is_active());
        // The toast comes even if the window shows another page by then.
        let ui = v.ui.clone();
        let mut part = host.clone().into_os_string();
        part.push(".part");
        let part = PathBuf::from(part);
        let mut t = Transfer::new(false, &guest);
        let cancel = self.begin(&t);
        let f = self.clone();
        glib::spawn_future_local(async move {
            let p = part.clone();
            let created = io(client::blocking(
                format!("create {}", p.display()),
                move || {
                    let file = OpenOptions::new().write(true).create_new(true).open(&p)?;
                    Ok(Arc::new(file))
                },
            ))
            .await;
            let file = match created {
                Ok(file) => file,
                Err(e) => return f.end(&ui, &t, &vm, Err(e)),
            };
            let end = async {
                loop {
                    if cancel.get() {
                        return Ok(false);
                    }
                    let (file, socket, vm, guest) =
                        (file.clone(), socket.clone(), vm.clone(), guest.clone());
                    let (what, offset) = (format!("write {}", part.display()), t.done);
                    let (n, more) = io(async move {
                        let request = model::read_request(&vm, &guest, offset, admin);
                        let data = client::file(&socket, request).await?;
                        let (bytes, more) =
                            model::read_answer(data, offset).map_err(CallError::Failed)?;
                        let n = bytes.len();
                        client::blocking(what, move || (&*file).write_all(&bytes)).await?;
                        Ok((n, more))
                    })
                    .await?;
                    t.done += n as u64;
                    f.show(&t);
                    if !more {
                        let (p, h) = (part.clone(), host.clone());
                        let what = format!("write {}", host.display());
                        io(client::blocking(what, move || std::fs::rename(&p, &h))).await?;
                        return Ok(true);
                    }
                }
            }
            .await;
            if end != Ok(true) {
                let p = part.clone();
                let what = format!("remove {}", p.display());
                let _ = io(client::blocking(what, move || std::fs::remove_file(&p))).await;
            }
            f.end(&ui, &t, &vm, end);
        });
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
