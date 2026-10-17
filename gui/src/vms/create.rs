//! Creating a VM: New, pick an image, Create. Name, processors, memory,
//! disk and network come prefilled; changing them is optional. An image
//! that is not downloaded yet is pulled first. The window stays usable
//! meanwhile, with a spinner and text in the sidebar. "Use My Own ISO…"
//! imports an installer from a file first, with progress in the dialog.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::{Rc, Weak};
use std::time::Instant;

use adw::prelude::*;
use adw::{gio, glib, gtk};
use libadwaita as adw;
use stallo::api::ImageInfo;
use stallo::host::HostInfo;
use stallo::images::Os;
use tokio::sync::watch;

use super::{Vms, name_spinner};
use crate::client;
use crate::model::{self, Action, ImageChoice, NewVm, Op};

const LIVE_SCREEN_NOTE: &str =
    "See and use the VM's screen here. Anyone in the stallo group can too.";

/// The New VM action (`vms.new`), its header button, and the progress
/// strip in the sidebar.
pub(super) struct Create {
    action: gio::SimpleAction,
    pub button: gtk::Button,
    /// Shown while a VM is downloaded or created.
    pub strip: gtk::Box,
    spinner: adw::Spinner,
    label: gtk::Label,
    /// One create at a time.
    busy: Cell<bool>,
    online: Cell<bool>,
}

impl Create {
    pub fn new() -> Self {
        let button = gtk::Button::builder()
            .icon_name("list-add-symbolic")
            .tooltip_text("New Virtual Machine")
            .action_name("vms.new")
            .build();
        button.update_property(&[gtk::accessible::Property::Label("New Virtual Machine")]);
        let spinner = adw::Spinner::new();
        let label = gtk::Label::builder()
            .xalign(0.0)
            .wrap(true)
            .hexpand(true)
            .css_classes(["caption"])
            .build();
        let strip = gtk::Box::builder()
            .spacing(8)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(12)
            .margin_end(12)
            .visible(false)
            .build();
        strip.append(&spinner);
        strip.append(&label);
        Self {
            action: gio::SimpleAction::new("new", None),
            button,
            strip,
            spinner,
            label,
            busy: Cell::new(false),
            online: Cell::new(true),
        }
    }

    pub fn set_online(&self, on: bool) {
        self.online.set(on);
        self.sync();
    }

    fn sync(&self) {
        self.action
            .set_enabled(self.online.get() && !self.busy.get());
    }

    /// Shows `text` with the spinner while a create runs, or hides both.
    fn show(&self, text: Option<&str>) {
        self.busy.set(text.is_some());
        self.strip.set_visible(text.is_some());
        if let Some(text) = text {
            self.label.set_label(text);
            name_spinner(&self.spinner, text);
        }
        self.sync();
    }
}

/// Puts `vms.new` on the page.
pub(super) fn connect(vms: &Rc<Vms>) {
    let group = gio::SimpleActionGroup::new();
    group.add_action(&vms.create.action);
    vms.root.insert_action_group("vms", Some(&group));
    let v = Rc::downgrade(vms);
    vms.create.action.connect_activate(move |_, _| {
        if let Some(v) = v.upgrade() {
            ask(&v);
        }
    });
}

/// The New VM dialog: a spinner until the images and the host are known.
fn ask(vms: &Rc<Vms>) {
    let loading = adw::Spinner::builder()
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Center)
        .width_request(32)
        .height_request(32)
        .build();
    name_spinner(&loading, "Loading images");
    let stack = gtk::Stack::new();
    stack.add_named(&loading, Some("loading"));
    let cancel = gtk::Button::with_label("Cancel");
    let create = gtk::Button::builder()
        .label("Create")
        .sensitive(false)
        .css_classes(["suggested-action"])
        .build();
    let header = adw::HeaderBar::builder()
        .show_start_title_buttons(false)
        .show_end_title_buttons(false)
        .build();
    header.pack_start(&cancel);
    header.pack_end(&create);
    let view = adw::ToolbarView::builder().content(&stack).build();
    view.add_top_bar(&header);
    let dialog = adw::Dialog::builder()
        .title("New Virtual Machine")
        .content_width(480)
        .content_height(640)
        .child(&view)
        .default_widget(&create)
        .build();
    let d = dialog.downgrade();
    cancel.connect_clicked(move |_| {
        if let Some(d) = d.upgrade() {
            d.close();
        }
    });
    dialog.present(Some(&vms.root));

    let (v, d, socket) = (Rc::downgrade(vms), dialog.downgrade(), vms.socket.clone());
    glib::spawn_future_local(async move {
        let got = client::spawn(async move {
            tokio::try_join!(client::images(&socket), client::host(&socket))
        })
        .await;
        // Closed meanwhile: nothing to show.
        let (Some(v), Some(dialog)) = (v.upgrade(), d.upgrade()) else {
            return;
        };
        match got {
            Ok(Ok((images, host))) if !images.is_empty() => {
                Form::build(&v, &dialog, &stack, &create, &images, host);
            }
            Ok(Ok(_)) => {
                dialog.close();
                v.ui.toast("Stallo offers no images to create a VM from");
            }
            Ok(Err(e)) => {
                dialog.close();
                v.ui.fail(&model::failure("Could not list the images".to_owned(), &e));
            }
            Err(_) => {
                dialog.close();
            }
        }
    });
}

/// The import that runs. Ends it when dropped: the stream closes, and the
/// daemon drops what it got.
struct Importing {
    /// Tells this import's handlers from an earlier one's.
    generation: u64,
    task: tokio::task::AbortHandle,
}

impl Drop for Importing {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The dialog's controls. Its handlers hold it weakly; the dialog holds
/// it until it closes.
struct Form {
    vms: Weak<Vms>,
    dialog: glib::WeakRef<adw::Dialog>,
    socket: PathBuf,
    /// One per image, in step with `checks`; an import adds one.
    images: RefCell<Vec<ImageChoice>>,
    /// One per image, in a radio group.
    checks: RefCell<Vec<gtk::CheckButton>>,
    installer_group: adw::PreferencesGroup,
    /// "Use My Own ISO…", after the installers.
    own_iso: adw::ActionRow,
    /// An import's progress, or why it failed.
    import_row: adw::ActionRow,
    import_bar: gtk::ProgressBar,
    import_stop: gtk::Button,
    /// The import that runs, if any: one at a time.
    importing: RefCell<Option<Importing>>,
    /// Imports started so far.
    generations: Cell<u64>,
    /// A chosen file is looked at, or its system asked, before its import.
    checking: Cell<bool>,
    name: adw::EntryRow,
    /// Shown only while the name is refused.
    hint: gtk::Label,
    /// Says why no VM fits, if so.
    advanced_group: adw::PreferencesGroup,
    advanced: adw::ExpanderRow,
    vcpus: adw::SpinRow,
    memory: adw::SpinRow,
    disk: adw::SpinRow,
    internet: adw::SwitchRow,
    live_screen: adw::SwitchRow,
    create: gtk::Button,
    host: HostInfo,
    /// Names of the VMs there are.
    taken: Vec<String>,
    production: bool,
    /// The name last suggested: it follows the image until edited.
    suggested: RefCell<String>,
    /// Processors, memory and disk as last chosen, before any cap: a
    /// lower cap for one image is undone on switching back.
    wanted: [Cell<f64>; 3],
    /// Internet Access as last chosen: kept while it is blocked.
    internet_wanted: Cell<bool>,
    /// The values are being fitted to the caps, not chosen.
    fitting: Cell<bool>,
    /// The selected image's defaults: `wanted` starts from them.
    defaults: Cell<(u32, u64, u64)>,
}

/// An image's row, with its radio button in the group of `first`.
fn image_row(
    image: &ImageChoice,
    first: Option<&gtk::CheckButton>,
    active: bool,
) -> (adw::ActionRow, gtk::CheckButton) {
    let check = gtk::CheckButton::builder()
        .active(active)
        .valign(gtk::Align::Center)
        .build();
    check.set_group(first);
    let row = adw::ActionRow::builder()
        .title(&image.title)
        .subtitle(&image.subtitle)
        .use_markup(false)
        .activatable_widget(&check)
        .build();
    row.add_prefix(&check);
    // Through `Widget`: the binding does not mark rows as `Accessible`.
    let label = row.upcast_ref::<gtk::Widget>().upcast_ref();
    check.update_relation(&[gtk::accessible::Relation::LabelledBy(&[label])]);
    (row, check)
}

impl Form {
    fn build(
        vms: &Rc<Vms>,
        dialog: &adw::Dialog,
        stack: &gtk::Stack,
        create: &gtk::Button,
        images: &[ImageInfo],
        host: HostInfo,
    ) {
        let images = model::image_choices(images);
        let selected = model::default_image(&images);
        let taken: Vec<String> = vms.vms.borrow().iter().map(|v| v.name.clone()).collect();

        let image_group = adw::PreferencesGroup::builder()
            .title("Operating System")
            .build();
        // Fixed text only: descriptions are markup.
        let installer_group = adw::PreferencesGroup::builder()
            .title("Installers")
            .description(model::INSTALLER_NOTE)
            .build();
        let mut checks: Vec<gtk::CheckButton> = Vec::new();
        for (i, image) in images.iter().enumerate() {
            let (row, check) = image_row(image, checks.first(), i == selected);
            if image.installer {
                installer_group.add(&row);
            } else {
                image_group.add(&row);
            }
            checks.push(check);
        }
        let own_iso = adw::ActionRow::builder()
            .title("Use My Own ISO…")
            .subtitle("Import an installer from this computer")
            .use_markup(false)
            .activatable(true)
            .build();
        own_iso.add_prefix(&gtk::Image::from_icon_name("folder-open-symbolic"));
        let import_bar = gtk::ProgressBar::builder()
            .valign(gtk::Align::Center)
            .width_request(96)
            .build();
        import_bar.update_property(&[gtk::accessible::Property::Label("Import progress")]);
        let import_stop = gtk::Button::builder()
            .label("Stop Import")
            .valign(gtk::Align::Center)
            .build();
        let import_row = adw::ActionRow::builder()
            .use_markup(false)
            .visible(false)
            .build();
        import_row.add_suffix(&import_bar);
        import_row.add_suffix(&import_stop);
        installer_group.add(&own_iso);
        installer_group.add(&import_row);

        let suggested = model::suggest_name_for(&images[selected], &taken);
        let name = adw::EntryRow::builder()
            .title("Name")
            .text(&suggested)
            .activates_default(true)
            .build();
        let hint = gtk::Label::builder()
            .wrap(true)
            .xalign(0.0)
            .margin_top(6)
            .visible(false)
            .css_classes(["caption", "error"])
            .build();
        name.upcast_ref::<gtk::Widget>()
            .update_relation(&[gtk::accessible::Relation::DescribedBy(&[hint.upcast_ref()])]);
        let name_group = adw::PreferencesGroup::new();
        name_group.add(&name);
        name_group.add(&hint);
        // Its own group: the name's hint stays right under the name.
        let live_screen = adw::SwitchRow::builder()
            .title("Live Screen")
            .subtitle(LIVE_SCREEN_NOTE)
            .use_markup(false)
            .active(true)
            .build();
        let internet = adw::SwitchRow::builder()
            .title("Internet Access")
            .use_markup(false)
            .build();
        let screen_group = adw::PreferencesGroup::new();
        screen_group.add(&live_screen);
        screen_group.add(&internet);

        let spin = |title: &str, value: u64| {
            let adjustment = gtk::Adjustment::new(value as f64, 1.0, value as f64, 1.0, 4.0, 0.0);
            adw::SpinRow::builder()
                .title(title)
                .use_markup(false)
                .adjustment(&adjustment)
                .numeric(true)
                .build()
        };
        let defaults = model::new_defaults(&images[selected]);
        let (v0, m0, d0) = defaults;
        let vcpus = spin("Processors", v0.into());
        let memory = spin("Memory (GiB)", m0);
        let disk = spin("Disk Size (GiB)", d0);
        let advanced = adw::ExpanderRow::builder()
            .title("Advanced")
            .use_markup(false)
            .build();
        for row in [&vcpus, &memory, &disk] {
            advanced.add_row(row);
        }
        let advanced_group = adw::PreferencesGroup::new();
        advanced_group.add(&advanced);

        let page = adw::PreferencesPage::new();
        page.add(&image_group);
        page.add(&installer_group);
        page.add(&name_group);
        page.add(&screen_group);
        page.add(&advanced_group);
        stack.add_named(&page, Some("form"));
        stack.set_visible_child_name("form");

        let form = Rc::new(Self {
            vms: Rc::downgrade(vms),
            dialog: dialog.downgrade(),
            socket: vms.socket.clone(),
            production: model::production(&vms.socket),
            images: RefCell::new(images),
            checks: RefCell::new(checks),
            installer_group,
            own_iso,
            import_row,
            import_bar,
            import_stop,
            importing: RefCell::new(None),
            generations: Cell::new(0),
            checking: Cell::new(false),
            name,
            hint,
            advanced_group,
            advanced,
            vcpus,
            memory,
            disk,
            internet,
            live_screen,
            create: create.clone(),
            host,
            taken,
            suggested: RefCell::new(suggested),
            wanted: [
                Cell::new(v0.into()),
                Cell::new(m0 as f64),
                Cell::new(d0 as f64),
            ],
            internet_wanted: Cell::new(false),
            fitting: Cell::new(false),
            defaults: Cell::new(defaults),
        });
        // Fit the values to the first image before any handler runs.
        form.update();
        for check in form.checks.borrow().iter() {
            form.connect_check(check);
        }
        let f = Rc::downgrade(&form);
        form.own_iso.connect_activated(move |_| {
            if let Some(f) = f.upgrade() {
                f.pick_iso();
            }
        });
        let f = Rc::downgrade(&form);
        form.import_stop.connect_clicked(move |_| {
            if let Some(f) = f.upgrade() {
                f.cancel_import();
            }
        });
        let f = Rc::downgrade(&form);
        form.name.connect_changed(move |_| {
            if let Some(f) = f.upgrade() {
                f.update();
            }
        });
        for (i, spin) in [&form.vcpus, &form.memory, &form.disk]
            .into_iter()
            .enumerate()
        {
            let f = Rc::downgrade(&form);
            spin.connect_value_notify(move |row| {
                if let Some(f) = f.upgrade() {
                    if !f.fitting.get() {
                        f.wanted[i].set(row.value());
                    }
                    f.update();
                }
            });
        }
        let f = Rc::downgrade(&form);
        form.internet.connect_active_notify(move |row| {
            if let Some(f) = f.upgrade() {
                if !f.fitting.get() {
                    f.internet_wanted.set(row.is_active());
                }
                f.update();
            }
        });
        let f = Rc::downgrade(&form);
        form.create.connect_clicked(move |_| {
            if let Some(f) = f.upgrade() {
                f.submit();
            }
        });
        // The image list comes first: that is the one choice to make.
        dialog.set_focus(Some(&form.checks.borrow()[selected]));
        // While an import runs, closing asks first (`can_close` is off).
        let f = Rc::downgrade(&form);
        dialog.connect_close_attempt(move |_| {
            if let Some(f) = f.upgrade() {
                f.ask_stop();
            }
        });
        // Closing the dialog drops the form, and so ends an import.
        let keep = Cell::new(Some(form));
        dialog.connect_closed(move |_| drop(keep.take()));
    }

    fn connect_check(self: &Rc<Self>, check: &gtk::CheckButton) {
        let f = Rc::downgrade(self);
        check.connect_toggled(move |c| {
            if let Some(f) = f.upgrade().filter(|_| c.is_active()) {
                f.image_changed();
            }
        });
    }

    fn selected(&self) -> usize {
        self.checks
            .borrow()
            .iter()
            .position(|c| c.is_active())
            .unwrap_or(0)
    }

    fn image(&self) -> ImageChoice {
        self.images.borrow()[self.selected()].clone()
    }

    fn image_changed(&self) {
        let image = self.image();
        // Images with other defaults (an installer, Windows, a cloud
        // image): a switch between them starts over from the new one's.
        let (v, m, d) = model::new_defaults(&image);
        if self.defaults.replace((v, m, d)) != (v, m, d) {
            for (wanted, value) in self.wanted.iter().zip([f64::from(v), m as f64, d as f64]) {
                wanted.set(value);
            }
            // Off by default: Windows installs offline, where a local
            // account is easy.
            self.internet_wanted.set(false);
        }
        let new = model::suggest_name_for(&image, &self.taken);
        let old = self.suggested.replace(new.clone());
        if self.name.text() == old {
            self.name.set_text(&new);
        }
        self.update();
    }

    /// Fits the limits, the network and the Create button to the choices.
    fn update(&self) {
        let image = self.image();
        let min = model::minimums(&image);
        let limits = model::limits(&self.host, image.download_bytes, image.download_reserve);
        let notes = limits.notes();
        for ((((row, upper), lower), note), wanted) in [
            (&self.vcpus, u64::from(limits.vcpus)),
            (&self.memory, limits.memory_gib),
            (&self.disk, limits.disk_gib),
        ]
        .into_iter()
        .zip([u64::from(min.0), min.1, min.2])
        .zip(&notes)
        .zip(&self.wanted)
        {
            let a = row.adjustment();
            let lower = lower as f64;
            let upper = (upper as f64).max(lower);
            let value = wanted.get().clamp(lower, upper);
            if a.lower() != lower || a.upper() != upper || a.value() != value {
                self.fitting.set(true);
                a.configure(value, lower, upper, 1.0, 4.0, 0.0);
                self.fitting.set(false);
            }
            if row.subtitle().as_deref() != Some(note.as_str()) {
                row.set_subtitle(note);
            }
        }
        // Fixed text only: descriptions are markup.
        self.installer_group.set_description(Some(if image.windows {
            model::WINDOWS_NOTE
        } else {
            model::INSTALLER_NOTE
        }));
        let lock = model::live_screen_lock(&image);
        if lock.is_some() && !self.live_screen.is_active() {
            self.live_screen.set_active(true);
        }
        self.live_screen.set_sensitive(lock.is_none());
        self.live_screen
            .set_subtitle(lock.unwrap_or(LIVE_SCREEN_NOTE));
        let block = model::internet_block(&image, self.production);
        let on = block.is_none() && self.internet_wanted.get();
        if self.internet.is_active() != on {
            self.fitting.set(true);
            self.internet.set_active(on);
            self.fitting.set(false);
        }
        self.internet.set_sensitive(block.is_none());
        self.internet.set_subtitle(
            block.unwrap_or("Reaches the internet, not this computer or your local network."),
        );
        let (vcpus, memory, disk) = self.values();
        self.advanced
            .set_subtitle(&model::advanced_summary(vcpus, memory, disk));
        let full = limits.block(min);
        self.advanced_group
            .set_description(full.or(image.windows.then_some(model::WINDOWS_MINIMUMS)));
        let text = self.name.text();
        let name = model::vm_name(&text, &self.taken);
        match &name {
            // Nothing typed yet is no mistake; Create just waits.
            Err(why) if !text.is_empty() => {
                self.name.add_css_class("error");
                self.hint.set_label(why);
                self.hint.set_visible(true);
            }
            _ => {
                self.name.remove_css_class("error");
                self.hint.set_visible(false);
            }
        }
        // Creating would close the dialog, and so end the import.
        let importing = self.importing.borrow().is_some();
        self.own_iso
            .set_sensitive(!importing && !self.checking.get());
        if let Some(d) = self.dialog.upgrade() {
            d.set_can_close(!importing);
        }
        self.create
            .set_sensitive(name.is_ok() && full.is_none() && !importing);
    }

    fn values(&self) -> (u32, u64, u64) {
        (
            self.vcpus.value() as u32,
            self.memory.value() as u64,
            self.disk.value() as u64,
        )
    }

    fn submit(&self) {
        let image = self.image();
        if self.importing.borrow().is_some() {
            return;
        }
        let Ok(name) = model::vm_name(&self.name.text(), &self.taken) else {
            return;
        };
        if model::limits(&self.host, image.download_bytes, image.download_reserve)
            .block(model::minimums(&image))
            .is_some()
        {
            return;
        }
        let (vcpus, memory_gib, disk_gib) = self.values();
        let plan = NewVm {
            name,
            image: image.id.clone(),
            image_title: image.title.clone(),
            cached: image.cached,
            vcpus,
            memory_gib,
            disk_gib,
            internet: self.internet.is_active(),
            live_screen: self.live_screen.is_active(),
            installer: image.installer,
        };
        if let Some(d) = self.dialog.upgrade() {
            d.close();
        }
        if let Some(v) = self.vms.upgrade() {
            v.create_vm(plan);
        }
    }

    /// "Use My Own ISO…": a file chooser (the portal's, if there is one)
    /// for `*.iso`.
    fn pick_iso(self: &Rc<Self>) {
        let filter = gtk::FileFilter::new();
        filter.set_name(Some("ISO Images"));
        filter.add_suffix("iso");
        let filters = gio::ListStore::new::<gtk::FileFilter>();
        filters.append(&filter);
        let chooser = gtk::FileDialog::builder()
            .title("Choose an Installer ISO")
            .modal(true)
            .filters(&filters)
            .default_filter(&filter)
            .build();
        let (f, window) = (
            Rc::downgrade(self),
            self.own_iso.root().and_downcast::<gtk::Window>(),
        );
        glib::spawn_future_local(async move {
            // Dismissed (or no portal): nothing to import.
            let Ok(file) = chooser.open_future(window.as_ref()).await else {
                return;
            };
            if let Some(f) = f.upgrade() {
                f.ask_os(&file);
            }
        });
    }

    /// Imports the ISO as the system it installs: guessed from its name
    /// and volume label, or asked when unsure.
    fn ask_os(self: &Rc<Self>, file: &gio::File) {
        let Some(path) = file.path() else {
            return self.import_failed("", "Only files on this computer can be imported.");
        };
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let label = stallo::printable(&file_name, 64);
        let id = stallo::images::local_id(&path.file_stem().unwrap_or_default().to_string_lossy());
        if self.images.borrow().iter().any(|i| i.id == id) {
            return self.import_failed(&label, model::IMPORTED_ALREADY);
        }
        self.checking.set(true);
        self.import_row.set_title(&format!("Checking {label}…"));
        self.import_row.set_subtitle("");
        self.import_bar.set_visible(false);
        self.import_stop.set_visible(false);
        self.import_row.set_visible(true);
        self.update();
        let f = Rc::downgrade(self);
        glib::spawn_future_local(async move {
            let p = path.clone();
            let volume = client::spawn(client::iso_label(p))
                .await
                .unwrap_or_default();
            let Some(f) = f.upgrade() else {
                return;
            };
            match model::guess_os(&file_name, &volume) {
                Some(os) => f.import(path, label, id, os),
                None => f.ask_unsure(path, label, id),
            }
        });
    }

    /// Asks Linux or Windows, then imports.
    fn ask_unsure(self: &Rc<Self>, path: PathBuf, label: String, id: String) {
        let systems = gtk::StringList::new(&["Linux", "Windows"]);
        let os = adw::ComboRow::builder()
            .title("Operating System")
            .use_markup(false)
            .model(&systems)
            .build();
        let list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .css_classes(["boxed-list"])
            .build();
        list.append(&os);
        let alert = adw::AlertDialog::builder()
            .heading(format!("Import {label}"))
            .heading_use_markup(false)
            .body("Which system does it install?")
            .body_use_markup(false)
            .extra_child(&list)
            .build();
        alert.add_response("cancel", "Cancel");
        alert.add_response("import", "Import");
        alert.set_response_appearance("import", adw::ResponseAppearance::Suggested);
        alert.set_default_response(Some("import"));
        alert.set_close_response("cancel");
        let f = Rc::downgrade(self);
        alert.connect_response(None, move |_, response| {
            let Some(f) = f.upgrade() else {
                return;
            };
            if response != "import" {
                f.checking.set(false);
                f.import_row.set_visible(false);
                return f.update();
            }
            let os = if os.selected() == 1 {
                Os::Windows
            } else {
                Os::Linux
            };
            f.import(path.clone(), label.clone(), id.clone(), os);
        });
        alert.present(Some(&self.own_iso));
    }

    /// Whether `generation` is the import that runs now.
    fn current(&self, generation: u64) -> bool {
        self.importing
            .borrow()
            .as_ref()
            .is_some_and(|i| i.generation == generation)
    }

    /// Streams the ISO to the daemon on the I/O thread, with progress and
    /// Stop Import in the import row. When done, the new image is selected.
    fn import(self: &Rc<Self>, path: PathBuf, label: String, id: String, os: Os) {
        if self.importing.borrow().is_some() {
            return;
        }
        self.checking.set(false);
        let (sent, mut progress) = watch::channel((0, 0));
        let task = client::spawn(client::import(
            self.socket.clone(),
            path.clone(),
            id.clone(),
            os,
            sent,
        ));
        let generation = self.generations.get() + 1;
        self.generations.set(generation);
        self.importing.replace(Some(Importing {
            generation,
            task: task.abort_handle(),
        }));
        self.import_row.set_title(&model::importing(&label, os));
        self.import_row.set_subtitle("Starting…");
        self.import_bar.set_fraction(0.0);
        self.import_bar.set_visible(true);
        self.import_stop.set_visible(true);
        self.import_row.set_visible(true);
        self.update();

        let f = Rc::downgrade(self);
        glib::spawn_future_local(async move {
            // Ends when the import does: its sender is gone.
            while progress.changed().await.is_ok() {
                let (done, total) = *progress.borrow_and_update();
                let Some(f) = f.upgrade().filter(|f| f.current(generation)) else {
                    return;
                };
                let (share, text) = model::import_progress(done, total);
                f.import_bar.set_fraction(share);
                f.import_row.set_subtitle(&text);
            }
        });
        let f = Rc::downgrade(self);
        glib::spawn_future_local(async move {
            let got = task.await;
            // Closed meanwhile: nothing to show.
            let Some(f) = f.upgrade() else {
                return;
            };
            let current = f.current(generation);
            if current {
                drop(f.importing.take());
            }
            let stem = path.file_stem().unwrap_or_default().to_string_lossy();
            let info = |data: serde_json::Value| ImageInfo {
                id: id.clone(),
                name: stallo::images::clean_name(&stem),
                cached: true,
                kind: Some(stallo::images::Kind::Iso),
                os: Some(os),
                trust: None,
                size_bytes: data["size"].as_u64(),
                sig_date: None,
                notes: vec![],
            };
            match got {
                Ok(Ok(data)) => {
                    if current {
                        f.import_row.set_visible(false);
                    }
                    // Stopped too late: the daemon has it all the same, so
                    // it is listed, but not chosen.
                    f.add_image(model::image_choices(&[info(data)]).remove(0), current);
                }
                // Stopped (or a newer import runs): its row says so.
                _ if !current => {}
                Ok(Err(e)) => f.import_failed(&label, &model::import_error(&e)),
                Err(_) => f.import_failed(&label, model::IMPORT_FAILED),
            }
            f.update();
        });
    }

    fn cancel_import(&self) {
        drop(self.importing.take());
        self.import_row.set_visible(false);
        self.update();
    }

    /// Closing while an import runs: stop it, or keep the dialog.
    fn ask_stop(self: &Rc<Self>) {
        if self.importing.borrow().is_none() {
            return;
        }
        let alert = adw::AlertDialog::builder()
            .heading("Stop Importing?")
            .body("The ISO is not imported yet. Stopping drops what was copied so far.")
            .body_use_markup(false)
            .build();
        alert.add_response("keep", "Keep Importing");
        alert.add_response("stop", "Stop Import");
        alert.set_response_appearance("stop", adw::ResponseAppearance::Destructive);
        alert.set_default_response(Some("keep"));
        alert.set_close_response("keep");
        let f = Rc::downgrade(self);
        alert.connect_response(Some("stop"), move |_, _| {
            if let Some(f) = f.upgrade() {
                f.cancel_import();
                if let Some(d) = f.dialog.upgrade() {
                    d.close();
                }
            }
        });
        alert.present(Some(&self.own_iso));
    }

    /// Shows why the import of `label` failed, in the import row.
    fn import_failed(&self, label: &str, why: &str) {
        self.import_row.set_title(&if label.is_empty() {
            "Could not import the ISO".to_owned()
        } else {
            format!("Could not import {label}")
        });
        self.import_row.set_subtitle(why);
        self.import_bar.set_visible(false);
        self.import_stop.set_visible(false);
        self.import_row.set_visible(true);
    }

    /// Lists an imported image with the installers, unless it is there,
    /// and selects it if `select`.
    fn add_image(self: &Rc<Self>, image: ImageChoice, select: bool) {
        if self.images.borrow().iter().any(|i| i.id == image.id) {
            return;
        }
        let (row, check) = image_row(&image, self.checks.borrow().first(), false);
        // After the other installers, before "Use My Own ISO…".
        self.installer_group.remove(&self.own_iso);
        self.installer_group.remove(&self.import_row);
        self.installer_group.add(&row);
        self.installer_group.add(&self.own_iso);
        self.installer_group.add(&self.import_row);
        self.images.borrow_mut().push(image);
        self.checks.borrow_mut().push(check.clone());
        self.connect_check(&check);
        if select {
            check.set_active(true);
            check.grab_focus();
        }
    }
}

impl Vms {
    /// The VM open in the content pane, if any.
    fn open_name(&self) -> Option<String> {
        self.detail.borrow().as_ref().map(|d| d.name.clone())
    }

    /// Creates and starts the VM (the daemon downloads its image first if
    /// needed), then shows it, unless the user moved on meanwhile.
    fn create_vm(self: &Rc<Self>, plan: NewVm) {
        if self.create.busy.get() {
            return;
        }
        self.create.show(Some(&plan.progress()));
        // Its row says it starts, and its buttons stay off until done.
        let claimed = self
            .pending
            .borrow_mut()
            .start(&plan.name, &Action::Life(Op::Start));
        self.refresh_rows();
        let before = self.open_name();
        // Weak: a download may take longer than the page stays.
        let (v, ui, socket) = (Rc::downgrade(self), self.ui.clone(), self.socket.clone());
        glib::spawn_future_local(async move {
            let (s, new) = (socket.clone(), plan.request());
            let got = client::spawn(async move { client::create(&s, new).await }).await;
            if let Some(v) = v.upgrade() {
                v.create.show(None);
                if claimed {
                    v.pending.borrow_mut().finish(&plan.name, Instant::now());
                }
                v.list_poll.borrow_mut().soon();
            }
            match got {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return ui.fail(&plan.failed(&e)),
                Err(_) => return,
            }
            // Now, not at the next poll: the new VM is what to show.
            let sent = Instant::now();
            let list =
                client::spawn(async move { client::list(&socket, client::READ_TIMEOUT).await })
                    .await;
            let (Some(v), Ok(Ok(list))) = (v.upgrade(), list) else {
                return ui.toast(&plan.done());
            };
            v.pending.borrow_mut().listed(sent);
            v.show(list);
            if v.open_name() == before {
                v.select_new(&plan.name);
                return ui.toast(&plan.done());
            }
            // The user looks at another VM: do not pull the view away.
            let toast = adw::Toast::builder()
                .title(plan.done())
                .use_markup(false)
                .button_label("Open")
                .build();
            let (w, name) = (Rc::downgrade(&v), plan.name.clone());
            toast.connect_button_clicked(move |_| {
                if let Some(v) = w.upgrade() {
                    v.select_new(&name);
                }
            });
            ui.toasts.add_toast(toast);
        });
    }
    /// Selects VM `name` and opens it on its first tab.
    fn select_new(self: &Rc<Self>, name: &str) {
        let row = self
            .rows
            .borrow()
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.row.clone());
        let Some(row) = row else {
            return;
        };
        self.list.select_row(Some(&row));
        self.open(row.index(), true);
        let detail = self.detail.borrow().clone();
        if let (Some(d), Some(vm)) = (detail, self.vm(name)) {
            let tab = model::first_tab(&vm);
            if d.tabs.child_by_name(tab).is_some() {
                d.tabs.set_visible_child_name(tab);
            }
        }
    }
}
