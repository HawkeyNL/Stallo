//! Creating a VM: New, pick an image, Create. Name, processors, memory,
//! disk and network come prefilled; changing them is optional. An image
//! that is not downloaded yet is pulled first. The window stays usable
//! meanwhile, with a spinner and text in the sidebar.

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};
use std::time::Instant;

use adw::prelude::*;
use adw::{gio, glib, gtk};
use libadwaita as adw;
use stallo::api::ImageInfo;
use stallo::host::HostInfo;

use super::{Vms, name_spinner};
use crate::client;
use crate::model::{self, Action, ImageChoice, NewVm, Op};

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
    let stack = gtk::Stack::new();
    stack.add_named(
        &adw::Spinner::builder()
            .halign(gtk::Align::Center)
            .valign(gtk::Align::Center)
            .width_request(32)
            .height_request(32)
            .build(),
        Some("loading"),
    );
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

/// The dialog's controls. Its handlers hold it weakly; the dialog holds
/// it until it closes.
struct Form {
    vms: Weak<Vms>,
    dialog: glib::WeakRef<adw::Dialog>,
    images: Vec<ImageChoice>,
    /// One per image, in a radio group.
    checks: Vec<gtk::CheckButton>,
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
    create: gtk::Button,
    host: HostInfo,
    /// Names of the VMs there are.
    taken: Vec<String>,
    production: bool,
    /// The name last suggested: it follows the image until edited.
    suggested: RefCell<String>,
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
        let mut checks: Vec<gtk::CheckButton> = Vec::new();
        for (i, image) in images.iter().enumerate() {
            let check = gtk::CheckButton::builder()
                .active(i == selected)
                .valign(gtk::Align::Center)
                .build();
            check.set_group(checks.first());
            let row = adw::ActionRow::builder()
                .title(&image.title)
                .subtitle(&image.subtitle)
                .use_markup(false)
                .activatable_widget(&check)
                .build();
            row.add_prefix(&check);
            image_group.add(&row);
            checks.push(check);
        }

        let suggested = model::suggest_vm_name(&images[selected].id, &taken);
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

        let spin = |title: &str, value: u64, lower: u64| {
            let adjustment = gtk::Adjustment::new(
                value as f64,
                lower as f64,
                value.max(lower) as f64,
                1.0,
                4.0,
                0.0,
            );
            adw::SpinRow::builder()
                .title(title)
                .use_markup(false)
                .adjustment(&adjustment)
                .numeric(true)
                .build()
        };
        let vcpus = spin("Processors", model::NEW_VCPUS.into(), 1);
        let memory = spin("Memory (GiB)", model::NEW_MEMORY_GIB, 1);
        let disk = spin("Disk Size (GiB)", model::NEW_DISK_GIB, model::MIN_DISK_GIB);
        let internet = adw::SwitchRow::builder()
            .title("Internet Access")
            .use_markup(false)
            .build();
        let advanced = adw::ExpanderRow::builder()
            .title("Advanced")
            .use_markup(false)
            .build();
        for row in [&vcpus, &memory, &disk] {
            advanced.add_row(row);
        }
        advanced.add_row(&internet);
        let advanced_group = adw::PreferencesGroup::new();
        advanced_group.add(&advanced);

        let page = adw::PreferencesPage::new();
        page.add(&image_group);
        page.add(&name_group);
        page.add(&advanced_group);
        stack.add_named(&page, Some("form"));
        stack.set_visible_child_name("form");

        let form = Rc::new(Self {
            vms: Rc::downgrade(vms),
            dialog: dialog.downgrade(),
            production: model::production(&vms.socket),
            images,
            checks,
            name,
            hint,
            advanced_group,
            advanced,
            vcpus,
            memory,
            disk,
            internet,
            create: create.clone(),
            host,
            taken,
            suggested: RefCell::new(suggested),
        });
        // Fit the values to the first image before any handler runs.
        form.update();
        for check in &form.checks {
            let f = Rc::downgrade(&form);
            check.connect_toggled(move |c| {
                if let Some(f) = f.upgrade().filter(|_| c.is_active()) {
                    f.image_changed();
                }
            });
        }
        let f = Rc::downgrade(&form);
        form.name.connect_changed(move |_| {
            if let Some(f) = f.upgrade() {
                f.update();
            }
        });
        for spin in [&form.vcpus, &form.memory, &form.disk] {
            let f = Rc::downgrade(&form);
            spin.connect_value_notify(move |_| {
                if let Some(f) = f.upgrade() {
                    f.update();
                }
            });
        }
        let f = Rc::downgrade(&form);
        form.internet.connect_active_notify(move |_| {
            if let Some(f) = f.upgrade() {
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
        dialog.set_focus(Some(&form.checks[selected]));
        let keep = Cell::new(Some(form));
        dialog.connect_closed(move |_| drop(keep.take()));
    }

    fn selected(&self) -> usize {
        self.checks.iter().position(|c| c.is_active()).unwrap_or(0)
    }

    fn image_changed(&self) {
        let new = model::suggest_vm_name(&self.images[self.selected()].id, &self.taken);
        let old = self.suggested.replace(new.clone());
        if self.name.text() == old {
            self.name.set_text(&new);
        }
        self.update();
    }

    /// Fits the limits, the network and the Create button to the choices.
    fn update(&self) {
        let image = &self.images[self.selected()];
        let limits = model::limits(&self.host, image.download_bytes);
        let notes = limits.notes();
        for ((row, upper), note) in [
            (&self.vcpus, u64::from(limits.vcpus)),
            (&self.memory, limits.memory_gib),
            (&self.disk, limits.disk_gib),
        ]
        .into_iter()
        .zip(&notes)
        {
            let a = row.adjustment();
            let upper = (upper as f64).max(a.lower());
            if a.upper() != upper {
                a.configure(a.value().min(upper), a.lower(), upper, 1.0, 4.0, 0.0);
            }
            if row.subtitle().as_deref() != Some(note.as_str()) {
                row.set_subtitle(note);
            }
        }
        let block = model::internet_block(image, self.production);
        if block.is_some() && self.internet.is_active() {
            self.internet.set_active(false);
        }
        self.internet.set_sensitive(block.is_none());
        self.internet.set_subtitle(
            block.unwrap_or("Reaches the internet, not this computer or your local network."),
        );
        let (vcpus, memory, disk) = self.values();
        self.advanced.set_subtitle(&model::advanced_summary(
            vcpus,
            memory,
            disk,
            self.internet.is_active(),
        ));
        // Fixed text only: descriptions are markup.
        let full = limits.block();
        self.advanced_group.set_description(full);
        let name = model::vm_name(&self.name.text(), &self.taken);
        match &name {
            Ok(_) => {
                self.name.remove_css_class("error");
                self.hint.set_visible(false);
            }
            Err(why) => {
                self.name.add_css_class("error");
                self.hint.set_label(why);
                self.hint.set_visible(true);
            }
        }
        self.create.set_sensitive(name.is_ok() && full.is_none());
    }

    fn values(&self) -> (u32, u64, u64) {
        (
            self.vcpus.value() as u32,
            self.memory.value() as u64,
            self.disk.value() as u64,
        )
    }

    fn submit(&self) {
        let image = &self.images[self.selected()];
        let Ok(name) = model::vm_name(&self.name.text(), &self.taken) else {
            return;
        };
        if model::limits(&self.host, image.download_bytes)
            .block()
            .is_some()
        {
            return;
        }
        let (vcpus, memory_gib, disk_gib) = self.values();
        let plan = NewVm {
            name,
            image: image.id.clone(),
            image_title: image.title.clone(),
            vcpus,
            memory_gib,
            disk_gib,
            internet: self.internet.is_active(),
        };
        if let Some(d) = self.dialog.upgrade() {
            d.close();
        }
        if let Some(v) = self.vms.upgrade() {
            v.create_vm(plan, image.cached);
        }
    }
}

impl Vms {
    /// Downloads the image if needed, then creates and starts the VM and
    /// shows it.
    fn create_vm(self: &Rc<Self>, plan: NewVm, cached: bool) {
        if self.create.busy.get() {
            return;
        }
        let first = if cached {
            plan.starting()
        } else {
            plan.downloading()
        };
        self.create.show(Some(&first));
        // Weak: a download may take longer than the page stays.
        let (v, ui, socket) = (Rc::downgrade(self), self.ui.clone(), self.socket.clone());
        glib::spawn_future_local(async move {
            if !cached {
                let (s, pull) = (socket.clone(), plan.pull());
                let got = client::spawn(async move { client::create(&s, pull).await }).await;
                if let Ok(Err(e)) = &got {
                    ui.fail(&plan.pull_failed(e));
                }
                if !matches!(got, Ok(Ok(_))) {
                    if let Some(v) = v.upgrade() {
                        v.create.show(None);
                    }
                    return;
                }
                if let Some(v) = v.upgrade() {
                    v.create.show(Some(&plan.starting()));
                }
            }
            // Its row says it starts, and its buttons stay off until done.
            let claimed = v.upgrade().is_some_and(|v| {
                let claimed = v
                    .pending
                    .borrow_mut()
                    .start(&plan.name, &Action::Life(Op::Start));
                v.refresh_rows();
                claimed
            });
            let (s, new) = (socket.clone(), plan.request());
            let got = client::spawn(async move { client::create(&s, new).await }).await;
            let ok = matches!(got, Ok(Ok(_)));
            match &got {
                Ok(Ok(_)) => ui.toast(&plan.done()),
                Ok(Err(e)) => ui.fail(&plan.failed(e)),
                Err(_) => {}
            }
            if let Some(v) = v.upgrade() {
                v.create.show(None);
                if claimed {
                    v.pending.borrow_mut().finish(&plan.name, Instant::now());
                }
                v.list_poll.borrow_mut().soon();
            }
            if !ok {
                return;
            }
            // Now, not at the next poll: the new VM is what to show.
            let sent = Instant::now();
            let list =
                client::spawn(async move { client::list(&socket, client::READ_TIMEOUT).await })
                    .await;
            if let (Some(v), Ok(Ok(list))) = (v.upgrade(), list) {
                v.pending.borrow_mut().listed(sent);
                v.show(list);
                v.select_new(&plan.name);
            }
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
