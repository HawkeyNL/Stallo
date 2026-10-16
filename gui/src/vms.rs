//! The connected window: the VM list with the host meter, and a VM's
//! overview with its lifecycle actions, its screen and its snapshots. All
//! text from the daemon goes through the view-model (`stallo::printable`)
//! into plain labels.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::{Rc, Weak};
use std::time::{Instant, SystemTime};

use adw::prelude::*;
use adw::{gio, glib, gtk};
use libadwaita as adw;
use stallo::api::{VmDetails, VmInfo};
use stallo::snapshot::Snapshot;

use crate::Ui;
use crate::client;
use crate::model::{self, Action, Op, Pending, Poll};
use crate::screen::Screen;

/// The pill around a VM's state in the sidebar.
pub const CSS: &str = ".state-pill { border-radius: 999px; padding: 1px 8px; background-color: alpha(currentColor, 0.12); }";

pub struct Vms {
    ui: Rc<Ui>,
    socket: PathBuf,
    pub root: adw::BreakpointBin,
    split: adw::NavigationSplitView,
    list: gtk::ListBox,
    /// The sidebar rows, in list order, with the VM each one shows.
    rows: RefCell<Vec<Row>>,
    vms: RefCell<Vec<VmInfo>>,
    /// Shown in the content pane while no VM is selected.
    none: adw::NavigationPage,
    detail: RefCell<Option<Rc<Detail>>>,
    /// VMs with an action in flight or just done: one at a time per VM.
    pending: RefCell<Pending>,
    /// The daemon answers (no reconnect banner).
    online: Cell<bool>,
    memory_bar: gtk::LevelBar,
    memory: gtk::Label,
    disk: gtk::Label,
    meter: gtk::Box,
    list_poll: RefCell<Poll>,
    host_poll: RefCell<Poll>,
    /// The heartbeat, while polling is on.
    timer: RefCell<Option<glib::SourceId>>,
}

struct Row {
    name: String,
    row: gtk::ListBoxRow,
    state: gtk::Label,
    /// Shown while an agent may control the VM.
    agent: gtk::Label,
    working: Progress,
    shown: RefCell<Option<model::RowVm>>,
}

/// A spinner with a caption, for an action that runs.
struct Progress {
    root: gtk::Box,
    spinner: adw::Spinner,
    label: gtk::Label,
}

impl Progress {
    fn new() -> Self {
        let spinner = adw::Spinner::new();
        let label = gtk::Label::builder()
            .xalign(0.0)
            .css_classes(["caption", "dim-label"])
            .build();
        label.set_ellipsize(gtk::pango::EllipsizeMode::End);
        let root = gtk::Box::builder()
            .spacing(6)
            .valign(gtk::Align::Center)
            .visible(false)
            .build();
        root.append(&spinner);
        root.append(&label);
        Self {
            root,
            spinner,
            label,
        }
    }

    /// Shows `text` with the spinner, or hides both.
    fn show(&self, text: Option<&str>) {
        self.root.set_visible(text.is_some());
        if let Some(text) = text {
            self.label.set_label(text);
            name_spinner(&self.spinner, text);
        }
    }
}

/// The content pane for one VM: the Overview, Screen and Snapshots tabs.
struct Detail {
    name: String,
    vms: Weak<Vms>,
    page: adw::NavigationPage,
    /// In [`Op::ALL`] order.
    actions: Vec<gio::SimpleAction>,
    /// The header shows one of these, for the VM's state.
    start: gtk::Button,
    stop: adw::SplitButton,
    resume: adw::SplitButton,
    /// Shown while an action on this VM runs.
    busy: adw::Spinner,
    values: Vec<adw::ActionRow>,
    details: RefCell<Option<VmDetails>>,
    poll: RefCell<Poll>,
    tabs: adw::ViewStack,
    screen: Rc<Screen>,
    take: gtk::Button,
    snaps_group: adw::PreferencesGroup,
    /// First on the timeline while a snapshot is taken.
    taking: adw::ActionRow,
    /// A spinner until the first snapshot list, then the timeline.
    snaps_view: gtk::Stack,
    timeline: gtk::ListBox,
    snap_rows: RefCell<Vec<SnapWidgets>>,
    /// Oldest first, as the daemon lists them.
    snaps: RefCell<Option<Vec<Snapshot>>>,
    snaps_poll: RefCell<Poll>,
    /// The VM state and time of the last snapshot list that timed out.
    snaps_stuck: RefCell<Option<(String, Instant)>>,
}

/// One snapshot on the timeline.
struct SnapWidgets {
    tag: String,
    row: adw::ActionRow,
    restore: gtk::Button,
    delete: gtk::Button,
    /// In place of the buttons while it is restored or deleted.
    working: Progress,
}

/// Names of tabs in [`Detail::tabs`].
const SCREEN: &str = "screen";
const SNAPSHOTS: &str = "snapshots";

impl Vms {
    pub fn new(ui: &Rc<Ui>, socket: PathBuf) -> Rc<Self> {
        let list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::Single)
            .css_classes(["navigation-sidebar"])
            .build();
        // Fixed text only: descriptions are markup.
        list.set_placeholder(Some(
            &adw::StatusPage::builder()
                .icon_name("computer-symbolic")
                .title("No Virtual Machines Yet")
                .description("Create one in a terminal with stallo new.")
                .css_classes(["compact"])
                .build(),
        ));
        let scroll = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&list)
            .build();

        let memory_bar = gtk::LevelBar::new();
        // The default offsets color a nearly empty bar as a warning, the
        // wrong way round for use of a budget.
        for offset in [
            gtk::LEVEL_BAR_OFFSET_LOW,
            gtk::LEVEL_BAR_OFFSET_HIGH,
            gtk::LEVEL_BAR_OFFSET_FULL,
        ] {
            memory_bar.remove_offset_value(Some(offset));
        }
        memory_bar.update_property(&[gtk::accessible::Property::Label("VM memory")]);
        let caption = |text: &str| {
            gtk::Label::builder()
                .label(text)
                .xalign(0.0)
                .wrap(true)
                .css_classes(["caption"])
                .build()
        };
        let (memory, disk) = (caption(""), caption(""));
        let meter = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(6)
            .margin_top(12)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .visible(false)
            .build();
        let title = gtk::Label::builder()
            .label("Host")
            .xalign(0.0)
            .css_classes(["heading"])
            .build();
        meter.append(&title);
        meter.append(&memory_bar);
        meter.append(&memory);
        meter.append(&disk);

        let sidebar = adw::ToolbarView::builder().content(&scroll).build();
        sidebar.add_top_bar(&adw::HeaderBar::new());
        sidebar.add_bottom_bar(&meter);

        let none = adw::NavigationPage::builder()
            .title("Stallo")
            .child(&toolbar(
                &adw::HeaderBar::new(),
                &adw::StatusPage::builder()
                    .icon_name("computer-symbolic")
                    .title("No Virtual Machine Selected")
                    .build(),
            ))
            .build();
        let split = adw::NavigationSplitView::builder()
            .sidebar(
                &adw::NavigationPage::builder()
                    .title("Virtual Machines")
                    .child(&sidebar)
                    .build(),
            )
            .content(&none)
            .build();
        let root = adw::BreakpointBin::builder()
            .width_request(360)
            .height_request(294)
            .child(&split)
            .build();
        let narrow = adw::Breakpoint::new(
            adw::BreakpointCondition::parse("max-width: 600sp").expect("a valid condition"),
        );
        narrow.add_setter(&split, "collapsed", Some(&true.to_value()));
        root.add_breakpoint(narrow);

        let vms = Rc::new(Self {
            ui: ui.clone(),
            socket,
            root,
            split,
            list,
            rows: RefCell::default(),
            vms: RefCell::default(),
            none,
            detail: RefCell::default(),
            pending: RefCell::default(),
            online: Cell::new(true),
            memory_bar,
            memory,
            disk,
            meter,
            list_poll: RefCell::new(Poll::new(model::LIST_EVERY)),
            host_poll: RefCell::new(Poll::new(model::HOST_EVERY)),
            timer: RefCell::default(),
        });
        // Selecting (keyboard, focus, screen readers) shows a VM beside the
        // list; activating (click, Enter) also brings it forward when the
        // view is collapsed, even if it was selected already.
        // Weak: widgets of this page must not keep it alive once the
        // window shows another page.
        let v = Rc::downgrade(&vms);
        vms.list.connect_row_selected(move |_, row| {
            if let (Some(v), Some(row)) = (v.upgrade(), row) {
                v.open(row.index(), false);
            }
        });
        let v = Rc::downgrade(&vms);
        vms.list.connect_row_activated(move |_, row| {
            if let Some(v) = v.upgrade() {
                v.open(row.index(), true);
            }
        });
        vms
    }

    /// While the daemon is out of reach no action can be sent.
    pub fn set_online(&self, on: bool) {
        if self.online.replace(on) != on {
            self.refresh_open();
        }
    }

    /// Polls while `on`: when the window is visible and connected.
    pub fn set_active(self: &Rc<Self>, on: bool) {
        let mut timer = self.timer.borrow_mut();
        if on && timer.is_none() {
            let v = Rc::downgrade(self);
            *timer = Some(glib::timeout_add_local(model::TICK, move || {
                if let Some(v) = v.upgrade() {
                    v.tick();
                }
                glib::ControlFlow::Continue
            }));
            drop(timer);
            // Shown again or reconnected: fresh data now, backoff or not.
            self.list_poll.borrow_mut().soon();
            self.host_poll.borrow_mut().soon();
            self.tick();
        } else if let Some(t) = timer.take_if(|_| !on) {
            t.remove();
            drop(timer);
            if let Some(d) = self.detail.borrow().as_ref() {
                d.screen.set_wanted(false);
            }
        }
    }

    /// Sends the polls that are due.
    fn tick(self: &Rc<Self>) {
        if self.timer.borrow().is_none() {
            return;
        }
        let now = Instant::now();
        if self.list_poll.borrow_mut().due(now) {
            let (v, socket) = (self.clone(), self.socket.clone());
            glib::spawn_future_local(async move {
                let sent = Instant::now();
                let got =
                    client::spawn(async move { client::list(&socket, client::READ_TIMEOUT).await })
                        .await;
                let ok = matches!(got, Ok(Ok(_)));
                v.list_poll.borrow_mut().done(Instant::now(), ok);
                match got {
                    Ok(Ok(vms)) => {
                        v.pending.borrow_mut().listed(sent);
                        v.show(vms);
                    }
                    // The probe decides: banner and reconnect, or a page.
                    _ => v.ui.probe(),
                }
            });
        }
        if self.host_poll.borrow_mut().due(now) {
            let (v, socket) = (self.clone(), self.socket.clone());
            glib::spawn_future_local(async move {
                let got = client::spawn(async move { client::host(&socket).await }).await;
                let ok = matches!(got, Ok(Ok(_)));
                v.host_poll.borrow_mut().done(Instant::now(), ok);
                if let Ok(Ok(host)) = got {
                    v.show_host(&model::meter(&host));
                }
            });
        }
        let Some(detail) = self.detail.borrow().clone() else {
            return;
        };
        let Some(vm) = self.vm(&detail.name) else {
            return;
        };
        let visible = !self.split.is_collapsed() || self.split.shows_content();
        let tab = detail.tabs.visible_child_name();
        detail
            .screen
            .set_wanted(visible && tab.as_deref() == Some(SCREEN));
        // Not while an action on the VM runs: the daemon would make the
        // list wait for it. The action asks again when it is done.
        if visible
            && tab.as_deref() == Some(SNAPSHOTS)
            && !self.pending.borrow().blocks(&detail.name)
            && !model::snaps_wait(detail.snaps_stuck.borrow().as_ref(), &vm.state, now)
            && detail.snaps_poll.borrow_mut().due(now)
        {
            let (v, socket, name) = (self.clone(), self.socket.clone(), detail.name.clone());
            let (detail, state) = (detail.clone(), vm.state.clone());
            glib::spawn_future_local(async move {
                let got =
                    client::spawn(async move { client::snapshots(&socket, name).await }).await;
                let ok = matches!(got, Ok(Ok(_)));
                detail.snaps_poll.borrow_mut().done(Instant::now(), ok);
                if let Ok(Err(model::CallError::Timeout)) = got {
                    *detail.snaps_stuck.borrow_mut() = Some((state, Instant::now()));
                }
                match got {
                    Ok(Ok(list)) => {
                        detail.snaps_stuck.take();
                        *detail.snaps.borrow_mut() = Some(list);
                        v.refresh(&detail);
                    }
                    // Only the first time: later the old list or the
                    // error stays.
                    Ok(Err(e))
                        if detail.snaps_view.visible_child_name().as_deref() == Some("loading") =>
                    {
                        detail.snaps_view.set_visible_child_name("failed");
                        let title = format!(
                            "Could not list the snapshots of {}",
                            stallo::printable(&detail.name, 64)
                        );
                        v.ui.fail(&model::failure(title, &e));
                    }
                    _ => {}
                }
            });
        }
        // Started or stopped since the last `info`: ask again now (the
        // Screen tab waits for the socket in it).
        let seen = detail
            .details
            .borrow()
            .as_ref()
            .map(|d| model::kind(&d.vm.state));
        let have = seen == Some(model::kind(&vm.state));
        if seen.is_some() && !have {
            detail.poll.borrow_mut().soon();
        }
        if model::wants_info(visible, model::kind(&vm.state), have)
            && detail.poll.borrow_mut().due(now)
        {
            let (v, socket, name) = (self.clone(), self.socket.clone(), detail.name.clone());
            glib::spawn_future_local(async move {
                let got = client::spawn(async move { client::info(&socket, name).await }).await;
                let ok = matches!(got, Ok(Ok(_)));
                detail.poll.borrow_mut().done(Instant::now(), ok);
                if let Ok(Ok(d)) = got {
                    *detail.details.borrow_mut() = Some(d);
                    v.refresh(&detail);
                }
            });
        }
    }

    fn vm(&self, name: &str) -> Option<VmInfo> {
        self.vms.borrow().iter().find(|v| v.name == name).cloned()
    }

    /// A new VM list from the daemon.
    fn show(self: &Rc<Self>, vms: Vec<VmInfo>) {
        let same = {
            let rows = self.rows.borrow();
            rows.len() == vms.len() && rows.iter().zip(&vms).all(|(r, v)| r.name == v.name)
        };
        // First: rebuilding selects the open VM's row again, by index.
        *self.vms.borrow_mut() = vms.clone();
        if !same {
            self.rebuild(&vms);
        }
        self.refresh_rows();
        let detail = self.detail.borrow().clone();
        if let Some(d) = detail {
            if self.vm(&d.name).is_some() {
                self.refresh(&d);
            } else {
                // Removed elsewhere.
                *self.detail.borrow_mut() = None;
                self.split.set_content(Some(&self.none));
                self.split.set_show_content(false);
            }
        }
    }

    fn rebuild(&self, vms: &[VmInfo]) {
        self.list.remove_all();
        let selected = self.detail.borrow().as_ref().map(|d| d.name.clone());
        let rows: Vec<Row> = vms.iter().map(|vm| Row::new(&vm.name)).collect();
        for r in &rows {
            self.list.append(&r.row);
            if selected.as_deref() == Some(&r.name) {
                self.list.select_row(Some(&r.row));
            }
        }
        *self.rows.borrow_mut() = rows;
    }

    /// Shows the VM in row `index`, and brings its page forward if `show`.
    fn open(self: &Rc<Self>, index: i32, show: bool) {
        let vm = usize::try_from(index)
            .ok()
            .and_then(|i| self.vms.borrow().get(i).cloned());
        let Some(vm) = vm else {
            return;
        };
        let current = self.detail.borrow().clone();
        if current.is_none_or(|d| d.name != vm.name) {
            let detail = Detail::new(&vm, self);
            self.split.set_content(Some(&detail.page));
            self.refresh(&detail);
            *self.detail.borrow_mut() = Some(detail);
        }
        if show {
            self.split.set_show_content(true);
        }
        self.tick();
    }

    /// Updates the sidebar rows from what is known now.
    fn refresh_rows(&self) {
        let pending = self.pending.borrow();
        for (r, vm) in self.rows.borrow().iter().zip(self.vms.borrow().iter()) {
            r.update(model::row(vm, pending.action(&vm.name)));
        }
    }

    /// Updates the open VM's page from what is known now.
    fn refresh(&self, detail: &Detail) {
        if let Some(vm) = self.vm(&detail.name) {
            let working = self.pending.borrow().action(&detail.name).cloned();
            detail.update(&vm, self.online.get(), working.as_ref());
        }
    }

    fn refresh_open(&self) {
        if let Some(d) = self.detail.borrow().as_ref() {
            self.refresh(d);
        }
    }

    /// Runs a lifecycle action, after a confirmation if it may lose data.
    pub(crate) fn ask(self: &Rc<Self>, op: Op, name: &str) {
        let Some(vm) = self.vm(name) else {
            return;
        };
        match model::confirm(op, &vm) {
            Some(c) => self.confirm(&c, Action::Life(op), name),
            None => self.run(Action::Life(op), name),
        }
    }

    /// The open VM and its snapshot `tag`, if both are still there.
    fn snapshot(&self, name: &str, tag: &str) -> Option<(VmInfo, Snapshot)> {
        let detail = self.detail.borrow().clone().filter(|d| d.name == name)?;
        let snap = detail
            .snaps
            .borrow()
            .iter()
            .flatten()
            .find(|s| s.name == tag)
            .cloned()?;
        Some((self.vm(name)?, snap))
    }

    fn ask_restore(self: &Rc<Self>, name: &str, tag: &str) {
        if let Some((vm, snap)) = self.snapshot(name, tag) {
            let c = model::confirm_restore(&vm, &snap);
            self.confirm(&c, Action::Restore(snap.name), name);
        }
    }

    fn ask_delete(self: &Rc<Self>, name: &str, tag: &str) {
        if let Some((vm, snap)) = self.snapshot(name, tag) {
            let c = model::confirm_delete(&vm, &snap.name);
            self.confirm(&c, Action::Delete(snap.name), name);
        }
    }

    /// Asks before `action`, with Cancel as the default.
    pub(crate) fn confirm(self: &Rc<Self>, c: &model::Confirm, action: Action, name: &str) {
        let dialog = adw::AlertDialog::builder()
            .heading(&c.heading)
            .heading_use_markup(false)
            .body(&c.body)
            .body_use_markup(false)
            .build();
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("confirm", c.button);
        dialog.set_response_appearance("confirm", adw::ResponseAppearance::Destructive);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        let (v, name) = (Rc::downgrade(self), name.to_owned());
        dialog.connect_response(Some("confirm"), move |_, _| {
            if let Some(v) = v.upgrade() {
                v.run(action.clone(), &name);
            }
        });
        dialog.present(Some(&self.root));
    }

    /// Asks for an optional name, checked as the daemon checks it.
    fn ask_take(self: &Rc<Self>, name: &str) {
        let detail = self.detail.borrow().clone().filter(|d| d.name == name);
        let (Some(vm), Some(detail)) = (self.vm(name), detail) else {
            return;
        };
        let snaps = detail.snaps.borrow().clone();
        let entry = adw::EntryRow::builder()
            .title("Name")
            .text(model::suggested_name(snaps.as_deref()))
            .activates_default(true)
            .build();
        let names = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .css_classes(["boxed-list"])
            .build();
        names.append(&entry);
        // Shown only while the name is refused, and read out with the entry.
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
        content.append(&names);
        content.append(&hint);
        let dialog = adw::AlertDialog::builder()
            .heading("Take Snapshot")
            .body(model::take_note(&vm))
            .body_use_markup(false)
            .extra_child(&content)
            .build();
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("take", "Take Snapshot");
        dialog.set_response_appearance("take", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("take"));
        dialog.set_close_response("cancel");
        // Weak: the dialog owns the entry and so this handler.
        let (d, list) = (dialog.downgrade(), snaps.clone());
        entry.connect_changed(move |e| {
            let checked = model::snapshot_name(&e.text(), list.as_deref());
            if let Some(d) = d.upgrade() {
                d.set_response_enabled("take", checked.is_ok());
            }
            match checked {
                Ok(_) => {
                    e.remove_css_class("error");
                    hint.set_visible(false);
                }
                Err(why) => {
                    e.add_css_class("error");
                    hint.set_label(&why);
                    hint.set_visible(true);
                }
            }
        });
        let (v, name, typed) = (Rc::downgrade(self), name.to_owned(), entry.clone());
        dialog.connect_response(Some("take"), move |_, _| {
            if let (Some(v), Ok(tag)) = (
                v.upgrade(),
                model::snapshot_name(&typed.text(), snaps.as_deref()),
            ) {
                v.run(Action::Take(tag), &name);
            }
        });
        // The suggested name is selected: typing replaces it.
        dialog.set_focus(Some(&entry));
        entry.select_region(0, -1);
        dialog.present(Some(&self.root));
    }

    /// Runs an action; one per VM at a time.
    pub(crate) fn run(self: &Rc<Self>, action: Action, name: &str) {
        if !self.online.get() || !self.pending.borrow_mut().start(name, &action) {
            return;
        }
        self.refresh_rows();
        self.refresh_open();
        let (v, socket, name) = (self.clone(), self.socket.clone(), name.to_owned());
        glib::spawn_future_local(async move {
            let (vm, sent) = (name.clone(), action.clone());
            let got = client::spawn(async move { client::act(&socket, &sent, &vm).await }).await;
            // Its buttons stay off until a list asked for from now on.
            v.pending.borrow_mut().finish(&name, Instant::now());
            let ok = matches!(got, Ok(Ok(_)));
            match got {
                Ok(Ok(data)) => {
                    if let Some(text) = action.done(&name, &data) {
                        v.ui.toast(&text);
                    }
                }
                Ok(Err(e)) => v.ui.fail(&action.failed(&name, &e)),
                Err(_) => {}
            }
            v.refresh_open();
            v.list_poll.borrow_mut().soon();
            if let Some(d) = v.detail.borrow().as_ref() {
                d.poll.borrow_mut().soon();
                d.snaps_poll.borrow_mut().soon();
                // The action got the VM's lock, so no list waits for it now.
                if ok && d.name == name {
                    d.snaps_stuck.take();
                }
            }
            v.tick();
        });
    }

    /// Fresh VM list and details at the next tick.
    pub(crate) fn poll_soon(self: &Rc<Self>) {
        self.list_poll.borrow_mut().soon();
        if let Some(d) = self.detail.borrow().as_ref() {
            d.poll.borrow_mut().soon();
        }
    }

    /// The Snapshots tab may have come into view: fresh data now.
    fn tab_changed(self: &Rc<Self>) {
        if let Some(d) = self.detail.borrow().as_ref() {
            d.snaps_poll.borrow_mut().soon();
        }
        self.tick();
    }

    fn show_host(&self, m: &model::Meter) {
        self.memory_bar.set_value(m.memory_fraction);
        self.memory.set_label(&m.memory);
        self.disk.set_label(&m.disk);
        if m.disk_low {
            self.disk.add_css_class("error");
        } else {
            self.disk.remove_css_class("error");
        }
        self.meter.set_visible(true);
    }
}

impl Row {
    fn new(name: &str) -> Self {
        let label = gtk::Label::builder()
            .label(stallo::printable(name, 64))
            .xalign(0.0)
            .hexpand(true)
            .build();
        // A setter, not the builder: the builder would link libpango for
        // the enum's type.
        label.set_ellipsize(gtk::pango::EllipsizeMode::End);
        let state = gtk::Label::builder()
            .valign(gtk::Align::Center)
            .css_classes(["caption", "state-pill"])
            .build();
        // Text, not an icon: someone else may drive this VM.
        let agent = gtk::Label::builder()
            .label("Agent")
            .tooltip_text("Agent control on")
            .valign(gtk::Align::Center)
            .visible(false)
            .css_classes(["caption", "state-pill", "warning"])
            .build();
        agent.update_property(&[gtk::accessible::Property::Label("Agent control on")]);
        let line = gtk::Box::builder()
            .spacing(8)
            .margin_top(6)
            .margin_bottom(6)
            .build();
        // While an action runs, its spinner and text take the pill's place.
        let working = Progress::new();
        line.append(&label);
        line.append(&state);
        line.append(&working.root);
        line.append(&agent);
        let row = gtk::ListBoxRow::builder().child(&line).build();
        Self {
            name: name.to_owned(),
            row,
            state,
            agent,
            working,
            shown: RefCell::default(),
        }
    }

    fn update(&self, r: model::RowVm) {
        if self.shown.borrow().as_ref() == Some(&r) {
            return;
        }
        if let Some(old) = self.shown.borrow().as_ref().and_then(|o| o.tone) {
            self.state.remove_css_class(old);
        }
        if let Some(tone) = r.tone {
            self.state.add_css_class(tone);
        }
        self.state.set_label(r.state);
        self.state.set_visible(r.working.is_none());
        self.state.set_tooltip_text(Some(&r.raw));
        self.agent.set_visible(r.agent);
        self.working.show(r.working);
        self.row
            .update_property(&[gtk::accessible::Property::Label(&r.label())]);
        *self.shown.borrow_mut() = Some(r);
    }
}

impl Detail {
    fn new(vm: &VmInfo, vms: &Rc<Vms>) -> Rc<Self> {
        let group = gio::SimpleActionGroup::new();
        let actions: Vec<gio::SimpleAction> = Op::ALL
            .iter()
            .map(|&op| {
                let a = gio::SimpleAction::new(op.action(), None);
                let (v, name) = (Rc::downgrade(vms), vm.name.clone());
                a.connect_activate(move |_, _| {
                    if let Some(v) = v.upgrade() {
                        v.ask(op, &name);
                    }
                });
                group.add_action(&a);
                a
            })
            .collect();
        // One of these shows at a time; the risky ones sit in a menu.
        let start = gtk::Button::builder()
            .label("Start")
            .action_name("vm.start")
            .css_classes(["suggested-action"])
            .visible(false)
            .build();
        let menu = gio::Menu::new();
        menu.append(Some("Force Off"), Some("vm.force-off"));
        menu.append(Some("Reset"), Some("vm.reset"));
        let stop = adw::SplitButton::builder()
            .label("Stop")
            .action_name("vm.stop")
            .menu_model(&menu)
            .dropdown_tooltip("More Ways to Stop")
            .visible(false)
            .build();
        // For a VM that does not run: Stop could not shut it down cleanly.
        let menu = gio::Menu::new();
        menu.append(Some("Force Off"), Some("vm.force-off"));
        let resume = adw::SplitButton::builder()
            .label("Resume")
            .action_name("vm.resume")
            .menu_model(&menu)
            .dropdown_tooltip("More Ways to Stop")
            .css_classes(["suggested-action"])
            .visible(false)
            .build();
        let busy = adw::Spinner::builder().visible(false).build();
        let header = adw::HeaderBar::new();
        header.pack_end(&start);
        header.pack_end(&stop);
        header.pack_end(&resume);
        header.pack_end(&busy);

        let overview = adw::PreferencesPage::new();
        let mut values = Vec::new();
        for (title, rows) in model::facts(vm, None) {
            let group = adw::PreferencesGroup::builder().title(title).build();
            for (title, _) in rows {
                let row = adw::ActionRow::builder()
                    .title(title)
                    .use_markup(false)
                    .subtitle_selectable(true)
                    .css_classes(["property"])
                    .build();
                group.add(&row);
                values.push(row);
            }
            overview.add(&group);
        }

        let take = gtk::Button::builder()
            .label("Take Snapshot")
            .valign(gtk::Align::Center)
            .build();
        let (v, name) = (Rc::downgrade(vms), vm.name.clone());
        take.connect_clicked(move |_| {
            if let Some(v) = v.upgrade() {
                v.ask_take(&name);
            }
        });
        let timeline = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .css_classes(["boxed-list"])
            .build();
        let taking_spinner = adw::Spinner::new();
        let taking = adw::ActionRow::builder()
            .title(Action::Take(None).progress())
            .visible(false)
            .build();
        name_spinner(&taking_spinner, Action::Take(None).progress());
        taking.add_prefix(&taking_spinner);
        timeline.append(&taking);
        timeline.set_placeholder(Some(
            &gtk::Label::builder()
                .label("No snapshots yet")
                .margin_top(12)
                .margin_bottom(12)
                .css_classes(["dim-label"])
                .build(),
        ));
        let snaps_view = gtk::Stack::new();
        snaps_view.add_named(&adw::Spinner::new(), Some("loading"));
        snaps_view.add_named(&timeline, Some("list"));
        snaps_view.add_named(
            &gtk::Label::builder()
                .label("The snapshots could not be listed. Stallo tries again later.")
                .wrap(true)
                .margin_top(12)
                .margin_bottom(12)
                .css_classes(["dim-label"])
                .build(),
            Some("failed"),
        );
        let snaps_group = adw::PreferencesGroup::builder()
            .title("Snapshots")
            .header_suffix(&take)
            .build();
        snaps_group.add(&snaps_view);
        let snapshots = adw::PreferencesPage::new();
        snapshots.add(&snaps_group);

        let screen = Screen::new(vm, vms);
        let tabs = adw::ViewStack::new();
        tabs.add_titled_with_icon(&overview, Some("overview"), "Overview", "computer-symbolic");
        tabs.add_titled_with_icon(
            &screen.root,
            Some(SCREEN),
            "Screen",
            "video-display-symbolic",
        );
        tabs.add_titled_with_icon(
            &snapshots,
            Some(SNAPSHOTS),
            "Snapshots",
            "camera-photo-symbolic",
        );
        // Tabs in the header bar, or at the bottom with the VM's name in
        // the header when this pane (not the window) is narrow.
        let switcher = adw::ViewSwitcher::builder()
            .stack(&tabs)
            .policy(adw::ViewSwitcherPolicy::Wide)
            .build();
        let title = gtk::Label::builder()
            .label(stallo::printable(&vm.name, 64))
            .visible(false)
            .css_classes(["title"])
            .build();
        title.set_ellipsize(gtk::pango::EllipsizeMode::End);
        let titles = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        titles.append(&switcher);
        titles.append(&title);
        header.set_title_widget(Some(&titles));
        let bar = adw::ViewSwitcherBar::builder().stack(&tabs).build();
        let view = toolbar(&header, &tabs);
        view.add_bottom_bar(&bar);
        let pane = adw::BreakpointBin::builder()
            .width_request(360)
            .height_request(294)
            .child(&view)
            .build();
        let narrow = adw::Breakpoint::new(
            adw::BreakpointCondition::parse("max-width: 700sp").expect("a valid condition"),
        );
        narrow.add_setter(&switcher, "visible", Some(&false.to_value()));
        narrow.add_setter(&title, "visible", Some(&true.to_value()));
        narrow.add_setter(&bar, "reveal", Some(&true.to_value()));
        pane.add_breakpoint(narrow);
        let v = Rc::downgrade(vms);
        tabs.connect_visible_child_name_notify(move |_| {
            if let Some(v) = v.upgrade() {
                v.tab_changed();
            }
        });

        let page = adw::NavigationPage::builder()
            .title(stallo::printable(&vm.name, 64))
            .child(&pane)
            .build();
        page.insert_action_group("vm", Some(&group));
        Rc::new(Self {
            name: vm.name.clone(),
            vms: Rc::downgrade(vms),
            page,
            actions,
            start,
            stop,
            resume,
            busy,
            values,
            details: RefCell::default(),
            poll: RefCell::new(Poll::new(model::INFO_EVERY)),
            tabs,
            screen,
            take,
            snaps_group,
            taking,
            snaps_view,
            timeline,
            snap_rows: RefCell::default(),
            snaps: RefCell::default(),
            snaps_poll: RefCell::new(Poll::new(model::SNAPS_EVERY)),
            snaps_stuck: RefCell::default(),
        })
    }

    /// Shows `vm` as it is now. No actions while offline or while an
    /// action on it runs or just ran (`working`).
    fn update(&self, vm: &VmInfo, online: bool, working: Option<&Action>) {
        let blocked = !online || working.is_some();
        let set = model::actions(vm, blocked);
        for (action, op) in self.actions.iter().zip(Op::ALL) {
            action.set_enabled(set.allows(op));
        }
        self.start.set_visible(set.primary == Op::Start);
        self.stop.set_visible(set.primary == Op::Stop);
        self.resume.set_visible(set.primary == Op::Resume);
        if set.suggested {
            self.resume.add_css_class("suggested-action");
        } else {
            self.resume.remove_css_class("suggested-action");
        }
        self.busy.set_visible(working.is_some());
        if let Some(text) = working.map(Action::progress) {
            self.busy.set_tooltip_text(Some(text));
            name_spinner(&self.busy, text);
        }
        self.screen
            .update(vm, self.details.borrow().as_ref(), blocked);
        let facts = model::facts(vm, self.details.borrow().as_ref());
        let values = facts.into_iter().flat_map(|(_, rows)| rows);
        for (row, (_, value)) in self.values.iter().zip(values) {
            if row.subtitle().as_deref() != Some(value.as_str()) {
                row.set_subtitle(&value);
            }
        }

        let snaps = self.snaps.borrow();
        let full = model::take_block(snaps.as_deref());
        self.take.set_sensitive(!blocked && full.is_none());
        // Fixed text only: descriptions are markup.
        self.snaps_group.set_description(full.as_deref());
        self.taking
            .set_visible(matches!(working, Some(Action::Take(_))));
        let Some(snaps) = snaps.as_ref() else {
            return;
        };
        // The one thing to do on an empty timeline.
        if snaps.is_empty() {
            self.take.add_css_class("suggested-action");
        } else {
            self.take.remove_css_class("suggested-action");
        }
        self.snaps_view.set_visible_child_name("list");
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let rows = model::timeline(vm, snaps, now, working);
        let same = {
            let shown = self.snap_rows.borrow();
            shown.len() == rows.len() && shown.iter().zip(&rows).all(|(w, r)| w.tag == r.tag)
        };
        if !same {
            for w in self.snap_rows.borrow().iter() {
                self.timeline.remove(&w.row);
            }
            let widgets: Vec<SnapWidgets> = rows.iter().map(|r| self.snap_row(r)).collect();
            for w in &widgets {
                self.timeline.append(&w.row);
            }
            *self.snap_rows.borrow_mut() = widgets;
        }
        for (w, r) in self.snap_rows.borrow().iter().zip(&rows) {
            if w.row.subtitle().as_deref() != Some(r.subtitle.as_str()) {
                w.row.set_subtitle(&r.subtitle);
            }
            w.restore
                .set_sensitive(!blocked && r.restore_block.is_none());
            w.delete.set_sensitive(!blocked);
            w.restore.set_visible(r.working.is_none());
            w.delete.set_visible(r.working.is_none());
            w.working.show(r.working);
        }
    }

    fn snap_row(&self, r: &model::SnapRow) -> SnapWidgets {
        let row = adw::ActionRow::builder()
            .title(&r.name)
            .use_markup(false)
            .build();
        let restore = gtk::Button::builder()
            .label("Restore")
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build();
        let delete = gtk::Button::builder()
            .icon_name("user-trash-symbolic")
            .tooltip_text("Delete")
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build();
        // The label child would name it plain "Restore".
        restore.reset_relation(gtk::AccessibleRelation::LabelledBy);
        restore.update_property(&[gtk::accessible::Property::Label(&format!(
            "Restore {}",
            r.name
        ))]);
        delete.update_property(&[gtk::accessible::Property::Label(&format!(
            "Delete {}",
            r.name
        ))]);
        let working = Progress::new();
        row.add_suffix(&working.root);
        row.add_suffix(&restore);
        row.add_suffix(&delete);
        let (v, name, tag) = (self.vms.clone(), self.name.clone(), r.tag.clone());
        restore.connect_clicked(move |_| {
            if let Some(v) = v.upgrade() {
                v.ask_restore(&name, &tag);
            }
        });
        let (v, name, tag) = (self.vms.clone(), self.name.clone(), r.tag.clone());
        delete.connect_clicked(move |_| {
            if let Some(v) = v.upgrade() {
                v.ask_delete(&name, &tag);
            }
        });
        SnapWidgets {
            tag: r.tag.clone(),
            row,
            restore,
            delete,
            working,
        }
    }
}

/// What a screen reader says for a spinner. Through `Widget`: the binding
/// does not mark `adw::Spinner` as `Accessible`.
fn name_spinner(spinner: &adw::Spinner, text: &str) {
    spinner
        .upcast_ref::<gtk::Widget>()
        .update_property(&[gtk::accessible::Property::Label(text)]);
}

fn toolbar(header: &adw::HeaderBar, content: &impl IsA<gtk::Widget>) -> adw::ToolbarView {
    let view = adw::ToolbarView::builder().content(content).build();
    view.add_top_bar(header);
    view
}
