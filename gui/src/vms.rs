//! The connected window: the VM list with the host meter, and a VM's
//! overview with its lifecycle actions. All text from the daemon goes
//! through the view-model (`stallo::printable`) into plain labels.

use std::cell::RefCell;
use std::collections::HashSet;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Instant;

use adw::prelude::*;
use adw::{gio, glib, gtk};
use libadwaita as adw;
use stallo::api::{VmDetails, VmInfo};

use crate::Ui;
use crate::client;
use crate::model::{self, Op, Poll};

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
    /// VMs with an action in flight: one at a time per VM.
    pending: RefCell<HashSet<String>>,
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
    control: gtk::Image,
    shown: RefCell<Option<model::RowVm>>,
}

/// The content pane for one VM.
struct Detail {
    name: String,
    page: adw::NavigationPage,
    /// In [`Op::ALL`] order.
    actions: Vec<gio::SimpleAction>,
    resume: gtk::Button,
    values: Vec<adw::ActionRow>,
    details: RefCell<Option<VmDetails>>,
    poll: RefCell<Poll>,
}

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
        let v = vms.clone();
        vms.list.connect_row_selected(move |_, row| {
            if let Some(row) = row {
                v.open(row.index(), false);
            }
        });
        let v = vms.clone();
        vms.list
            .connect_row_activated(move |_, row| v.open(row.index(), true));
        vms
    }

    /// Polls while `on`: when the window is visible and connected.
    pub fn set_active(self: &Rc<Self>, on: bool) {
        let mut timer = self.timer.borrow_mut();
        if on && timer.is_none() {
            let v = self.clone();
            *timer = Some(glib::timeout_add_local(model::TICK, move || {
                v.tick();
                glib::ControlFlow::Continue
            }));
            drop(timer);
            // Shown again or reconnected: fresh data now, backoff or not.
            self.list_poll.borrow_mut().soon();
            self.host_poll.borrow_mut().soon();
            self.tick();
        } else if let Some(t) = timer.take_if(|_| !on) {
            t.remove();
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
                let got =
                    client::spawn(async move { client::list(&socket, client::READ_TIMEOUT).await })
                        .await;
                let ok = matches!(got, Ok(Ok(_)));
                v.list_poll.borrow_mut().done(Instant::now(), ok);
                match got {
                    Ok(Ok(vms)) => v.show(vms),
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
        let have = detail.details.borrow().is_some();
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
        for (r, vm) in self.rows.borrow().iter().zip(&vms) {
            r.update(model::row(vm));
        }
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
            let detail = Detail::new(&vm);
            for (action, op) in detail.actions.iter().zip(Op::ALL) {
                let (v, name) = (self.clone(), vm.name.clone());
                action.connect_activate(move |_, _| v.run(op, &name));
            }
            self.split.set_content(Some(&detail.page));
            self.refresh(&detail);
            *self.detail.borrow_mut() = Some(detail);
        }
        if show {
            self.split.set_show_content(true);
        }
        self.tick();
    }

    /// Updates the open VM's page from what is known now.
    fn refresh(&self, detail: &Detail) {
        if let Some(vm) = self.vm(&detail.name) {
            let pending = self.pending.borrow().contains(&detail.name);
            detail.update(&vm, pending);
        }
    }

    fn refresh_open(&self) {
        if let Some(d) = self.detail.borrow().as_ref() {
            self.refresh(d);
        }
    }

    /// Runs a lifecycle action; one per VM at a time.
    fn run(self: &Rc<Self>, op: Op, name: &str) {
        if !self.pending.borrow_mut().insert(name.to_owned()) {
            return;
        }
        self.refresh_open();
        let (v, socket, name) = (self.clone(), self.socket.clone(), name.to_owned());
        glib::spawn_future_local(async move {
            let vm = name.clone();
            let got = client::spawn(async move { client::act(&socket, op, &vm).await }).await;
            v.pending.borrow_mut().remove(&name);
            if let Ok(Err(e)) = got {
                v.ui.toast(&op.failed(&name, &e));
            }
            v.refresh_open();
            v.list_poll.borrow_mut().soon();
            if let Some(d) = v.detail.borrow().as_ref() {
                d.poll.borrow_mut().soon();
            }
            v.tick();
        });
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
        let control = gtk::Image::new();
        let line = gtk::Box::builder()
            .spacing(8)
            .margin_top(6)
            .margin_bottom(6)
            .build();
        line.append(&label);
        line.append(&state);
        line.append(&control);
        let row = gtk::ListBoxRow::builder().child(&line).build();
        Self {
            name: name.to_owned(),
            row,
            state,
            control,
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
        self.state.set_label(&r.state);
        self.control.set_icon_name(Some(r.control_icon));
        self.control.set_tooltip_text(Some(r.control_tip));
        self.control
            .update_property(&[gtk::accessible::Property::Label(r.control_tip)]);
        let label = format!("{}, {}, {}", r.name, r.state, r.control_tip);
        self.row
            .update_property(&[gtk::accessible::Property::Label(&label)]);
        *self.shown.borrow_mut() = Some(r);
    }
}

impl Detail {
    fn new(vm: &VmInfo) -> Rc<Self> {
        let group = gio::SimpleActionGroup::new();
        let actions: Vec<gio::SimpleAction> = Op::ALL
            .iter()
            .map(|op| {
                let a = gio::SimpleAction::new(op.action(), None);
                group.add_action(&a);
                a
            })
            .collect();
        let start = gtk::Button::builder()
            .label("Start")
            .action_name("vm.start")
            .build();
        let menu = gio::Menu::new();
        menu.append(Some("Force Off"), Some("vm.force-off"));
        menu.append(Some("Reset"), Some("vm.reset"));
        let stop = adw::SplitButton::builder()
            .label("Stop")
            .action_name("vm.stop")
            .menu_model(&menu)
            .dropdown_tooltip("More Ways to Stop")
            .build();
        let resume = gtk::Button::builder()
            .label("Resume")
            .action_name("vm.resume")
            .tooltip_text("Paused because the host disk was nearly full")
            .css_classes(["suggested-action"])
            .visible(false)
            .build();
        let header = adw::HeaderBar::new();
        header.pack_end(&stop);
        header.pack_end(&start);
        header.pack_end(&resume);

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
        let page = adw::NavigationPage::builder()
            .title(stallo::printable(&vm.name, 64))
            .child(&toolbar(&header, &overview))
            .build();
        page.insert_action_group("vm", Some(&group));
        Rc::new(Self {
            name: vm.name.clone(),
            page,
            actions,
            resume,
            values,
            details: RefCell::default(),
            poll: RefCell::new(Poll::new(model::INFO_EVERY)),
        })
    }

    fn update(&self, vm: &VmInfo, pending: bool) {
        let set = model::actions(vm, pending);
        for (action, op) in self.actions.iter().zip(Op::ALL) {
            action.set_enabled(set.allows(op));
        }
        self.resume.set_visible(set.show_resume);
        let facts = model::facts(vm, self.details.borrow().as_ref());
        let values = facts.into_iter().flat_map(|(_, rows)| rows);
        for (row, (_, value)) in self.values.iter().zip(values) {
            if row.subtitle().as_deref() != Some(value.as_str()) {
                row.set_subtitle(&value);
            }
        }
    }
}

fn toolbar(header: &adw::HeaderBar, content: &impl IsA<gtk::Widget>) -> adw::ToolbarView {
    let view = adw::ToolbarView::builder().content(content).build();
    view.add_top_bar(header);
    view
}
