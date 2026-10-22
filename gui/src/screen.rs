//! The Screen tab: a VM's display through the RFB client, with keyboard
//! and mouse, fit or 1:1, view-only and fullscreen. What it shows comes
//! from the view-model. The guest's pixels are untrusted: they are only
//! ever drawn inside a frame, and in fullscreen under a strip that says
//! whose screen it is, so they never pass for the host's own windows.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::{Rc, Weak};
use std::sync::Arc;

use adw::prelude::*;
use adw::{gdk, glib, gtk};
use glib::translate::IntoGlib;
use libadwaita as adw;
use stallo::api::{VmDetails, VmInfo};

use crate::client;
use crate::model::{self, Action, KeyPress, Link, Op, ScreenPage};
use crate::rfb::{Frame, Input, Session};
use crate::vms::Vms;

/// The guest's pixels as texture memory, without a copy.
struct Pixels(Arc<Vec<u8>>);

impl AsRef<[u8]> for Pixels {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct Screen {
    name: String,
    vms: Weak<Vms>,
    /// "status" or "live".
    pub root: gtk::Stack,
    status: adw::StatusPage,
    spinner: adw::Spinner,
    /// Why the connection ended, behind Details.
    reason: gtk::Label,
    details_list: gtk::ListBox,
    /// The one action of a status page.
    action: gtk::Button,
    /// Why the screen is view-only.
    banner: adw::Banner,
    /// Holds `frame` while it is not fullscreen.
    holder: adw::Bin,
    frame: adw::Bin,
    scroller: gtk::ScrolledWindow,
    picture: gtk::Picture,
    hint: gtk::Label,
    ctrl_alt_del: gtk::Button,
    view_only: gtk::ToggleButton,
    actual_size: gtk::ToggleButton,
    /// Fullscreen only, above the guest: whose screen this is, and the
    /// ways out.
    strip: gtk::Box,
    strip_hint: gtk::Label,
    release: gtk::Button,
    full: RefCell<Option<adw::Window>>,

    vm: RefCell<Option<VmInfo>>,
    details: RefCell<Option<VmDetails>>,
    /// An action on the VM runs, or the daemon is out of reach.
    blocked: Cell<bool>,
    /// Agent control as last seen; `None` before the first update.
    agent: Cell<Option<bool>>,
    /// The tab is on screen.
    wanted: Cell<bool>,
    link: RefCell<Link>,
    session: RefCell<Option<Session>>,
    /// Bumped by every connect and disconnect: older tasks stop.
    generation: Cell<u64>,
    texture: RefCell<Option<gdk::Texture>>,
    /// The serial and size of the frame in `texture`.
    shown: Cell<Option<(u64, u16, u16)>>,
    shown_page: RefCell<Option<ScreenPage>>,
    /// The guest has the keyboard.
    grabbed: Cell<bool>,
    /// The window whose system shortcuts go to the guest while grabbed.
    inhibited: RefCell<Option<gdk::Toplevel>>,
    keys: RefCell<model::Keys>,
    mouse: RefCell<model::Mouse>,
}

impl Screen {
    pub fn new(vm: &VmInfo, vms: &Rc<Vms>) -> Rc<Self> {
        let title = stallo::printable(&vm.name, 64);
        let spinner = adw::Spinner::builder()
            .width_request(32)
            .height_request(32)
            .build();
        let action = gtk::Button::builder()
            .halign(gtk::Align::Center)
            .css_classes(["pill", "suggested-action"])
            .build();
        // The raw error, for a bug report; the page says it plainly.
        let reason = gtk::Label::builder()
            .wrap(true)
            .xalign(0.0)
            .selectable(true)
            .margin_top(12)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .build();
        reason.set_wrap_mode(gtk::pango::WrapMode::WordChar);
        let details = adw::ExpanderRow::builder().title("Details").build();
        details.add_row(&reason);
        let details_list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .css_classes(["boxed-list"])
            .build();
        details_list.append(&details);
        let content = gtk::Box::new(gtk::Orientation::Vertical, 24);
        content.append(&spinner);
        content.append(&action);
        content.append(&details_list);
        let status = adw::StatusPage::builder().child(&content).build();

        let picture = gtk::Picture::builder()
            .can_shrink(true)
            .content_fit(gtk::ContentFit::Contain)
            .focusable(true)
            .hexpand(true)
            .vexpand(true)
            .build();
        picture.update_property(&[gtk::accessible::Property::Label(&format!(
            "Screen of {title}"
        ))]);
        let scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::External)
            .vscrollbar_policy(gtk::PolicyType::External)
            .child(&picture)
            .build();

        let strip_hint = gtk::Label::builder()
            .label(model::RELEASE_HINT)
            .css_classes(["caption", "dim-label"])
            .build();
        let release = gtk::Button::builder()
            .label("Release Keyboard")
            .css_classes(["flat"])
            .build();
        let leave = gtk::Button::builder()
            .icon_name("view-restore-symbolic")
            .tooltip_text("Leave Fullscreen (F11)")
            .css_classes(["flat", "circular"])
            .build();
        leave.update_property(&[gtk::accessible::Property::Label("Leave Fullscreen")]);
        let line = gtk::Box::builder()
            .spacing(12)
            .halign(gtk::Align::Center)
            .hexpand(true)
            .margin_top(6)
            .margin_bottom(6)
            .build();
        line.append(&gtk::Label::new(Some(&format!("Guest screen: {title}"))));
        line.append(&strip_hint);
        line.append(&release);
        line.append(&leave);
        let strip = gtk::Box::builder().css_classes(["osd"]).build();
        strip.append(&line);
        // A card: the guest's pixels always sit in a visible frame.
        let frame = adw::Bin::builder()
            .child(&scroller)
            .overflow(gtk::Overflow::Hidden)
            .margin_top(12)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .css_classes(["card"])
            .build();
        let holder = adw::Bin::builder().child(&frame).vexpand(true).build();

        let banner = adw::Banner::builder()
            .title("Agent control is on, so the screen starts view-only")
            .button_label("Allow Input")
            .use_markup(false)
            .build();
        let ctrl_alt_del = gtk::Button::builder()
            .label("Ctrl+Alt+Del")
            .tooltip_text("Send Ctrl+Alt+Del")
            .build();
        let hint = gtk::Label::builder()
            .css_classes(["caption", "dim-label"])
            .build();
        hint.set_ellipsize(gtk::pango::EllipsizeMode::End);
        let view_only = gtk::ToggleButton::builder()
            .label("View Only")
            .tooltip_text("Show the screen without sending keys or clicks")
            .build();
        let actual_size = gtk::ToggleButton::builder()
            .icon_name("zoom-original-symbolic")
            .tooltip_text("Actual Size")
            .build();
        actual_size.update_property(&[gtk::accessible::Property::Label("Actual Size")]);
        let fullscreen = gtk::Button::builder()
            .icon_name("view-fullscreen-symbolic")
            .tooltip_text("Fullscreen (F11)")
            .build();
        fullscreen.update_property(&[gtk::accessible::Property::Label("Fullscreen")]);
        let bar = gtk::ActionBar::new();
        bar.pack_start(&ctrl_alt_del);
        bar.set_center_widget(Some(&hint));
        bar.pack_end(&fullscreen);
        bar.pack_end(&actual_size);
        bar.pack_end(&view_only);
        let live = gtk::Box::new(gtk::Orientation::Vertical, 0);
        live.append(&banner);
        live.append(&holder);
        live.append(&bar);

        let root = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::Crossfade)
            .build();
        root.add_named(&status, Some("status"));
        root.add_named(&live, Some("live"));

        let screen = Rc::new(Self {
            name: vm.name.clone(),
            vms: Rc::downgrade(vms),
            root,
            status,
            spinner,
            reason,
            details_list,
            action,
            banner,
            holder,
            frame,
            scroller,
            picture,
            hint,
            ctrl_alt_del,
            view_only,
            actual_size,
            strip,
            strip_hint,
            release,
            full: RefCell::default(),
            vm: RefCell::default(),
            details: RefCell::default(),
            blocked: Cell::new(false),
            agent: Cell::new(None),
            wanted: Cell::new(false),
            link: RefCell::new(Link::Idle),
            session: RefCell::default(),
            generation: Cell::new(0),
            texture: RefCell::default(),
            shown: Cell::new(None),
            shown_page: RefCell::default(),
            grabbed: Cell::new(false),
            inhibited: RefCell::default(),
            keys: RefCell::default(),
            mouse: RefCell::default(),
        });
        screen.connect_signals(&leave, &fullscreen);
        screen
    }

    /// Weak: widgets of this tab must not keep it alive.
    fn connect_signals(self: &Rc<Self>, leave: &gtk::Button, fullscreen: &gtk::Button) {
        let weak = || Rc::downgrade(self);
        let s = weak();
        self.action.connect_clicked(move |_| {
            if let Some(s) = s.upgrade() {
                s.act();
            }
        });
        let s = weak();
        self.banner.connect_button_clicked(move |_| {
            if let Some(s) = s.upgrade() {
                s.view_only.set_active(false);
            }
        });
        let s = weak();
        self.ctrl_alt_del.connect_clicked(move |_| {
            if let Some(s) = s.upgrade().filter(|s| s.input_allowed()) {
                for input in model::ctrl_alt_del() {
                    s.send(input);
                }
            }
        });
        let s = weak();
        self.view_only.connect_toggled(move |_| {
            if let Some(s) = s.upgrade() {
                // Mid-drag: no button stays held in the guest.
                let up = s.mouse.borrow_mut().let_go();
                if let Some(input) = up {
                    s.send(input);
                }
                s.ungrab();
                s.show_input();
            }
        });
        let s = weak();
        self.actual_size.connect_toggled(move |b| {
            if let Some(s) = s.upgrade() {
                s.set_actual_size(b.is_active());
            }
        });
        let s = weak();
        fullscreen.connect_clicked(move |_| {
            if let Some(s) = s.upgrade() {
                s.fullscreen();
            }
        });
        let s = weak();
        leave.connect_clicked(move |_| {
            if let Some(s) = s.upgrade() {
                s.leave_fullscreen();
            }
        });
        let s = weak();
        self.release.connect_clicked(move |_| {
            if let Some(s) = s.upgrade() {
                s.ungrab();
            }
        });

        let input = gtk::EventControllerLegacy::new();
        let s = weak();
        input.connect_event(move |_, event| match s.upgrade() {
            Some(s) => s.input(event),
            None => glib::Propagation::Proceed,
        });
        self.picture.add_controller(input);
        // A click or fullscreen hands the guest the keyboard; focus
        // elsewhere takes it back.
        let focus = gtk::EventControllerFocus::new();
        let s = weak();
        focus.connect_leave(move |_| {
            if let Some(s) = s.upgrade() {
                s.ungrab();
            }
        });
        self.picture.add_controller(focus);

        // F11 while the focus is in this tab (local scope) and the screen
        // shows; never under a dialog.
        let s = weak();
        let toggle = gtk::CallbackAction::new(move |_, _| {
            let Some(s) = s.upgrade() else {
                return glib::Propagation::Proceed;
            };
            let dialog = s
                .root
                .root()
                .and_downcast::<adw::ApplicationWindow>()
                .is_some_and(|w| w.visible_dialog().is_some());
            if dialog || !s.root.is_mapped() || s.page() != Some(ScreenPage::Live) {
                return glib::Propagation::Proceed;
            }
            s.fullscreen();
            glib::Propagation::Stop
        });
        let shortcuts = gtk::ShortcutController::new();
        shortcuts.set_scope(gtk::ShortcutScope::Local);
        shortcuts.add_shortcut(gtk::Shortcut::new(
            Some(gtk::KeyvalTrigger::new(
                gdk::Key::F11,
                gdk::ModifierType::empty(),
            )),
            Some(toggle),
        ));
        self.root.add_controller(shortcuts);
    }

    /// The VM as it is now. `blocked`: no actions now.
    pub fn update(self: &Rc<Self>, vm: &VmInfo, details: Option<&VmDetails>, blocked: bool) {
        let before = self.agent.replace(Some(vm.agent_control));
        let view_only = model::view_only(self.view_only.is_active(), before, vm.agent_control);
        self.view_only.set_active(view_only);
        *self.vm.borrow_mut() = Some(vm.clone());
        *self.details.borrow_mut() = details.cloned();
        self.blocked.set(blocked);
        self.sync();
    }

    /// Connects while the tab is on screen, and only then.
    pub fn set_wanted(self: &Rc<Self>, on: bool) {
        if self.wanted.replace(on) != on {
            self.sync();
        }
    }

    /// Connects or disconnects as the VM and the tab ask, then shows it.
    fn sync(self: &Rc<Self>) {
        let socket = self
            .vm
            .borrow()
            .as_ref()
            .and_then(|vm| model::screen_socket(vm, self.details.borrow().as_ref()));
        match socket {
            Some(socket) if self.wanted.get() => {
                if *self.link.borrow() == Link::Idle {
                    self.connect(socket);
                }
            }
            _ => self.disconnect(),
        }
        self.show();
    }

    fn disconnect(&self) {
        self.generation.set(self.generation.get() + 1);
        self.session.take();
        *self.link.borrow_mut() = Link::Idle;
    }

    fn connect(self: &Rc<Self>, socket: PathBuf) {
        let generation = self.generation.get() + 1;
        self.generation.set(generation);
        *self.link.borrow_mut() = Link::Connecting;
        // A new session: nothing held, nothing half scrolled.
        self.mouse.replace(model::Mouse::default());
        self.shown.set(None);
        self.texture.take();
        self.picture.set_paintable(None::<&gdk::Paintable>);
        let s = Rc::downgrade(self);
        let current = move || s.upgrade().filter(|s| s.generation.get() == generation);
        glib::spawn_future_local(async move {
            let got = client::spawn(async move { Session::connect(&socket).await }).await;
            let Some(screen) = current() else {
                return; // the session, if any, drops here
            };
            let mut frames = match got {
                Ok(Ok((session, frames))) => {
                    *screen.session.borrow_mut() = Some(session);
                    frames
                }
                Ok(Err(e)) => return screen.end(&format!("{e:#}")),
                Err(e) => return screen.end(&e.to_string()),
            };
            drop(screen);
            loop {
                let changed = frames.changed().await;
                let Some(screen) = current() else {
                    return;
                };
                if changed.is_err() {
                    let why = screen
                        .session
                        .borrow()
                        .as_ref()
                        .and_then(Session::end_reason)
                        .unwrap_or("closed")
                        .to_owned();
                    return screen.end(&why);
                }
                let frame = frames.borrow_and_update().clone();
                screen.draw(frame);
            }
        });
    }

    /// The session ended by itself.
    fn end(&self, why: &str) {
        self.generation.set(self.generation.get() + 1);
        self.session.take();
        *self.link.borrow_mut() = Link::Ended(why.to_owned());
        self.show();
        // Often the VM stopped: ask now rather than show this until the
        // next list.
        if let Some(v) = self.vms.upgrade() {
            v.poll_soon();
        }
    }

    fn draw(&self, frame: Frame) {
        let (w, h) = (frame.width, frame.height);
        let partial = model::partial_redraw(self.shown.get(), frame.serial, (w, h));
        let bytes = glib::Bytes::from_owned(Pixels(frame.pixels));
        let mut builder = gdk::MemoryTextureBuilder::new()
            .set_bytes(Some(&bytes))
            .set_width(w.into())
            .set_height(h.into())
            .set_stride(usize::from(w) * 4)
            .set_format(gdk::MemoryFormat::B8g8r8x8);
        let old = self.texture.borrow().clone();
        if let (true, Some(old)) = (partial, old) {
            let rects: Vec<_> = frame
                .damage
                .iter()
                .map(|r| {
                    gtk::cairo::RectangleInt::new(r.x.into(), r.y.into(), r.w.into(), r.h.into())
                })
                .collect();
            builder = builder
                .set_update_texture(Some(&old))
                .set_update_region(Some(&gtk::cairo::Region::create_rectangles(&rects)));
        }
        let texture = builder.build();
        self.picture.set_paintable(Some(&texture));
        *self.texture.borrow_mut() = Some(texture);
        self.shown.set(Some((frame.serial, w, h)));
        if *self.link.borrow() == Link::Connecting {
            *self.link.borrow_mut() = Link::Live;
            self.show();
        }
    }

    fn page(&self) -> Option<ScreenPage> {
        let vm = self.vm.borrow();
        Some(model::screen_page(
            vm.as_ref()?,
            self.details.borrow().as_ref(),
            &self.link.borrow(),
        ))
    }

    fn show(&self) {
        let Some(page) = self.page() else {
            return;
        };
        if page != ScreenPage::Live {
            self.leave_fullscreen();
            self.ungrab();
        }
        let sensitive = match &page {
            ScreenPage::Stopped => self
                .vm
                .borrow()
                .as_ref()
                .is_some_and(|vm| model::actions(vm, self.blocked.get()).start),
            ScreenPage::Off { .. } => !self.blocked.get(),
            _ => true,
        };
        self.action.set_sensitive(sensitive);
        self.show_input();
        if self.shown_page.borrow().as_ref() == Some(&page) {
            return;
        }
        if page == ScreenPage::Live {
            self.root.set_visible_child_name("live");
        } else {
            let s = model::screen_status(&page);
            self.status.set_icon_name(s.icon);
            self.status.set_title(s.title);
            self.status
                .set_description(Some(s.description).filter(|d| !d.is_empty()));
            self.spinner.set_visible(page == ScreenPage::Connecting);
            if let ScreenPage::Ended(why) = &page {
                self.reason.set_label(why);
            }
            self.details_list
                .set_visible(matches!(page, ScreenPage::Ended(_)));
            self.action.set_visible(s.button.is_some());
            self.action.set_label(s.button.unwrap_or_default());
            // One suggested button at a time: not beside the header's Start.
            let header = self
                .vm
                .borrow()
                .as_ref()
                .is_some_and(|vm| model::actions(vm, false).suggested);
            if header {
                self.action.remove_css_class("suggested-action");
            } else {
                self.action.add_css_class("suggested-action");
            }
            self.root.set_visible_child_name("status");
        }
        *self.shown_page.borrow_mut() = Some(page);
    }

    /// The hints, the banner and Ctrl+Alt+Del, for whether input goes to
    /// the guest now.
    fn show_input(&self) {
        let (allowed, grabbed) = (self.input_allowed(), self.grabbed.get());
        self.hint.set_label(if grabbed {
            model::RELEASE_HINT
        } else {
            model::GRAB_HINT
        });
        self.hint.set_visible(allowed);
        self.strip_hint.set_visible(grabbed);
        self.release.set_visible(grabbed);
        self.ctrl_alt_del.set_sensitive(allowed);
        self.banner
            .set_revealed(self.view_only.is_active() && self.agent.get() == Some(true));
    }

    /// The button on a status page.
    fn act(self: &Rc<Self>) {
        let (Some(page), Some(v)) = (self.page(), self.vms.upgrade()) else {
            return;
        };
        let Some(vm) = self.vm.borrow().clone() else {
            return;
        };
        match page {
            ScreenPage::Stopped => v.ask(Op::Start, &self.name),
            ScreenPage::Off {
                on: false,
                restart: false,
            } => v.run(Action::LiveScreen(true), &self.name),
            ScreenPage::Off {
                on: false,
                restart: true,
            } => self.ask_live_screen(&v, &vm),
            ScreenPage::Off { on: true, .. } => v.confirm(
                &model::confirm_restart(&vm),
                Action::Restart { live_screen: false },
                &self.name,
            ),
            ScreenPage::Ended(_) => {
                *self.link.borrow_mut() = Link::Idle;
                self.sync();
            }
            ScreenPage::Connecting | ScreenPage::Live => {}
        }
    }

    /// Restart now, or turn it on for the next start; Cancel by default.
    fn ask_live_screen(&self, v: &Rc<Vms>, vm: &VmInfo) {
        let c = model::confirm_live_screen(vm);
        let dialog = adw::AlertDialog::builder()
            .heading(&c.heading)
            .heading_use_markup(false)
            .body(&c.body)
            .body_use_markup(false)
            .build();
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("later", model::LATER);
        dialog.add_response("restart", c.button);
        dialog.set_response_appearance("restart", adw::ResponseAppearance::Destructive);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        let (weak, name) = (Rc::downgrade(v), self.name.clone());
        dialog.connect_response(None, move |_, response| {
            let action = match response {
                "later" => Action::LiveScreen(true),
                "restart" => Action::Restart { live_screen: true },
                _ => return,
            };
            if let Some(v) = weak.upgrade() {
                v.run(action, &name);
            }
        });
        dialog.present(Some(&self.root));
    }

    fn input_allowed(&self) -> bool {
        *self.link.borrow() == Link::Live
            && !self.view_only.is_active()
            && self.session.borrow().is_some()
    }

    fn send(&self, input: Input) {
        if let Some(s) = self.session.borrow().as_ref() {
            s.send(input);
        }
    }

    /// Hands the guest the keyboard, system shortcuts included. `event`
    /// is the click that asked for it, if any (Wayland wants one).
    fn grab(&self, event: Option<&gdk::Event>) {
        if self.grabbed.get() || !self.input_allowed() {
            return;
        }
        self.grabbed.set(true);
        let toplevel = self
            .picture
            .native()
            .and_then(|n| n.surface())
            .and_then(|s| s.downcast::<gdk::Toplevel>().ok());
        if let Some(t) = toplevel {
            t.inhibit_system_shortcuts(event);
            *self.inhibited.borrow_mut() = Some(t);
        }
        self.show_input();
    }

    /// Takes the keyboard back; the guest lets go of every key it holds.
    fn ungrab(&self) {
        if !self.grabbed.replace(false) {
            return;
        }
        let held = self.keys.borrow_mut().release_all();
        for input in held {
            self.send(input);
        }
        if let Some(t) = self.inhibited.take() {
            t.restore_system_shortcuts();
        }
        self.show_input();
    }

    /// Keys while grabbed, the pointer and the wheel, for the guest.
    fn input(&self, event: &gdk::Event) -> glib::Propagation {
        use gdk::EventType as T;
        if !self.input_allowed() {
            return glib::Propagation::Proceed;
        }
        let kind = event.event_type();
        match kind {
            T::KeyPress | T::KeyRelease => {
                let Some(key) = event.downcast_ref::<gdk::KeyEvent>() else {
                    return glib::Propagation::Proceed;
                };
                if !self.grabbed.get() {
                    return glib::Propagation::Proceed;
                }
                let (keycode, keysym) = (key.keycode(), key.keyval().into_glib());
                if kind == T::KeyRelease {
                    let up = self.keys.borrow_mut().release(keycode, keysym);
                    if let Some(input) = up {
                        self.send(input);
                    }
                    return glib::Propagation::Stop;
                }
                let state = event.modifier_state();
                let press = self.keys.borrow_mut().press(
                    keycode,
                    keysym,
                    state.contains(gdk::ModifierType::CONTROL_MASK),
                    state.contains(gdk::ModifierType::ALT_MASK),
                );
                match press {
                    KeyPress::Send(input) => self.send(input),
                    KeyPress::Release(ups) => {
                        for input in ups {
                            self.send(input);
                        }
                        self.ungrab();
                    }
                }
                glib::Propagation::Stop
            }
            T::ButtonPress | T::ButtonRelease => {
                let bit = event
                    .downcast_ref::<gdk::ButtonEvent>()
                    .and_then(|b| model::button_bit(b.button()));
                let (Some(bit), Some((x, y, inside))) = (bit, self.point(event)) else {
                    return glib::Propagation::Proceed;
                };
                let press = kind == T::ButtonPress;
                if press {
                    self.grab(Some(event));
                    self.picture.grab_focus();
                    // A click on the letterbox only focuses.
                    if !inside {
                        return glib::Propagation::Stop;
                    }
                }
                let input = self.mouse.borrow_mut().button(x, y, bit, press);
                if let Some(input) = input {
                    self.send(input);
                }
                glib::Propagation::Stop
            }
            T::MotionNotify => {
                if let Some((x, y, inside)) = self.point(event) {
                    let input = self.mouse.borrow_mut().moved(x, y, inside);
                    if let Some(input) = input {
                        self.send(input);
                    }
                }
                glib::Propagation::Stop
            }
            T::Scroll => {
                let Some(scroll) = event.downcast_ref::<gdk::ScrollEvent>() else {
                    return glib::Propagation::Proceed;
                };
                let delta = match scroll.direction() {
                    gdk::ScrollDirection::Up => -1.0,
                    gdk::ScrollDirection::Down => 1.0,
                    gdk::ScrollDirection::Smooth => match scroll.unit() {
                        gdk::ScrollUnit::Surface => scroll.deltas().1 / model::SCROLL_PIXELS,
                        _ => scroll.deltas().1,
                    },
                    _ => 0.0,
                };
                let clicks = self.mouse.borrow_mut().scroll(delta);
                for input in clicks {
                    self.send(input);
                }
                glib::Propagation::Stop
            }
            _ => glib::Propagation::Proceed,
        }
    }

    /// The framebuffer pixel under a pointer event, and whether it is on
    /// the screen rather than the letterbox.
    fn point(&self, event: &gdk::Event) -> Option<(u16, u16, bool)> {
        // Events carry surface coordinates.
        let (ex, ey) = event.position()?;
        let native = self.picture.native()?;
        let (sx, sy) = native.surface_transform();
        let p = native.compute_point(
            &self.picture,
            &gtk::graphene::Point::new((ex - sx) as f32, (ey - sy) as f32),
        )?;
        let (_, w, h) = self.shown.get()?;
        let widget = (
            f64::from(self.picture.width()),
            f64::from(self.picture.height()),
        );
        let place = model::placement(widget, (w, h), !self.actual_size.is_active());
        Some(model::to_guest(place, (w, h), p.x().into(), p.y().into()))
    }

    /// Fit (the default) or 1:1, with scrollbars when it does not fit.
    fn set_actual_size(&self, on: bool) {
        self.picture.set_can_shrink(!on);
        self.picture.set_content_fit(if on {
            gtk::ContentFit::ScaleDown
        } else {
            gtk::ContentFit::Contain
        });
        let policy = if on {
            gtk::PolicyType::Automatic
        } else {
            gtk::PolicyType::External
        };
        self.scroller.set_policy(policy, policy);
    }

    /// Moves the framed screen into a fullscreen window of its own,
    /// under the guest strip, and hands the guest the keyboard. Leaves
    /// fullscreen if it is on (F11).
    fn fullscreen(self: &Rc<Self>) {
        if self.full.borrow().is_some() {
            return self.leave_fullscreen();
        }
        let parent = self.root.root().and_downcast::<gtk::Window>();
        self.holder.set_child(None::<&gtk::Widget>);
        let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        content.append(&self.strip);
        content.append(&self.frame);
        let window = adw::Window::builder()
            .title(format!(
                "Guest screen: {}",
                stallo::printable(&self.name, 64)
            ))
            .modal(true)
            .content(&content)
            .build();
        window.set_transient_for(parent.as_ref());
        let s = Rc::downgrade(self);
        window.connect_close_request(move |w| {
            if let Some(s) = s.upgrade() {
                s.restore(w);
            }
            glib::Propagation::Proceed
        });
        // Esc and F11 leave, unless the guest has the keyboard (then they
        // never get here).
        let keys = gtk::EventControllerKey::new();
        let w = window.downgrade();
        keys.connect_key_pressed(move |_, key, _, _| {
            if key != gdk::Key::Escape && key != gdk::Key::F11 {
                return glib::Propagation::Proceed;
            }
            if let Some(w) = w.upgrade() {
                w.close();
            }
            glib::Propagation::Stop
        });
        window.add_controller(keys);
        *self.full.borrow_mut() = Some(window.clone());
        window.fullscreen();
        window.present();
        self.picture.grab_focus();
        self.grab(None);
    }

    fn leave_fullscreen(&self) {
        let window = self.full.borrow().clone();
        if let Some(w) = window {
            w.close();
        }
    }

    /// The fullscreen window closes: the screen goes back into the tab.
    fn restore(&self, window: &adw::Window) {
        self.ungrab();
        self.full.take();
        if let Some(content) = self.frame.parent().and_downcast::<gtk::Box>() {
            content.remove(&self.strip);
            content.remove(&self.frame);
        }
        window.set_content(None::<&gtk::Widget>);
        self.holder.set_child(Some(&self.frame));
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        if let Some(t) = self.inhibited.get_mut().take() {
            t.restore_system_shortcuts();
        }
        if let Some(w) = self.full.get_mut().take() {
            w.destroy();
        }
    }
}
