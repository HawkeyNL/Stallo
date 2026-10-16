//! stallo-gui: the desktop app for Stallo. It finds the daemon, walks the
//! user through anything that stops it from connecting, and then lists the
//! VMs, starts and stops them, shows their screens, and takes and restores
//! snapshots.

mod client;
mod model;
mod rfb;
mod screen;
mod vms;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use adw::{gio, glib, gtk};
use libadwaita as adw;

use model::{Onboarding, View};

/// Also the name of the desktop file, the icon and the AppStream metadata.
const APP_ID: &str = "io.github.hawkeynl.Stallo";

/// systemd's `Manager.StartUnit` on the system bus: destination, object,
/// interface and method.
const START_UNIT: [&str; 4] = [
    "org.freedesktop.systemd1",
    "/org/freedesktop/systemd1",
    "org.freedesktop.systemd1.Manager",
    "StartUnit",
];
/// Let polkit ask for a password; the user may take a while to type it.
const START_FLAGS: gio::DBusCallFlags = gio::DBusCallFlags::ALLOW_INTERACTIVE_AUTHORIZATION;
const START_TIMEOUT_MS: i32 = 120_000;

fn start_unit_args() -> glib::Variant {
    ("stallod.service", "replace").to_variant()
}

/// Text that is not ours to trust: no markup. Not selectable: as the only
/// focusable widget on a page, a selectable label trips a GTK critical
/// (gtk_widget_is_ancestor) once accessibility is active.
fn plain_label(text: &str) -> gtk::Label {
    gtk::Label::builder()
        .label(text)
        .wrap(true)
        .justify(gtk::Justification::Center)
        .css_classes(["dim-label"])
        .build()
}

/// POSIX shell quoting, for commands the user copies.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn main() -> glib::ExitCode {
    // RUST_LOG=error|warn|info|debug|trace (default warn), on stderr.
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|l| l.parse().ok())
        .unwrap_or(tracing::Level::WARN);
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .init();
    let mut flags = gio::ApplicationFlags::empty();
    if !model::single_instance(std::env::var_os("STALLO_SOCKET").is_some()) {
        flags |= gio::ApplicationFlags::NON_UNIQUE;
    }
    let app = adw::Application::builder()
        .application_id(APP_ID)
        .flags(flags)
        .build();
    app.connect_activate(|app| {
        if let Some(window) = app.active_window() {
            window.present();
            return;
        }
        Ui::new(app);
    });
    app.run()
}

struct Ui {
    window: adw::ApplicationWindow,
    view: adw::ToolbarView,
    /// Hidden while connected: the split view brings its own.
    header: adw::HeaderBar,
    banner: adw::Banner,
    toasts: adw::ToastOverlay,
    /// `None` until the first probe is back.
    state: RefCell<Option<View>>,
    /// A probe is in flight; do not start another.
    busy: Cell<bool>,
    timer: RefCell<Option<glib::SourceId>>,
    /// The connected page, while it is shown.
    vms: RefCell<Option<Rc<vms::Vms>>>,
}

impl Ui {
    fn new(app: &adw::Application) -> Rc<Self> {
        let banner = adw::Banner::new("Reconnecting…");
        let connecting = adw::StatusPage::builder()
            .title("Connecting to Stallo")
            .child(&adw::Spinner::new())
            .build();
        let view = adw::ToolbarView::builder().content(&connecting).build();
        let header = adw::HeaderBar::new();
        view.add_top_bar(&header);
        view.add_top_bar(&banner);
        let toasts = adw::ToastOverlay::new();
        toasts.set_child(Some(&view));
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("Stallo")
            .default_width(900)
            .default_height(600)
            .content(&toasts)
            .build();
        let css = gtk::CssProvider::new();
        css.load_from_string(&[vms::CSS, screen::CSS].join("\n"));
        gtk::style_context_add_provider_for_display(
            &WidgetExt::display(&window),
            &css,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
        let ui = Rc::new(Self {
            window,
            view,
            header,
            banner,
            toasts,
            state: RefCell::new(None),
            busy: Cell::new(false),
            timer: RefCell::new(None),
            vms: RefCell::new(None),
        });
        // ponytail: these closures keep `ui` alive for the process lifetime;
        // fine with one window. Use weak refs if there are ever several.
        let u = ui.clone();
        ui.window.connect_is_active_notify(move |w| {
            if w.is_active() {
                u.probe();
            }
        });
        let u = ui.clone();
        ui.window
            .connect_notify_local(Some("is-suspended"), move |_, _| u.reschedule());
        let u = ui.clone();
        ui.window.connect_map(move |_| u.reschedule());
        let u = ui.clone();
        ui.window.connect_unmap(move |_| u.reschedule());
        ui.window.present();
        ui.probe();
        ui
    }

    fn probe(self: &Rc<Self>) {
        if self.busy.replace(true) {
            return;
        }
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let probed = client::spawn(async { model::onboarding(&client::probe().await) }).await;
            ui.busy.set(false);
            if let Ok(probed) = probed {
                ui.apply(probed);
            }
        });
    }

    fn apply(self: &Rc<Self>, probed: Onboarding) {
        let old = self.state.borrow().clone();
        let (view, back) = match &old {
            Some(v) => v.next(probed),
            None => (
                View {
                    page: probed,
                    reconnecting: false,
                },
                false,
            ),
        };
        if old.as_ref().map(|v| &v.page) != Some(&view.page) {
            if let Some(vms) = self.vms.take() {
                vms.set_active(false);
                // Nothing but requests in flight may keep the old page,
                // and none outlives its time limit.
                #[cfg(debug_assertions)]
                {
                    let old = Rc::downgrade(&vms);
                    glib::timeout_add_local_once(
                        model::SNAP_LIMIT + client::READ_TIMEOUT,
                        move || assert!(old.upgrade().is_none(), "a replaced page leaked"),
                    );
                }
            }
            self.header
                .set_visible(!matches!(view.page, Onboarding::Connected { .. }));
            self.view.set_content(Some(&self.page(&view.page)));
        }
        self.banner.set_revealed(view.reconnecting);
        if back {
            self.toast("Connected to Stallo again");
        }
        *self.state.borrow_mut() = Some(view);
        self.reschedule();
    }

    /// Starts or stops the [`model::POLL`] timer and the VM polls.
    fn reschedule(self: &Rc<Self>) {
        let visible = self.window.is_mapped() && !self.window.is_suspended();
        let state = self.state.borrow().clone();
        if let Some(vms) = self.vms.borrow().as_ref() {
            vms.set_online(state.as_ref().is_some_and(|v| !v.reconnecting));
            vms.set_active(state.as_ref().is_some_and(|v| v.polls_vms(visible)));
        }
        let want = state.as_ref().map_or(visible, |v| v.polls(visible));
        let mut timer = self.timer.borrow_mut();
        if want && timer.is_none() {
            let ui = self.clone();
            *timer = Some(glib::timeout_add_local(model::POLL, move || {
                ui.probe();
                glib::ControlFlow::Continue
            }));
        } else if let Some(t) = timer.take_if(|_| !want) {
            t.remove();
        }
    }

    fn toast(&self, text: &str) {
        let toast = adw::Toast::builder().title(text).use_markup(false).build();
        self.toasts.add_toast(toast);
    }

    /// A toast for an error. Its Details button shows the whole text,
    /// which a toast would cut off, in a dialog.
    fn fail(&self, f: &model::Failure) {
        let toast = adw::Toast::builder()
            .title(&f.title)
            .use_markup(false)
            .build();
        if let Some(details) = f.details.clone() {
            toast.set_button_label(Some("Details"));
            let (window, heading) = (self.window.downgrade(), f.title.clone());
            toast.connect_button_clicked(move |_| {
                // Selectable, so it can be copied into a bug report. The
                // Close button keeps it from being the only focusable widget.
                let text = gtk::Label::builder()
                    .label(&details)
                    .use_markup(false)
                    .selectable(true)
                    .wrap(true)
                    .xalign(0.0)
                    .build();
                text.set_wrap_mode(gtk::pango::WrapMode::WordChar);
                let scroll = gtk::ScrolledWindow::builder()
                    .hscrollbar_policy(gtk::PolicyType::Never)
                    .propagate_natural_height(true)
                    .max_content_height(300)
                    .child(&text)
                    .build();
                let dialog = adw::AlertDialog::builder()
                    .heading(&heading)
                    .heading_use_markup(false)
                    .extra_child(&scroll)
                    .build();
                dialog.add_response("close", "Close");
                dialog.present(window.upgrade().as_ref());
            });
        }
        self.toasts.add_toast(toast);
    }

    fn page(self: &Rc<Self>, page: &Onboarding) -> gtk::Widget {
        // Descriptions are Pango markup: only fixed text goes there. Anything
        // else goes into plain labels or rows with markup off.
        let status = adw::StatusPage::new();
        let content = gtk::Box::new(gtk::Orientation::Vertical, 24);
        let (icon, title, description) = match page {
            Onboarding::NoKvm => (
                "computer-fail-symbolic",
                "Virtualization Is Not Available",
                "Stallo needs KVM, but this computer has no /dev/kvm. Turn on virtualization (Intel VT-x or AMD-V) in the firmware settings and check that the kvm module is loaded.",
            ),
            Onboarding::DaemonStopped => {
                let start = gtk::Button::builder()
                    .label("Start Stallo Service")
                    .halign(gtk::Align::Center)
                    .css_classes(["pill", "suggested-action"])
                    .build();
                let ui = self.clone();
                start.connect_clicked(move |b| ui.start_service(b));
                content.append(&start);
                content.append(&self.commands(&["systemctl start stallod"]));
                (
                    "system-run-symbolic",
                    "Stallo Is Not Running",
                    "Start the Stallo service to manage virtual machines. You may be asked for your password.",
                )
            }
            Onboarding::NotInGroup => {
                content.append(&self.commands(&["sudo usermod -aG stallo \"$USER\""]));
                (
                    "system-users-symbolic",
                    "Join the Stallo Group",
                    "Your account may not use Stallo yet. Members of the stallo group have full control over all virtual machines, and so does every program they run, including AI agents that can run commands. Only add your account if you accept that. Then log out and back in.",
                )
            }
            Onboarding::NeedsRelogin => (
                "system-log-out-symbolic",
                "Log Out to Finish",
                "Your account is in the stallo group, but this session started before it was added. Log out and back in, then open Stallo again.",
            ),
            Onboarding::TwoDaemons { dev } => {
                content.append(&self.commands(&[
                    "STALLO_SOCKET=/run/stallo/api.sock stallo-gui",
                    &format!(
                        "STALLO_SOCKET={} stallo-gui",
                        sh_quote(&dev.to_string_lossy())
                    ),
                ]));
                (
                    "dialog-warning-symbolic",
                    "Two Stallo Daemons Are Running",
                    "Both the Stallo service and a dev-mode daemon are running, and Stallo will not guess which one you mean. Stop one of them, or start the app with STALLO_SOCKET set to the socket to use.",
                )
            }
            Onboarding::SocketDown { socket } => {
                content.append(&plain_label(&socket.to_string_lossy()));
                (
                    "network-offline-symbolic",
                    "Nothing Answers on the Chosen Socket",
                    "STALLO_SOCKET points at the socket below, but no Stallo daemon answers there. Start the daemon that serves it, or open Stallo without STALLO_SOCKET.",
                )
            }
            Onboarding::Unreachable(error) => {
                content.append(&plain_label(&stallo::printable(error, 300)));
                (
                    "network-error-symbolic",
                    "Stallo Is Not Responding",
                    "Trying again every few seconds.",
                )
            }
            Onboarding::Connected { socket } => {
                let vms = vms::Vms::new(self, socket.clone());
                let root = vms.root.clone().upcast();
                *self.vms.borrow_mut() = Some(vms);
                return root;
            }
        };
        status.set_icon_name(Some(icon));
        status.set_title(title);
        status.set_description(Some(description));
        if content.first_child().is_some() {
            status.set_child(Some(&content));
        }
        status.upcast()
    }

    /// Commands to run in a terminal, each with a copy button.
    fn commands(self: &Rc<Self>, commands: &[&str]) -> gtk::ListBox {
        let list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .css_classes(["boxed-list"])
            .build();
        for command in commands {
            let row = adw::ActionRow::builder()
                .title(*command)
                .use_markup(false)
                .title_selectable(true)
                .css_classes(["monospace"])
                .build();
            let copy = gtk::Button::builder()
                .icon_name("edit-copy-symbolic")
                .tooltip_text("Copy")
                .valign(gtk::Align::Center)
                .css_classes(["flat"])
                .build();
            let (ui, command) = (self.clone(), command.to_string());
            copy.connect_clicked(move |b| {
                b.clipboard().set_text(&command);
                ui.toast("Copied to clipboard");
            });
            row.add_suffix(&copy);
            list.append(&row);
        }
        list
    }

    /// Asks systemd to start the daemon; polkit decides and may ask for a
    /// password. No shell, no pkexec.
    fn start_service(self: &Rc<Self>, button: &gtk::Button) {
        button.set_sensitive(false);
        let (ui, button) = (self.clone(), button.clone());
        glib::spawn_future_local(async move {
            let result = async {
                let bus = gio::bus_get_future(gio::BusType::System).await?;
                let [dest, path, iface, method] = START_UNIT;
                bus.call_future(
                    Some(dest),
                    path,
                    iface,
                    method,
                    Some(&start_unit_args()),
                    glib::VariantTy::new("(o)").ok(),
                    START_FLAGS,
                    START_TIMEOUT_MS,
                )
                .await
            }
            .await;
            button.set_sensitive(true);
            if let Err(e) = result {
                ui.toast(&format!(
                    "Could not start the Stallo service: {}",
                    stallo::printable(e.message(), 200)
                ));
            }
            ui.probe();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_unit_call() {
        assert_eq!(
            start_unit_args().to_string(),
            "('stallod.service', 'replace')"
        );
        assert_eq!(start_unit_args().type_().as_str(), "(ss)");
        assert!(START_FLAGS.contains(gio::DBusCallFlags::ALLOW_INTERACTIVE_AUTHORIZATION));
        assert!(gio::dbus_is_name(START_UNIT[0]));
        assert!(glib::Variant::is_object_path(START_UNIT[1]));
        assert!(gio::dbus_is_interface_name(START_UNIT[2]));
        assert!(gio::dbus_is_member_name(START_UNIT[3]));
    }

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("/run/user/1000/x"), "'/run/user/1000/x'");
        assert_eq!(sh_quote("a'b"), r"'a'\''b'");
    }
}
