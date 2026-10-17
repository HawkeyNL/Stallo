//! Dev only (feature `shots`): `stallo-gui --screenshot <dir>` renders the
//! real pages against a fake daemon (see [`fake`]) and saves each as
//! `<page>-<light|dark>.png`. Run it through `packaging/dev/shots.sh`,
//! which gives it a private broadway display. It binds its fake sockets
//! in the working directory.

mod fake;

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;
use adw::{glib, gtk};
use gtk::{graphene, gsk};
use libadwaita as adw;

use super::{SCREEN, SNAPSHOTS, Vms};
use crate::Ui;

const WIDTH: i32 = 1100;
const HEIGHT: i32 = 720;

/// `Some` when started as `stallo-gui --screenshot <dir>`.
pub fn run() -> Option<glib::ExitCode> {
    let mut args = std::env::args_os().skip(1);
    if args.next()? != "--screenshot" {
        return None;
    }
    let Some(out) = args.next().map(PathBuf::from) else {
        eprintln!("usage: stallo-gui --screenshot <dir>");
        return Some(glib::ExitCode::FAILURE);
    };
    Some(match shoot_all(&out) {
        Ok(()) => glib::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("screenshots failed: {e:#}");
            glib::ExitCode::FAILURE
        }
    })
}

fn shoot_all(out: &Path) -> anyhow::Result<()> {
    adw::init()?;
    // Shots of finished states, not of transitions half way.
    if let Some(settings) = gtk::Settings::default() {
        settings.set_gtk_enable_animations(false);
    }
    std::fs::create_dir_all(out)?;
    let (full, empty) = (PathBuf::from("stallod.sock"), PathBuf::from("empty.sock"));
    for socket in [&full, &empty, &PathBuf::from(fake::VNC_SOCKET)] {
        let _ = std::fs::remove_file(socket);
    }
    fake::daemon(&full, fake::vms())?;
    fake::daemon(&empty, serde_json::json!([]))?;
    fake::screen(fake::VNC_SOCKET.as_ref())?;

    let ui = ui();
    let main = glib::MainLoop::new(None, false);
    let result = Rc::new(RefCell::new(Ok(())));
    let (m, r, out) = (main.clone(), result.clone(), out.to_owned());
    glib::spawn_future_local(async move {
        *r.borrow_mut() = script(&ui, &out, full, empty).await;
        m.quit();
    });
    main.run();
    result.replace(Ok(()))
}

/// The window as `Ui::new` builds it, minus the probe: nothing here may
/// reach a real daemon. `busy` stays set, so no probe ever starts.
fn ui() -> Rc<Ui> {
    let banner = adw::Banner::new("Reconnecting…");
    let view = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    header.set_visible(false);
    view.add_top_bar(&header);
    view.add_top_bar(&banner);
    let toasts = adw::ToastOverlay::new();
    toasts.set_child(Some(&view));
    // Broadway's screen is 1024x768 with no browser attached; a minimum
    // size is not clamped to it.
    toasts.set_size_request(WIDTH, HEIGHT);
    let window = adw::ApplicationWindow::builder()
        .title("Stallo")
        .default_width(WIDTH)
        .default_height(HEIGHT)
        .content(&toasts)
        .build();
    let css = gtk::CssProvider::new();
    css.load_from_string(super::CSS);
    gtk::style_context_add_provider_for_display(
        &WidgetExt::display(&window),
        &css,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
    window.present();
    Rc::new(Ui {
        window,
        view,
        header,
        banner,
        toasts,
        state: RefCell::new(None),
        busy: Cell::new(true),
        timer: RefCell::new(None),
        vms: RefCell::new(None),
    })
}

async fn settle(ms: u64) {
    glib::timeout_future(Duration::from_millis(ms)).await;
}

/// Shows the VMs of the fake daemon on `socket`, polling it.
async fn connect(ui: &Rc<Ui>, socket: PathBuf) -> Rc<Vms> {
    if let Some(old) = ui.vms.take() {
        old.set_active(false);
    }
    let vms = Vms::new(ui, socket);
    ui.view.set_content(Some(&vms.root));
    *ui.vms.borrow_mut() = Some(vms.clone());
    vms.set_active(true);
    settle(1500).await;
    vms
}

async fn select(vms: &Rc<Vms>, name: &str) -> anyhow::Result<Rc<super::Detail>> {
    let index = vms.rows.borrow().iter().position(|r| r.name == name);
    let row = index
        .and_then(|i| vms.list.row_at_index(i32::try_from(i).ok()?))
        .ok_or_else(|| anyhow::anyhow!("no VM {name}"))?;
    vms.list.select_row(Some(&row));
    settle(1500).await;
    vms.detail
        .borrow()
        .clone()
        .ok_or_else(|| anyhow::anyhow!("{name} did not open"))
}

async fn tab(detail: &super::Detail, name: &str) {
    detail.tabs.set_visible_child_name(name);
    settle(2000).await;
}

async fn script(ui: &Rc<Ui>, out: &Path, full: PathBuf, empty: PathBuf) -> anyhow::Result<()> {
    let shot = |page: &'static str| shoot(&ui.window, out, page);

    connect(ui, empty).await;
    shot("empty").await?;

    let vms = connect(ui, full).await;
    shot("vm-list").await?;

    let detail = select(&vms, "dev").await?;
    shot("overview").await?;
    tab(&detail, SCREEN).await;
    shot("screen").await?;
    tab(&detail, "files").await;
    shot("files").await?;
    tab(&detail, SNAPSHOTS).await;
    shot("snapshots").await?;

    // Agent control is off for win11: turning it on asks first.
    let detail = select(&vms, "win11").await?;
    shot("overview-installer").await?;
    detail.agent.set_active(true);
    settle(800).await;
    shot("agent-confirm").await?;
    close_dialog(ui).await;

    WidgetExt::activate_action(&vms.root, "vms.new", None)?;
    settle(1500).await;
    shot("create").await?;
    let windows = find_row(ui.window.upcast_ref(), "Windows")
        .ok_or_else(|| anyhow::anyhow!("no Windows image in the New VM dialog"))?;
    ActionRowExt::activate(&windows);
    settle(500).await;
    shot("create-windows").await?;
    close_dialog(ui).await;
    Ok(())
}

async fn close_dialog(ui: &Ui) {
    if let Some(d) = ui.window.visible_dialog() {
        d.force_close();
    }
    settle(500).await;
}

/// The first action row under `w` whose title contains `text`.
fn find_row(w: &gtk::Widget, text: &str) -> Option<adw::ActionRow> {
    if let Some(row) = w.downcast_ref::<adw::ActionRow>()
        && row.title().contains(text)
    {
        return Some(row.clone());
    }
    let mut child = w.first_child();
    while let Some(c) = child {
        if let Some(found) = find_row(&c, text) {
            return Some(found);
        }
        child = c.next_sibling();
    }
    None
}

/// Saves the window as `<page>-light.png` and `<page>-dark.png`.
async fn shoot(window: &adw::ApplicationWindow, out: &Path, page: &str) -> anyhow::Result<()> {
    let style = adw::StyleManager::default();
    for (scheme, name) in [
        (adw::ColorScheme::ForceLight, "light"),
        (adw::ColorScheme::ForceDark, "dark"),
    ] {
        style.set_color_scheme(scheme);
        settle(500).await;
        // ponytail: polls for up to 2 s; the window sometimes draws
        // nothing for a moment after a dialog opens.
        let mut texture = None;
        for _ in 0..20 {
            texture = render(window)?;
            if texture.is_some() {
                break;
            }
            settle(100).await;
        }
        let texture = texture.ok_or_else(|| anyhow::anyhow!("{page}: the window drew nothing"))?;
        let path = out.join(format!("{page}-{name}.png"));
        texture.save_to_png(&path)?;
        println!("{}", path.display());
    }
    Ok(())
}

/// Draws the window offscreen with the cairo renderer; `None` if it drew
/// nothing.
fn render(window: &adw::ApplicationWindow) -> anyhow::Result<Option<gtk::gdk::Texture>> {
    let (w, h) = (window.width() as f32, window.height() as f32);
    let snapshot = gtk::Snapshot::new();
    gtk::WidgetPaintable::new(Some(window)).snapshot(&snapshot, w.into(), h.into());
    let Some(node) = snapshot.to_node() else {
        return Ok(None);
    };
    let renderer = gsk::CairoRenderer::new();
    renderer.realize_for_display(&WidgetExt::display(window))?;
    let texture = renderer.render_texture(&node, Some(&graphene::Rect::new(0.0, 0.0, w, h)));
    renderer.unrealize();
    Ok(Some(texture))
}
