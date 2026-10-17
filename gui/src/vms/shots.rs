//! Dev only (feature `shots`): `stallo-gui --screenshot <dir>` renders the
//! real pages against a fake daemon (see [`fake`]) and saves each as
//! `<page>-<light|dark>.png`. Run it through `packaging/dev/shots.sh`,
//! which gives it a private broadway display and a fresh working
//! directory (`STALLO_SHOTS_DIR`) for its fake sockets.

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
use crate::model::Onboarding;

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
    // The fake sockets go in the working directory: only in one made for
    // them, never in wherever this happens to run.
    let here = std::env::current_dir()?.canonicalize()?;
    let dir = std::env::var_os("STALLO_SHOTS_DIR").map(|d| Path::new(&d).canonicalize());
    anyhow::ensure!(
        matches!(dir, Some(Ok(d)) if d == here),
        "run me through packaging/dev/shots.sh (STALLO_SHOTS_DIR must be the working directory)"
    );
    adw::init()?;
    // Shots of finished states, not of transitions half way.
    if let Some(settings) = gtk::Settings::default() {
        settings.set_gtk_enable_animations(false);
    }
    std::fs::create_dir_all(out)?;
    let (full, empty) = (PathBuf::from("stallod.sock"), PathBuf::from("empty.sock"));
    fake::daemon(&full, fake::vms())?;
    fake::daemon(&empty, serde_json::json!([]))?;
    fake::screen(fake::VNC_SOCKET.as_ref())?;

    // `busy` stays set, so the window never probes: nothing here may reach
    // a real daemon.
    let ui = Ui::build(None);
    ui.busy.set(true);
    ui.window.set_default_size(WIDTH, HEIGHT);
    // Broadway's screen is 1024x768 with no browser attached; a minimum
    // size is not clamped to it.
    ui.toasts.set_size_request(WIDTH, HEIGHT);
    ui.window.present();
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

/// Waits until `done`, for at most 10 s.
async fn wait_until(what: &str, mut done: impl FnMut() -> bool) -> anyhow::Result<()> {
    for _ in 0..200 {
        if done() {
            return Ok(());
        }
        glib::timeout_future(Duration::from_millis(50)).await;
    }
    anyhow::bail!("timed out waiting for {what}")
}

/// Waits for two frames of `window`: what changed is laid out and drawn.
async fn frames(window: &adw::ApplicationWindow) -> anyhow::Result<()> {
    let ticks = Rc::new(Cell::new(0));
    let t = ticks.clone();
    let id = window.add_tick_callback(move |_, _| {
        t.set(t.get() + 1);
        glib::ControlFlow::Continue
    });
    let done = wait_until("a frame", || ticks.get() >= 2).await;
    id.remove();
    done
}

/// Shows the VMs of the fake daemon on `socket`, as connecting to it does.
async fn connect(ui: &Rc<Ui>, socket: PathBuf, vms: bool) -> anyhow::Result<Rc<Vms>> {
    ui.apply(Onboarding::Connected { socket });
    let page = ui.vms.borrow().clone();
    let page = page.ok_or_else(|| anyhow::anyhow!("no VM page"))?;
    wait_until("the VM list and host", || {
        page.meter.is_visible() && page.rows.borrow().is_empty() != vms
    })
    .await?;
    Ok(page)
}

async fn select(vms: &Rc<Vms>, name: &str) -> anyhow::Result<Rc<super::Detail>> {
    let index = vms.rows.borrow().iter().position(|r| r.name == name);
    let row = index
        .and_then(|i| vms.list.row_at_index(i32::try_from(i).ok()?))
        .ok_or_else(|| anyhow::anyhow!("no VM {name}"))?;
    vms.list.select_row(Some(&row));
    let open = || {
        vms.detail
            .borrow()
            .clone()
            .filter(|d| d.name == name && d.details.borrow().is_some())
    };
    wait_until(&format!("{name} to open"), || open().is_some()).await?;
    open().ok_or_else(|| anyhow::anyhow!("{name} closed"))
}

async fn script(ui: &Rc<Ui>, out: &Path, full: PathBuf, empty: PathBuf) -> anyhow::Result<()> {
    let shot = |page: &'static str| shoot(&ui.window, out, page);

    connect(ui, empty, false).await?;
    shot("empty").await?;

    let vms = connect(ui, full, true).await?;
    shot("vm-list").await?;

    let detail = select(&vms, "dev").await?;
    shot("overview").await?;
    detail.tabs.set_visible_child_name(SCREEN);
    let screen = &detail.screen.root;
    wait_until("the live screen", || {
        screen.visible_child_name().as_deref() == Some("live")
    })
    .await?;
    // The frame is decoded and uploaded after the page turns live.
    glib::timeout_future(Duration::from_millis(500)).await;
    shot("screen").await?;
    detail.tabs.set_visible_child_name("files");
    shot("files").await?;
    detail.tabs.set_visible_child_name(SNAPSHOTS);
    let snaps = &detail.snaps_view;
    wait_until("the snapshots", || {
        snaps.visible_child_name().as_deref() == Some("list")
    })
    .await?;
    shot("snapshots").await?;

    // Agent control is off for win11: turning it on asks first.
    let detail = select(&vms, "win11").await?;
    shot("overview-installer").await?;
    detail.agent.set_active(true);
    wait_until("the confirmation", || ui.window.visible_dialog().is_some()).await?;
    shot("agent-confirm").await?;
    close_dialog(ui).await?;

    WidgetExt::activate_action(&vms.root, "vms.new", None)?;
    let windows = || find_row(ui.window.upcast_ref(), "Windows");
    wait_until("the images", || windows().is_some()).await?;
    shot("create").await?;
    let windows = windows().ok_or_else(|| anyhow::anyhow!("no Windows image"))?;
    ActionRowExt::activate(&windows);
    shot("create-windows").await?;
    // Advanced open, scrolled to the bottom.
    let processors = ui
        .window
        .visible_dialog()
        .and_then(|d| find_row(d.upcast_ref(), "Processors"))
        .ok_or_else(|| anyhow::anyhow!("no Processors row"))?;
    if let Some(advanced) = processors
        .ancestor(adw::ExpanderRow::static_type())
        .and_downcast::<adw::ExpanderRow>()
    {
        advanced.set_expanded(true);
    }
    // Again as the expander's animation grows the page.
    if let Some(scroll) = processors
        .ancestor(gtk::ScrolledWindow::static_type())
        .and_downcast::<gtk::ScrolledWindow>()
    {
        for _ in 0..5 {
            glib::timeout_future(Duration::from_millis(200)).await;
            let a = scroll.vadjustment();
            a.set_value(a.upper() - a.page_size());
        }
    }
    shot("create-windows-advanced").await?;
    close_dialog(ui).await
}

async fn close_dialog(ui: &Ui) -> anyhow::Result<()> {
    if let Some(d) = ui.window.visible_dialog() {
        d.force_close();
    }
    wait_until("the dialog to close", || {
        ui.window.visible_dialog().is_none()
    })
    .await
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
        frames(window).await?;
        // The window sometimes draws nothing for a moment after a dialog
        // opens.
        let mut texture = None;
        wait_until(&format!("{page} to draw"), || {
            texture = render(window).ok().flatten();
            texture.is_some()
        })
        .await?;
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
