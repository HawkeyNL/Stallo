//! stallo-gui: the desktop app for Stallo. For now an empty window.

use adw::prelude::*;
use libadwaita as adw;

/// Also the name of the desktop file, the icon and the AppStream metadata.
const APP_ID: &str = "io.github.hawkeynl.Stallo";

fn main() -> adw::glib::ExitCode {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(|app| {
        let placeholder = adw::StatusPage::builder()
            .icon_name(APP_ID)
            .title("Stallo")
            .description("Your virtual machines will show up here.")
            .build();
        let view = adw::ToolbarView::builder().content(&placeholder).build();
        view.add_top_bar(&adw::HeaderBar::new());
        adw::ApplicationWindow::builder()
            .application(app)
            .title("Stallo")
            .default_width(900)
            .default_height(600)
            .content(&view)
            .build()
            .present();
    });
    app.run()
}
