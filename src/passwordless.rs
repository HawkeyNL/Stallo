//! `stallo set <vm> --passwordless on|off`: a Linux guest where the guest
//! user needs no password for sudo, admin dialogs (polkit) or logging in,
//! so an agent can work without ever being given one. Nothing is stored on
//! the host. With agent control an agent can already run commands as root
//! (`exec` with `admin`), so this adds no power inside the guest; it only
//! drops the password prompts, for anyone at the VM's console too.

/// The sudoers drop-in. Written under a name with a dot first, which sudo
/// skips, then checked with `visudo -cf` and moved in place.
pub const SUDOERS: &str = "/etc/sudoers.d/90-stallo-passwordless";
pub const SUDOERS_TMP: &str = "/etc/sudoers.d/.stallo-passwordless";
pub const POLKIT_RULE: &str = "/etc/polkit-1/rules.d/49-stallo-passwordless.rules";
/// Written first, then moved: polkitd reads only `*.rules`.
pub const POLKIT_TMP: &str = "/etc/polkit-1/rules.d/.stallo-passwordless.tmp";
/// No lock screen and no blank screen (a blank screen shows agents
/// nothing); a user's own settings still win.
pub const SCREEN_DEFAULTS: (&str, &str) = (
    "/usr/share/glib-2.0/schemas/91_stallo-passwordless.gschema.override",
    "# Stallo: passwordless\n[org.gnome.desktop.screensaver]\nlock-enabled=false\n\n[org.gnome.desktop.session]\nidle-delay=uint32 0\n",
);
/// GDM's config on Debian/Ubuntu and on Fedora.
pub const GDM_CONFS: [&str; 2] = ["/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"];
/// Seconds the login screen shows after a log out before it logs in again.
pub const TIMED_LOGIN_DELAY: u32 = 5;
const GDM_KEYS: [&str; 5] = [
    "AutomaticLoginEnable",
    "AutomaticLogin",
    "TimedLoginEnable",
    "TimedLogin",
    "TimedLoginDelay",
];
const MARK: &str = "# Stallo: passwordless login (stallo set <vm> --passwordless off)";
/// Before an owner's own login key while Stallo's block is in place.
const SAVED: &str = "#stallo-saved# ";

/// The sudoers line for `user` (a name checked by `validate_guest_user`).
pub fn sudoers(user: &str) -> String {
    format!("# Stallo: passwordless\n{user} ALL=(ALL:ALL) NOPASSWD: ALL\n")
}

/// Every polkit action for `user` without asking.
pub fn polkit_rule(user: &str) -> String {
    format!(
        "// Stallo: passwordless\npolkit.addRule(function(action, subject) {{\n    if (subject.user == \"{user}\") {{\n        return polkit.Result.YES;\n    }}\n}});\n"
    )
}

/// GDM's `custom.conf` with automatic login (at boot) and timed login
/// (after a log out) for `user`, or as it was before (`None`). Login keys
/// the owner set in `[daemon]` are commented out while Stallo's block is
/// there, and come back when it goes.
pub fn gdm_conf(conf: &str, user: Option<&str>) -> String {
    let login_key = |line: &str| {
        line.split_once('=')
            .is_some_and(|(key, _)| GDM_KEYS.contains(&key.trim()))
    };
    // The file without Stallo: its block dropped, saved lines restored.
    let mut lines = Vec::new();
    let mut block = false;
    for line in conf.lines() {
        if line.trim() == MARK {
            block = true;
            continue;
        }
        if block && login_key(line) {
            continue;
        }
        block = false;
        lines.push(line.strip_prefix(SAVED).unwrap_or(line));
    }
    let Some(user) = user else {
        return lines.iter().map(|l| format!("{l}\n")).collect();
    };
    let ours = format!(
        "{MARK}\nAutomaticLoginEnable=true\nAutomaticLogin={user}\nTimedLoginEnable=true\nTimedLogin={user}\nTimedLoginDelay={TIMED_LOGIN_DELAY}\n"
    );
    let mut out = String::with_capacity(conf.len() + 256);
    let mut section = "";
    let mut placed = false;
    for line in lines {
        let t = line.trim();
        if t.starts_with('[') {
            section = t;
        }
        if section == "[daemon]" && !t.starts_with('#') && login_key(line) {
            out.push_str(SAVED);
        }
        out.push_str(line);
        out.push('\n');
        if t == "[daemon]" && !placed {
            out.push_str(&ours);
            placed = true;
        }
    }
    if !placed {
        out.push_str("\n[daemon]\n");
        out.push_str(&ours);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU: &str = "# GDM configuration storage
#
[daemon]
# Uncomment the line below to force the login screen to use Xorg
#WaylandEnable=false

# Enabling automatic login
#  AutomaticLoginEnable = true
#  AutomaticLogin = user1

[security]

[debug]
#Enable=true
";

    #[test]
    fn gdm_login() {
        let on = gdm_conf(UBUNTU, Some("gus-ai"));
        assert!(on.contains(
            "[daemon]\n# Stallo: passwordless login (stallo set <vm> --passwordless off)\nAutomaticLoginEnable=true\nAutomaticLogin=gus-ai\nTimedLoginEnable=true\nTimedLogin=gus-ai\nTimedLoginDelay=5\n# Uncomment"
        ));
        // Comments and other sections stay.
        assert!(
            on.contains("#  AutomaticLogin = user1\n") && on.contains("[debug]\n#Enable=true\n")
        );
        // Again: no second copy; another user replaces it.
        assert_eq!(gdm_conf(&on, Some("gus-ai")), on);
        let other = gdm_conf(&on, Some("bob"));
        assert!(other.contains("AutomaticLogin=bob\n") && !other.contains("gus-ai"));
        // Off: back to the original.
        assert_eq!(gdm_conf(&on, None), UBUNTU);
        // Keys the owner set by hand in [daemon] are kept, commented out,
        // and come back with off; the same keys elsewhere stay as they are.
        let hand =
            "[daemon]\nAutomaticLoginEnable = True\nAutomaticLogin=old\n[other]\nTimedLogin=x\n";
        let on = gdm_conf(hand, Some("a"));
        assert!(
            on.contains("#stallo-saved# AutomaticLogin=old\n")
                && on.ends_with("[other]\nTimedLogin=x\n")
        );
        assert_eq!(gdm_conf(&on, Some("a")), on);
        assert_eq!(gdm_conf(&on, None), hand);
        // No [daemon] section: one is added.
        assert!(gdm_conf("[security]\n", Some("a")).ends_with("\n[daemon]\n# Stallo: passwordless login (stallo set <vm> --passwordless off)\nAutomaticLoginEnable=true\nAutomaticLogin=a\nTimedLoginEnable=true\nTimedLogin=a\nTimedLoginDelay=5\n"));
        assert_eq!(gdm_conf("", None), "");
    }

    #[test]
    fn files() {
        assert_eq!(
            sudoers("gus-ai"),
            "# Stallo: passwordless\ngus-ai ALL=(ALL:ALL) NOPASSWD: ALL\n"
        );
        assert!(polkit_rule("gus-ai").contains("if (subject.user == \"gus-ai\")"));
        // sudo skips names with a dot: the unchecked file is never read.
        assert!(SUDOERS_TMP.rsplit('/').next().unwrap().contains('.'));
        assert!(!SUDOERS.rsplit('/').next().unwrap().contains('.'));
        // polkitd reads only *.rules.
        assert!(POLKIT_RULE.ends_with(".rules") && !POLKIT_TMP.ends_with(".rules"));
        assert!(SCREEN_DEFAULTS.1.contains("lock-enabled=false"));
    }
}
