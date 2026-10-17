# GUI screenshots

To review the GUI without a daemon or a window on your desktop, run
`packaging/dev/shots.sh <output dir>`. It builds `stallo-gui` with the
dev-only `shots` feature (never in release builds), starts a private
`gtk4-broadwayd` on a Unix socket (no TCP port, no `DISPLAY`,
`WAYLAND_DISPLAY` or session bus), and runs `stallo-gui --screenshot <dir>`.
That drives the real widgets against a fake daemon and a fake VM screen
(`gui/src/vms/shots/fake.rs`), renders each page offscreen at 1100x720 and
writes `<page>-light.png` and `<page>-dark.png`: the empty state, the VM
list, a VM's overview (also with an installer ISO in its drive), the
Screen, Files and Snapshots tabs, the agent control confirmation and the
New VM dialog (also with an imported Windows ISO selected). To add a page,
add a step to `script` in `gui/src/vms/shots.rs`; to change the data, edit
`fake.rs`. broadwayd and the app stop when the script ends.
