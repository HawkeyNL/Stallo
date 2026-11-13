#!/usr/bin/python3 -I
"""Stallo UI helper: reports the desktop's windows and controls to the host.

Runs in the logged-in user's session (XDG autostart) and answers requests
from Stallo over the virtio-serial port org.stallo.ui.0, one JSON object per
line each way, read from the accessibility bus (AT-SPI). It runs no commands
and evaluates nothing: it only handles the ops below.

  hello              -> {"v": 1, "platform": "atspi"}
  tree               -> {"tree": {...}}   windows and controls
  probe  {"key": K}  -> {"bbox": [x, y, w, h] | null, "hit": bool, "screen": [w, h]}
  focus  {"key": K}  -> {}
  invoke {"key": K}  -> {}

`python3 -I stallo-ui.py --self-test` checks the pure parts without AT-SPI.
"""

import hashlib
import json
import os
import select
import sys
import time

VERSION = 1
PORT = "/dev/virtio-ports/org.stallo.ui.0"
MAX_REQUEST = 64 << 10
WALK_SECONDS = 2.0
MAX_NODES = 5000
MAX_DEPTH = 64
MAX_TEXT = 200
# The host's caps: one character more travels, so the host marks the cut.
NAME_MAX = 80
VALUE_MAX = 40
APP_MAX = 40
# A reply over the host's 1 MiB line limit would fail whole: stop the walk
# (partial) before that.
MAX_BYTES = 900_000
# Children read from a node that manages its descendants (big lists and
# tables: their rows are made on demand).
MAX_MANAGED = 200
WRITE_SECONDS = 5.0

# AT-SPI role names (non-localized) to the host's vocabulary.
ROLES = {
    "push button": "button",
    "toggle button": "toggle",
    "check box": "checkbox",
    "radio button": "radio",
    "combo box": "combo",
    "entry": "textbox",
    "password text": "password",
    "link": "link",
    "menu item": "menuitem",
    "check menu item": "menuitem",
    "radio menu item": "menuitem",
    "tearoff menu item": "menuitem",
    "menu": "menu",
    "menu bar": "menu",
    "popup menu": "menu",
    "page tab": "tab",
    "list item": "item",
    "tree item": "item",
    "table row": "item",
    "list": "list",
    "list box": "list",
    "tree": "tree",
    "tree table": "tree",
    "table": "table",
    "table cell": "cell",
    "slider": "slider",
    "spin button": "spin",
    "scroll bar": "scrollbar",
    "heading": "heading",
    "label": "text",
    "static": "text",
    "paragraph": "text",
    "caption": "text",
    "icon": "image",
    "image": "image",
    "dialog": "dialog",
    "file chooser": "dialog",
    "alert": "alert",
    "notification": "alert",
    "tool bar": "toolbar",
    "status bar": "statusbar",
    "document web": "document",
    "document frame": "document",
    "document text": "document",
    "panel": "group",
    "filler": "group",
    "section": "group",
    "grouping": "group",
    "form": "group",
    "page tab list": "group",
}
WINDOW_ROLES = {"frame", "dialog", "window", "file chooser", "alert"}
INVOKE_NAMES = ("click", "press", "activate", "toggle", "jump", "open")


def role_word(role_name, editable):
    """The host role for an AT-SPI role name."""
    if role_name == "text":
        return "textbox" if editable else "text"
    return ROLES.get(role_name, "other")


def state_words(has, role):
    """The host states for a node; `has(name)` tells an AT-SPI state."""
    words = []
    if has("focused"):
        words.append("focused")
    if not has("sensitive") and not has("enabled"):
        words.append("disabled")
    if has("checked") or has("pressed"):
        words.append("checked")
    if has("selected"):
        words.append("selected")
    if has("expanded"):
        words.append("expanded")
    elif has("expandable"):
        words.append("collapsed")
    if not has("showing") or not has("visible"):
        words.append("offscreen")
    if has("editable"):
        words.append("editable")
    if has("modal"):
        words.append("modal")
    if has("busy"):
        words.append("busy")
    if role == "password":
        words.append("password")
    return words


def make_key(raw):
    """A host key: printable ASCII, at most 128 bytes."""
    if len(raw) <= 120 and all(33 <= ord(c) <= 126 for c in raw):
        return raw
    return "h" + hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:40]


def parse_request(line):
    """A request dict, or None for junk."""
    try:
        req = json.loads(line)
    except Exception:  # also RecursionError
        return None
    if not isinstance(req, dict) or not isinstance(req.get("id"), int):
        return None
    if req.get("op") not in ("hello", "tree", "probe", "focus", "invoke"):
        return None
    if "key" in req and not isinstance(req["key"], str):
        return None
    return req


class Desktop:
    """The accessibility tree, through AT-SPI (imported here, not at start)."""

    def __init__(self, atspi=None):
        if atspi is None:
            import gi

            gi.require_version("Atspi", "2.0")
            from gi.repository import Atspi as atspi

            atspi.init()
            from gi.repository import GLib

            self.context = GLib.MainContext.default()
        else:
            self.context = None
        self.atspi = atspi
        self.nodes = {}  # key -> (accessible, window accessible, pid), last walk

    def idle(self):
        """Handles pending bus messages, so nothing piles up while idle."""
        while self.context is not None and self.context.pending():
            self.context.iteration(False)

    def has(self, acc):
        try:
            states = acc.get_state_set()
        except Exception:
            return lambda name: False
        return lambda name: states.contains(
            getattr(self.atspi.StateType, name.upper().replace(" ", "_"))
        )

    def pid(self, acc):
        try:
            return acc.get_process_id()
        except Exception:
            return 0

    def key(self, acc, pid):
        path = getattr(acc, "path", None) or ""
        return make_key("%d:%s" % (pid, path or id(acc)))

    def children(self, acc, limit, deadline):
        """At most `limit` children, read before `deadline`. Returns them
        and whether some were left out."""
        kids = []
        try:
            count = acc.get_child_count()
            for k in range(min(count, limit)):
                if time.monotonic() > deadline:
                    return kids, True
                kids.append(acc.get_child_at_index(k))
        except Exception:
            return kids, False
        return kids, count > limit

    def extents(self, acc):
        try:
            r = acc.get_extents(self.atspi.CoordType.SCREEN)
            return [r.x, r.y, max(r.width, 0), max(r.height, 0)]
        except Exception:
            return None

    def text(self, acc, editable):
        try:
            ifaces = acc.get_interfaces()
        except Exception:
            return None
        try:
            if editable and "Text" in ifaces:
                n = min(acc.get_character_count(), VALUE_MAX + 1)
                return acc.get_text(0, n)
            if "Value" in ifaces:
                return str(acc.get_current_value())
        except Exception:
            return None
        return None

    def screen(self, windows):
        size = None
        try:
            r = self.atspi.get_desktop(0).get_extents(self.atspi.CoordType.SCREEN)
            if r.width > 0 and r.height > 0:
                size = [r.width, r.height]
        except Exception:
            pass
        if not size:
            w = max([b[0] + b[2] for b in windows if b] or [1280])
            h = max([b[1] + b[3] for b in windows if b] or [800])
            size = [w, h]
        return [min(max(size[0], 1), 16384), min(max(size[1], 1), 16384)]

    def tree(self):
        start = time.monotonic()
        deadline = start + WALK_SECONDS
        desktop = self.atspi.get_desktop(0)
        windows, nodes, bounds = [], [], []
        self.nodes = {}
        partial = False
        size = 0
        for i in range(desktop.get_child_count()):
            if time.monotonic() > deadline or len(windows) >= 64:
                partial = True
                break
            try:
                app = desktop.get_child_at_index(i)
                app.set_cache_mask(self.atspi.Cache.NONE)
                app_name = (app.get_name() or "")[:APP_MAX + 1]
                pid = self.pid(app)
                tops, _ = self.children(app, 64, deadline)
            except Exception:
                continue
            for top in tops:
                try:
                    if top.get_role_name() not in WINDOW_ROLES or not self.has(top)("showing"):
                        continue
                    wkey = self.key(top, pid)
                    if wkey in self.nodes:
                        continue
                    if len(windows) >= 64:
                        partial = True
                        break
                    win = len(windows)
                    windows.append({
                        "key": wkey,
                        "title": (top.get_name() or "")[:NAME_MAX + 1],
                        "app": app_name,
                        "active": self.has(top)("active"),
                    })
                    bounds.append(self.extents(top))
                    self.nodes[wkey] = (top, top, pid)
                except Exception:
                    continue
                # Pre-order: pop a node, then push its children reversed.
                kids, cut = self.children(top, MAX_NODES - len(nodes), deadline)
                partial |= cut
                stack = [(c, 0, False) for c in reversed(kids)]
                while stack:
                    if len(nodes) >= MAX_NODES or time.monotonic() > deadline or size > MAX_BYTES:
                        partial = True
                        break
                    acc, depth, secret = stack.pop()
                    node, managed = self.node(acc, pid, win, depth, secret)
                    if node is None or node["key"] in self.nodes:
                        continue  # not showing (nor its subtree), or seen
                    nodes.append(node)
                    size += len(dump(node)) + 1
                    self.nodes[node["key"]] = (acc, top, pid)
                    # Bounded memory: never more than 2 * MAX_NODES queued.
                    room = min(MAX_NODES - len(nodes), 2 * MAX_NODES - len(stack))
                    kids, cut = self.children(acc, min(room, MAX_MANAGED) if managed else room, deadline)
                    partial |= cut
                    if depth + 1 >= MAX_DEPTH:
                        partial |= bool(kids)
                        continue
                    # Nothing below a password field shows its text.
                    secret = secret or node["role"] == "password"
                    stack.extend((k, depth + 1, secret) for k in reversed(kids))
        return {
            "screen": self.screen(bounds),
            "coords": "window" if os.environ.get("WAYLAND_DISPLAY") else "screen",
            "partial": partial,
            "windows": windows,
            "nodes": nodes,
        }

    def node(self, acc, pid, win, depth, secret):
        """The node for `acc` and whether it manages its descendants, or
        None for one that is not showing."""
        try:
            has = self.has(acc)
            if not has("showing"):
                return None, False
            role = role_word(acc.get_role_name(), has("editable"))
            node = {
                "key": self.key(acc, pid),
                "win": win,
                "depth": depth,
                "role": role,
                "name": (acc.get_name() or "")[:NAME_MAX + 1],
                "states": state_words(has, role),
            }
        except Exception:
            return None, False
        if role != "password" and not secret:
            value = self.text(acc, has("editable"))
            if value:
                node["value"] = value[:VALUE_MAX + 1]
        bbox = self.extents(acc)
        if bbox:
            node["bbox"] = bbox
        try:
            if acc.get_n_actions() > 0:
                node["actions"] = ["a"]
        except Exception:
            pass
        return node, has("manages descendants")

    def find(self, key):
        found = self.nodes.get(key)
        if found is None:
            raise LookupError("unknown element; call ui_tree")
        return found

    def probe(self, key):
        acc, window, pid = self.find(key)
        bbox = self.extents(acc)
        screen = self.screen([self.extents(window)])
        hit = False
        if bbox and bbox[2] > 0 and bbox[3] > 0:
            x, y = bbox[0] + bbox[2] // 2, bbox[1] + bbox[3] // 2
            hit = self.at_point(window, pid, x, y, key) and not self.covered(window, x, y)
        return {"bbox": bbox, "hit": hit, "screen": screen}

    def at_point(self, window, pid, x, y, key):
        """Whether the deepest control at (x, y) in `window` is `key` or
        inside it."""
        cur = window
        for _ in range(MAX_DEPTH):
            try:
                child = cur.get_accessible_at_point(x, y, self.atspi.CoordType.SCREEN)
            except Exception:
                child = None
            if child is None or self.key(child, pid) == self.key(cur, pid):
                break
            cur = child
        for _ in range(32):
            if cur is None:
                return False
            if self.key(cur, pid) == key:
                return True
            try:
                cur = cur.get_parent()
            except Exception:
                return False
        return False

    def covered(self, window, x, y):
        """Whether another, active window lies over (x, y). AT-SPI has no
        stacking order; the active window is taken to be on top."""
        if self.has(window)("active"):
            return False
        for acc, top, _ in self.nodes.values():
            if acc is top and acc is not window and self.has(acc)("active"):
                b = self.extents(acc)
                if b and b[0] <= x < b[0] + b[2] and b[1] <= y < b[1] + b[3]:
                    return True
        return False

    def focus(self, key):
        """Focuses `key`, and checks keys would reach it: on Wayland a
        control in an inactive window can take focus while typed keys go
        to the active window."""
        acc, window, _ = self.find(key)
        if not acc.grab_focus():
            raise RuntimeError("the control did not take focus")
        if not self.has(window)("active"):
            raise RuntimeError("its window is not active; click or invoke something in it first")
        if not self.has(acc)("focused"):
            raise RuntimeError("the control did not take focus")

    def invoke(self, key):
        acc, _, _ = self.find(key)
        n = acc.get_n_actions()
        if n <= 0:
            raise RuntimeError("the control has no action")
        names = [(acc.get_action_name(i) or "").lower() for i in range(n)]
        index = next((i for i, a in enumerate(names) if a in INVOKE_NAMES), 0)
        if not acc.do_action(index):
            raise RuntimeError("the action failed")


def answer(desktop, req):
    op, rid = req["op"], req["id"]
    try:
        if op == "hello":
            return {"id": rid, "ok": True, "v": VERSION, "platform": "atspi"}
        if op == "tree":
            return {"id": rid, "ok": True, "tree": desktop.tree()}
        key = req.get("key", "")
        if op == "probe":
            return dict(desktop.probe(key), id=rid, ok=True)
        if op == "focus":
            desktop.focus(key)
        else:
            desktop.invoke(key)
        return {"id": rid, "ok": True}
    except Exception as e:
        return {"id": rid, "ok": False, "error": str(e)[:MAX_TEXT]}


def dump(obj):
    """Compact UTF-8 JSON, as sent."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "replace")


def write_all(fd, data):
    """Writes `data`, or gives up after WRITE_SECONDS: with no host side
    connected, a write would wait forever."""
    deadline = time.monotonic() + WRITE_SECONDS
    while data:
        left = deadline - time.monotonic()
        if left <= 0:
            return False
        _, writable, _ = select.select([], [fd], [], left)
        if writable:
            data = data[os.write(fd, data):]
    return True


def serve(desktop):
    backoff = 1.0
    while True:
        try:
            fd = os.open(PORT, os.O_RDWR | os.O_NONBLOCK)
        except OSError:
            time.sleep(backoff)
            backoff = min(backoff * 2, 10.0)
            continue
        backoff = 1.0
        buf = b""
        try:
            while True:
                readable, _, _ = select.select([fd], [], [], 1.0)
                desktop.idle()
                if not readable:
                    continue
                chunk = os.read(fd, 65536)
                if not chunk:
                    # No host side connected.
                    time.sleep(0.5)
                    continue
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    req = parse_request(line) if len(line) <= MAX_REQUEST else None
                    if req is None:
                        continue
                    if not write_all(fd, dump(answer(desktop, req)) + b"\n"):
                        raise OSError("the host stopped reading")
                if len(buf) > MAX_REQUEST:
                    buf = b""
        except OSError:
            os.close(fd)
            time.sleep(1.0)


def self_test():
    assert role_word("push button", False) == "button"
    assert role_word("text", True) == "textbox"
    assert role_word("text", False) == "text"
    assert role_word("password text", True) == "password"
    assert role_word("something new", False) == "other"
    host_roles = set(ROLES.values()) | {"textbox", "text", "other"}
    assert host_roles <= {
        "button", "toggle", "checkbox", "radio", "combo", "textbox", "password", "link",
        "menuitem", "menu", "tab", "item", "list", "tree", "table", "cell", "slider", "spin",
        "scrollbar", "heading", "text", "image", "dialog", "alert", "toolbar", "statusbar",
        "document", "group", "other",
    }
    on = {"showing", "visible", "enabled", "sensitive", "focused", "expandable"}
    assert state_words(on.__contains__, "button") == ["focused", "collapsed"]
    assert state_words(set().__contains__, "password") == ["disabled", "offscreen", "password"]
    assert make_key("1234:/org/a11y/atspi/accessible/7") == "1234:/org/a11y/atspi/accessible/7"
    long = make_key("1:/" + "x" * 300)
    assert long.startswith("h") and len(long) == 41
    assert make_key("1:/é")[0] == "h"
    assert parse_request('{"id": 3, "op": "tree"}') == {"id": 3, "op": "tree"}
    for bad in ["junk", "[]", '{"id": "3", "op": "tree"}', '{"id": 3, "op": "exec"}',
                '{"id": 3, "op": "probe", "key": 5}']:
        assert parse_request(bad) is None, bad
    assert dump({"t": "a\ud800b"}) == b'{"t":"a?b"}'
    reply = answer(None, {"id": 9, "op": "hello"})
    assert reply == {"id": 9, "ok": True, "v": VERSION, "platform": "atspi"}
    reply = answer(None, {"id": 9, "op": "tree"})
    assert reply["ok"] is False and reply["id"] == 9
    fake_desktop_test()
    print("ok")


class FakeAcc:
    """Just enough of an AT-SPI accessible for the self-test."""

    def __init__(self, path, role, name="", states=(), box=None, kids=(), actions=(), text=None):
        self.path, self.role, self.name, self.box = path, role, name, box
        self.states = set(states) | {"SHOWING", "VISIBLE", "ENABLED", "SENSITIVE"}
        self.kids, self.actions, self.value, self.parent = list(kids), list(actions), text, None
        self.done = []
        for k in self.kids:
            k.parent = self

    def get_process_id(self):
        return 42

    def get_role_name(self):
        return self.role

    def get_name(self):
        return self.name

    def get_state_set(self):
        return self

    def contains(self, state):
        return state in self.states

    def get_child_count(self):
        return len(self.kids)

    def get_child_at_index(self, i):
        return self.kids[i]

    def get_parent(self):
        return self.parent

    def set_cache_mask(self, mask):
        pass

    def get_extents(self, coord):
        if self.box is None:
            raise RuntimeError("no Component")
        x, y, w, h = self.box
        return type("Rect", (), {"x": x, "y": y, "width": w, "height": h})

    def get_interfaces(self):
        return ["Text"] if self.value is not None else []

    def get_character_count(self):
        return len(self.value)

    def get_text(self, a, b):
        return self.value[a:b]

    def get_n_actions(self):
        return len(self.actions)

    def get_action_name(self, i):
        return self.actions[i]

    def grab_focus(self):
        self.states.add("FOCUSED")
        return True

    def do_action(self, i):
        self.done.append(self.actions[i])
        return True

    def get_accessible_at_point(self, x, y, coord):
        for k in reversed(self.kids):
            if k.box and k.box[0] <= x < k.box[0] + k.box[2] and k.box[1] <= y < k.box[1] + k.box[3]:
                return k
        return None


class FakeAtspi:
    class StateType:
        def __getattr__(self, name):
            return name

    StateType = StateType()
    CoordType = type("CoordType", (), {"SCREEN": 0})
    Cache = type("Cache", (), {"NONE": 0})

    def __init__(self, desktop):
        self.desktop = desktop

    def get_desktop(self, i):
        return self.desktop


def fake_desktop_test():
    save = FakeAcc("/save", "push button", "Save", box=(600, 400, 90, 32), actions=["click"])
    hidden = FakeAcc("/hidden", "push button", "Hidden", box=(0, 0, 9, 9))
    hidden.states.discard("SHOWING")
    hidden.kids = [FakeAcc("/hidden/kid", "push button", "Kid")]
    pw = FakeAcc("/pw", "password text", "Password", states=["EDITABLE"], box=(10, 10, 100, 20), text="hunter2")
    entry = FakeAcc("/name", "text", "Name", states=["EDITABLE", "FOCUSED"], box=(300, 300, 400, 32), text="Untitled")
    panel = FakeAcc("/panel", "panel", kids=[entry, save, hidden, pw], box=(0, 0, 1280, 800))
    dialog = FakeAcc("/dlg", "dialog", "Save As", states=["ACTIVE"], kids=[panel, panel], box=(0, 0, 1280, 800))
    off = FakeAcc("/off", "frame", "Minimised")
    off.states.discard("SHOWING")
    app = FakeAcc("/app", "application", "gedit", kids=[dialog, off])
    d = Desktop(FakeAtspi(FakeAcc("/", "desktop frame", kids=[app], box=(0, 0, 1920, 1080))))
    tree = d.tree()
    assert tree["screen"] == [1920, 1080] and not tree["partial"]
    assert [w["title"] for w in tree["windows"]] == ["Save As"] and tree["windows"][0]["active"]
    got = [(n["depth"], n["role"], n["name"]) for n in tree["nodes"]]
    # The repeated panel is skipped, the hidden button and its child too.
    assert got == [(0, "group", ""), (1, "textbox", "Name"), (1, "button", "Save"),
                   (1, "password", "Password")], got
    by = {n["name"]: n for n in tree["nodes"]}
    assert by["Name"]["value"] == "Untitled" and "focused" in by["Name"]["states"]
    assert "value" not in by["Password"]
    assert by["Save"]["actions"] == ["a"] and by["Save"]["key"] == "42:/save"
    assert d.probe("42:/save") == {"bbox": [600, 400, 90, 32], "hit": True, "screen": [1920, 1080]}
    assert d.probe("42:/name")["hit"] is True
    d.invoke("42:/save")
    assert save.done == ["click"]
    try:
        d.probe("42:/gone")
        raise AssertionError("unknown key accepted")
    except LookupError:
        pass
    # Focus counts only in the active window, where keys arrive.
    d.focus("42:/name")
    dialog.states.discard("ACTIVE")
    try:
        d.focus("42:/name")
        raise AssertionError("focus in an inactive window accepted")
    except RuntimeError as e:
        assert "not active" in str(e)

    # Nothing under a password field shows text; a list that manages its
    # rows gives at most MAX_MANAGED; a huge tree stops (partial) under the
    # host's line limit.
    inner = FakeAcc("/pw/inner", "text", "", states=["EDITABLE"], box=(10, 10, 90, 20), text="hunter2")
    secret = FakeAcc("/pw2", "password text", "PIN", box=(10, 10, 100, 20), kids=[inner])
    rows = [FakeAcc("/row%d" % i, "list item", "Row %d" % i) for i in range(MAX_MANAGED + 50)]
    table = FakeAcc("/rows", "list", "Rows", states=["MANAGES_DESCENDANTS"], kids=rows)
    big = [FakeAcc("/b%d" % i, "push button", "名" * 100) for i in range(MAX_NODES)]
    frame = FakeAcc("/f", "frame", "Big", states=["ACTIVE"], kids=[secret, table] + big)
    d = Desktop(FakeAtspi(FakeAcc("/", "desktop frame", kids=[FakeAcc("/a", "application", "x", kids=[frame])])))
    tree = d.tree()
    assert "hunter2" not in json.dumps(tree)
    assert sum(1 for n in tree["nodes"] if n["name"].startswith("Row ")) == MAX_MANAGED
    assert tree["partial"] and len(dump(tree)) < (1 << 20) - 100
    assert all(len(n["name"]) <= NAME_MAX + 1 for n in tree["nodes"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        serve(Desktop())
