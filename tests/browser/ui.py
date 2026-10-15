#!/usr/bin/python3
"""One bounded AT-SPI operation on the harness's private Xvfb desktop.

Run with the distro Python (python3-pyatspi), not the verifier venv. Input
arrives on stdin; PINs never appear in argv, output, screenshots or logs.
Only named browser prompts and the expected account may be operated.
"""
import json
import hashlib
import re
import subprocess
import sys
import time


def nodes(root, limit=3000):
    pending = [root]
    for _ in range(limit):
        if not pending:
            return
        node = pending.pop()
        yield node
        pending.extend(reversed(list(node)))
    raise RuntimeError("accessibility tree exceeds bounded traversal")


def visible(node, api):
    state = node.getState()
    return state.contains(api.STATE_SHOWING) and state.contains(api.STATE_VISIBLE)


def activate(node, api, *, xtest=False):
    if xtest:
        # Chromium's Views buttons acknowledge AT-SPI doAction without
        # activating these dialogs. Click the named native control at its
        # accessibility-provided bounds on our private 1280x960 Xvfb desktop.
        bounds = node.queryComponent().getExtents(api.DESKTOP_COORDS)
        x, y, width, height = bounds.x, bounds.y, bounds.width, bounds.height
        if not (0 <= x < x + width <= 1280 and 0 <= y < y + height <= 960):
            raise RuntimeError('native control is outside the owned desktop')
        subprocess.run(['xdotool', 'mousemove', '--sync', str(x + width // 2), str(y + height // 2), 'click', '1'],
                       check=True, timeout=2)
    else:
        action = node.queryAction()
        if not action.nActions or not action.doAction(0):
            raise RuntimeError('native prompt accessibility action failed')


def operate(request, api):
    desktop = api.Registry.getDesktop(0)
    items = [n for app in desktop for n in nodes(app) if visible(n, api)]
    chromium = any(n.getRoleName() == 'application' and n.name == 'Chromium' for n in items)
    dialogs = [n for n in items if n.getRoleName() in ("dialog", "alert", "alert dialog")]
    # Never inspect or emit editable/password values.
    safe = [{"role": n.getRoleName(), "name": n.name[:400]} for n in items
            if n.getRoleName() not in ("password text", "text", "entry")]
    result = {"action": None, "action_kind": None, "evidence": [], "tree": safe}
    result["fingerprint"] = hashlib.sha256(json.dumps(safe, sort_keys=True).encode()).hexdigest()
    text = " ".join(n.name for n in items if n.getRoleName() not in ("password text", "text", "entry")).lower()
    incompatible = ("this security key can't be used", "this security key cannot be used",
                    "your device can't be used with this site", "no supported algorithms")
    if any(label in text for label in incompatible):
        result["evidence"].append("unsupported-key")
    if request.get("last_fingerprint") == result["fingerprint"]:
        return result
    passwords = [n for n in items if n.getRoleName() == "password text"]
    if passwords:
        if any(label in text for label in ('incorrect pin', 'device has been locked', 'temporarily blocked')):
            raise RuntimeError('fixture PIN was rejected')
        if len(passwords) != 1:
            raise RuntimeError("unexpected PIN setup/multiple password fields; fixture PIN is already set")
        # Focus and use XTEST keystrokes, as a person types into the native field.
        if not passwords[0].queryComponent().grabFocus():
            raise RuntimeError('could not focus native PIN field')
        subprocess.run(["xdotool", "key", "--clearmodifiers", "ctrl+a"], check=True, timeout=2)
        subprocess.run(["xdotool", "type", "--clearmodifiers", "--file", "-"], input=request["pin"].encode(), check=True, timeout=2)
        # Chromium's PIN dialog does not submit on Return. Its named native
        # button is available before typing, even though editable values are
        # deliberately excluded from the public accessibility fingerprint.
        next_buttons = [n for dialog in dialogs for n in nodes(dialog)
                        if visible(n, api) and n.getRoleName() in ("push button", "button")
                        and n.name.strip() == "Next"]
        if next_buttons:
            sensitive = getattr(api, 'STATE_SENSITIVE', None)
            deadline = time.monotonic() + 1
            while sensitive is not None and not next_buttons[0].getState().contains(sensitive):
                if time.monotonic() >= deadline:
                    raise RuntimeError('native PIN submit control did not become enabled')
                time.sleep(0.05)
            activate(next_buttons[0], api, xtest=chromium)
        else:
            subprocess.run(["xdotool", "key", "Return"], check=True, timeout=2)
        result["action"] = "entered PIN in native dialog"
        result["action_kind"] = "pin"
        return result
    if any(n.name == 'PIN required' for n in dialogs):
        # Wait for the password accessible rather than clicking an empty form.
        return result
    buttons = [n for n in items if n.getRoleName() in ("push button", "button", "menu item", "list item", "radio button")]
    account = request.get("account")
    # Match full account labels, never a substring of another user's name.
    candidates = [n for n in buttons if account and n.name.strip().splitlines()
                  and all(re.fullmatch(re.escape(account) + r'(?: \(\d+\))?', line.strip())
                          for line in n.name.strip().splitlines())]
    opaque = request.get('opaque_account')
    if not candidates and opaque is not None:
        index, count = opaque['index'], opaque['count']
        if not isinstance(index, int) or not isinstance(count, int) or not 0 <= index < count:
            raise RuntimeError('invalid inspected account index')
        if index == 0:
            candidates = [n for n in buttons if n.name.strip() == 'Unknown account (0)']
        else:
            menus = [n for n in items if n.getRoleName() == 'menu' and n.name == 'More actions']
            if menus:
                options = [n for menu in menus for n in nodes(menu)
                           if visible(n, api) and n.getRoleName() == 'menu item' and n.name == 'Unknown account']
                # Firefox omits the first response from this secondary menu.
                # Its access-key suffix is visual, not in AT-SPI item names.
                if len(options) != count - 1:
                    raise RuntimeError('anonymous account menu differs from inspected credential count')
                candidates = [options[index - 1]]
    action_kind = 'account'
    if not candidates:
        action_kind = 'transport'
        candidates = [n for n in buttons if n.name.strip().lower() in
                      ("usb security key", "security key", "use a security key", "use another device")]
    if not candidates and dialogs:
        action_kind = 'continue'
        candidates = [n for n in buttons if n.name.strip().lower() in ("continue", "next", "allow", "ok")]
    if not candidates and account:
        action_kind = 'account-menu'
        candidates = [n for n in buttons if n.name.strip().lower() in ('more actions', 'more options', 'show more options')
                      or n.name.strip().endswith(' More Options')]
    if "unsupported-key" in result["evidence"]:
        action_kind = 'dismiss-incompatibility'
        candidates = [n for n in buttons if n.name.strip().lower() == "cancel"]
    if candidates:
        node = candidates[0]
        activate(node, api, xtest=chromium)
        result["action"] = "native " + node.name
        result["action_kind"] = action_kind
    return result


if __name__ == "__main__":
    import pyatspi
    try:
        print(json.dumps(operate(json.load(sys.stdin), pyatspi)))
    except Exception as error:
        # An exception might carry a peer's payload; publish only its type.
        print(json.dumps({"error": type(error).__name__}))
        sys.exit(1)
