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


def operate(request, api):
    desktop = api.Registry.getDesktop(0)
    items = [n for app in desktop for n in nodes(app) if visible(n, api)]
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
            if not next_buttons[0].queryAction().doAction(0):
                raise RuntimeError('could not submit native PIN dialog')
        else:
            subprocess.run(["xdotool", "key", "Return"], check=True, timeout=2)
        result["action"] = "entered PIN in native dialog"
        result["action_kind"] = "pin"
        return result
    buttons = [n for n in items if n.getRoleName() in ("push button", "button", "menu item", "list item", "radio button")]
    account = request.get("account")
    # Match full account labels, never a substring of another user's name.
    candidates = [n for n in buttons if account and n.name.strip().splitlines()
                  and all(re.fullmatch(re.escape(account) + r'(?: \(\d+\))?', line.strip())
                          for line in n.name.strip().splitlines())]
    if not candidates and request.get('opaque_account'):
        candidates = [n for n in buttons if n.name.strip() == request['opaque_account']]
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
        action = node.queryAction()
        if not action.nActions:
            raise RuntimeError("native prompt control has no accessibility action")
        if not action.doAction(0):
            raise RuntimeError("native prompt action failed")
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
