"""A fake desktop notification server on the D-Bus session bus.

It implements the parts of org.freedesktop.Notifications (Desktop
Notifications Specification 1.2) that `pqkey attach --presence notify`
uses, records what it was asked to show and close, and plays the user: after
a notification appears it invokes Approve or Deny, dismisses it, or leaves it
unanswered, as the test chooses.

It connects to the bus named by DBUS_SESSION_BUS_ADDRESS, the same bus the
daemon under test uses (see .github/workflows/e2e.yml).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from jeepney import DBusAddress, HeaderFields, MessageType, new_error, new_method_return, new_signal
from jeepney.bus_messages import message_bus
from jeepney.io.blocking import open_dbus_connection

NAME = "org.freedesktop.Notifications"
PATH = "/org/freedesktop/Notifications"

# RequestName flag and reply.
DO_NOT_QUEUE = 4
PRIMARY_OWNER = 1

# NotificationClosed reasons.
DISMISSED = 2
CLOSED_BY_CALL = 3

# How long the fake user takes to answer.
ANSWER_DELAY_S = 0.3


@dataclass
class Shown:
    id: int
    app_name: str
    summary: str
    body: str
    actions: list[str]
    hints: dict
    expire_timeout: int
    at: float = field(default_factory=time.monotonic)


class FakeNotificationServer:
    def __init__(self) -> None:
        self.capabilities = ["actions", "body"]
        # "approve", "deny", "dismiss", or None to leave notifications unanswered.
        self.answer: str | None = "approve"
        self.shown: list[Shown] = []
        self.close_requests: list[int] = []
        self._next_id = 1
        self._open: set[int] = set()
        self._pending: list[tuple[float, int, str]] = []
        self._stop = threading.Event()
        self._conn = None
        self._thread: threading.Thread | None = None
        self._emitter = DBusAddress(PATH, interface=NAME)

    def start(self) -> "FakeNotificationServer":
        self._conn = open_dbus_connection(bus="SESSION")
        reply = self._conn.send_and_get_reply(message_bus.RequestName(NAME, DO_NOT_QUEUE), timeout=5)
        if reply.header.message_type != MessageType.method_return or reply.body[0] != PRIMARY_OWNER:
            self._conn.close()
            raise RuntimeError(f"could not own {NAME}: {reply.body}")
        self._thread = threading.Thread(target=self._serve, name="fake-notification-server", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._conn is not None:
            self._conn.close()
        wait_until_no_server()

    def wait_for_shown(self, count: int = 1, timeout: float = 10.0) -> Shown:
        """The `count`-th notification shown, once it has been."""
        wait_for(lambda: len(self.shown) >= count, timeout, f"notification {count} was never shown")
        return self.shown[count - 1]

    # The server thread.

    def _serve(self) -> None:
        while not self._stop.is_set():
            self._answer_due()
            try:
                message = self._conn.receive(timeout=0.02)
            except TimeoutError:
                continue
            if message.header.message_type == MessageType.method_call:
                self._handle(message)

    def _handle(self, message) -> None:
        fields = message.header.fields
        member = fields.get(HeaderFields.member)
        if fields.get(HeaderFields.interface) not in (NAME, None) or fields.get(HeaderFields.path) != PATH:
            self._conn.send(new_error(message, "org.freedesktop.DBus.Error.UnknownObject"))
        elif member == "GetCapabilities":
            self._conn.send(new_method_return(message, "as", (list(self.capabilities),)))
        elif member == "GetServerInformation":
            self._conn.send(new_method_return(message, "ssss", ("fake", "e2e", "1", "1.2")))
        elif member == "Notify":
            app_name, _replaces, _icon, summary, body, actions, hints, expire_timeout = message.body
            notification_id = self._next_id
            self._next_id += 1
            self._open.add(notification_id)
            self.shown.append(Shown(notification_id, app_name, summary, body, list(actions), dict(hints), expire_timeout))
            self._conn.send(new_method_return(message, "u", (notification_id,)))
            if self.answer is not None:
                self._pending.append((time.monotonic() + ANSWER_DELAY_S, notification_id, self.answer))
        elif member == "CloseNotification":
            (notification_id,) = message.body
            self.close_requests.append(notification_id)
            self._conn.send(new_method_return(message))
            if notification_id in self._open:
                self._closed(notification_id, CLOSED_BY_CALL)
        else:
            self._conn.send(new_error(message, "org.freedesktop.DBus.Error.UnknownMethod"))

    def _answer_due(self) -> None:
        now = time.monotonic()
        due = [entry for entry in self._pending if entry[0] <= now]
        self._pending = [entry for entry in self._pending if entry[0] > now]
        for _, notification_id, answer in due:
            if notification_id not in self._open:
                continue
            if answer == "dismiss":
                self._closed(notification_id, DISMISSED)
            else:
                # As desktop servers do: the action, then the notification goes.
                self._conn.send(new_signal(self._emitter, "ActionInvoked", "us", (notification_id, answer)))
                self._closed(notification_id, DISMISSED)

    def _closed(self, notification_id: int, reason: int) -> None:
        self._open.discard(notification_id)
        self._conn.send(new_signal(self._emitter, "NotificationClosed", "uu", (notification_id, reason)))


def wait_for(predicate, timeout: float, message: str) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError(message)
        time.sleep(0.01)


def wait_until_no_server(timeout: float = 5.0) -> None:
    """Wait until nothing owns org.freedesktop.Notifications."""
    with open_dbus_connection(bus="SESSION") as conn:
        deadline = time.monotonic() + timeout
        while conn.send_and_get_reply(message_bus.NameHasOwner(NAME), timeout=5).body[0]:
            if time.monotonic() >= deadline:
                raise AssertionError(f"{NAME} still has an owner")
            time.sleep(0.01)
