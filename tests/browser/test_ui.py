"""Native-UI peer unit doubles; no real browser or authenticator results."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import ui


class Node:
    def __init__(self, name, role, *children, focus=True):
        self.name, self.role, self.children, self.focus = name, role, children, focus
        self.action = MagicMock(nActions=1)
        self.action.doAction.return_value = True

    def __iter__(self):
        return iter(self.children)

    def getState(self):
        return SimpleNamespace(contains=lambda _: True)

    def getRoleName(self):
        return self.role

    def queryComponent(self):
        return SimpleNamespace(grabFocus=lambda: self.focus)

    def queryAction(self):
        return self.action


def api(*items):
    return SimpleNamespace(STATE_SHOWING=1, STATE_VISIBLE=2,
                           Registry=SimpleNamespace(getDesktop=lambda _: [Node('test browser', 'application', *items)]))


class UI(unittest.TestCase):
    def test_pin_requires_focus_and_stays_out_of_argv_and_tree(self):
        password = Node('protected value', 'password text')
        with patch.object(ui.subprocess, 'run') as execute:
            result = ui.operate({'pin': 'unit-secret'}, api(password))
        self.assertEqual(result['action_kind'], 'pin')
        self.assertNotIn('unit-secret', json.dumps(result))
        self.assertNotIn('protected value', json.dumps(result))
        self.assertTrue(any(c.kwargs.get('input') == b'unit-secret' for c in execute.call_args_list))
        self.assertFalse(any('unit-secret' in str(c.args) for c in execute.call_args_list))
        with patch.object(ui.subprocess, 'run') as execute:
            with self.assertRaisesRegex(RuntimeError, 'could not focus'):
                ui.operate({'pin': 'unit-secret'}, api(Node('PIN', 'password text', focus=False)))
            execute.assert_not_called()

    def test_only_the_exact_expected_account_is_chosen(self):
        bob, bobby = Node('bob', 'push button'), Node('bobby', 'push button')
        result = ui.operate({'account': 'bob'}, api(bobby, bob))
        self.assertEqual(result['action_kind'], 'account')
        bob.action.doAction.assert_called_once()
        bobby.action.doAction.assert_not_called()

    def test_chromium_pin_uses_the_native_next_button(self):
        next_button = Node('Next', 'push button')
        dialog = Node('PIN required', 'dialog', Node('PIN', 'password text'), next_button)
        with patch.object(ui.subprocess, 'run') as execute:
            result = ui.operate({'pin': 'unit-secret'}, api(dialog))
        self.assertEqual(result['action_kind'], 'pin')
        next_button.action.doAction.assert_called_once_with(0)
        self.assertEqual(execute.call_count, 2)

    def test_firefox_account_access_keys_and_opaque_selection(self):
        bob, bobby = Node('bob (1)', 'menu item'), Node('bobby (0)', 'menu item')
        self.assertEqual(ui.operate({'account': 'bob'}, api(bobby, bob))['action_kind'], 'account')
        bob.action.doAction.assert_called_once()
        bobby.action.doAction.assert_not_called()
        unknown = Node('Unknown account (2)', 'menu item')
        ui.operate({'account': 'alice'}, api(unknown))
        unknown.action.doAction.assert_not_called()
        self.assertEqual(ui.operate({'account': 'alice', 'opaque_account': 'Unknown account (2)'}, api(unknown))['action_kind'], 'account')
        unknown.action.doAction.assert_called_once()
        more = Node('Unknown account (0) More Options', 'push button')
        self.assertEqual(ui.operate({'account': 'bob'}, api(more))['action_kind'], 'account-menu')

    def test_duplicate_screen_does_not_repeat_input(self):
        password = Node('PIN', 'password text')
        with patch.object(ui.subprocess, 'run') as execute:
            first = ui.operate({'pin': 'unit-secret'}, api(password))
            again = ui.operate({'pin': 'unit-secret', 'last_fingerprint': first['fingerprint']}, api(password))
        self.assertIsNone(again['action'])
        self.assertEqual(execute.call_count, 3)

    def test_incompatibility_requires_specific_visible_text(self):
        cancel = Node('Cancel', 'push button')
        result = ui.operate({}, api(Node('Something went wrong', 'label'), cancel))
        self.assertEqual(result['evidence'], [])
        cancel.action.doAction.assert_not_called()
        result = ui.operate({}, api(Node("This security key can't be used", 'label'), cancel))
        self.assertEqual(result['evidence'], ['unsupported-key'])
        self.assertEqual(result['action_kind'], 'dismiss-incompatibility')

    def test_tree_traversal_is_bounded(self):
        with self.assertRaisesRegex(RuntimeError, 'bounded traversal'):
            list(ui.nodes(Node('a', 'application', Node('b', 'label')), limit=1))


if __name__ == '__main__':
    unittest.main()
