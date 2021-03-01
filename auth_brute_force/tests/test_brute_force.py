# -*- coding: utf-8 -*-
# Copyright 2017 Tecnativa - Jairo Llopis
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

from urllib.parse import urlencode

from mock import patch
from odoo import http
from odoo.exceptions import AccessDenied
from odoo.tests.common import at_install, HttpCase, post_install
from odoo.tools import mute_logger
from werkzeug.utils import redirect

from ..models import res_authentication_attempt, res_users

GARBAGE_LOGGERS = (
    "werkzeug",
    res_authentication_attempt.__name__,
    res_users.__name__,
)


def patch_cursor(func):
    """ Decorator that patches the current TestCursor for nested savepoint
    support """

    def acquire(cursor):
        cursor._depth += 1
        cursor._lock.acquire()
        cursor.execute("SAVEPOINT test_cursor%d" % cursor._depth)

    def release(cursor):
        cursor.execute("RELEASE SAVEPOINT test_cursor%d" % cursor._depth)
        cursor._depth -= 1
        cursor._lock.release()

    def close(cursor):
        cursor.release()

    def commit(cursor):
        cursor.execute("RELEASE SAVEPOINT test_cursor%d" % cursor._depth)
        cursor.execute("SAVEPOINT test_cursor%d" % cursor._depth)

    def rollback(cursor):
        cursor.execute(
            "ROLLBACK TO SAVEPOINT test_cursor%d" % cursor._depth)
        cursor.execute("SAVEPOINT test_cursor%d" % cursor._depth)

    def wrap(func, *args):

        def wrapped_function(self, *args):
            with self.cursor() as cursor:
                cursor.execute("SAVEPOINT test_cursor0")
                cursor._depth = 1
                cursor.execute("SAVEPOINT test_cursor%d" % cursor._depth)

                cursor.__acquire = cursor.acquire
                cursor.__release = cursor.release
                cursor.__commit = cursor.commit
                cursor.__rollback = cursor.rollback
                cursor.__close = cursor.close
                cursor.acquire = lambda: acquire(cursor)
                cursor.release = lambda: release(cursor)
                cursor.commit = lambda: commit(cursor)
                cursor.rollback = lambda: rollback(cursor)
                cursor.close = lambda: close(cursor)

            try:
                func(self, *args)
            finally:
                with self.cursor() as cursor:
                    cursor.acquire = cursor.__acquire
                    cursor.release = cursor.__release
                    cursor.commit = cursor.__commit
                    cursor.rollback = cursor.__rollback
                    cursor.close = cursor.__close

        return wrapped_function

    return wrap


@at_install(False)
@post_install(True)
# Skip CSRF validation on tests
@patch(http.__name__ + ".WebRequest.validate_csrf", return_value=True)
# Skip specific browser forgery on redirections
@patch(http.__name__ + ".redirect_with_hash", side_effect=redirect)
# Faster tests without calls to geolocation API
@patch(res_authentication_attempt.__name__ + ".urlopen", return_value="")
class BruteForceCase(HttpCase):
    def setUp(self):
        super(BruteForceCase, self).setUp()
        self.good_password = "admin"  # default password set up by demo db
        self.data_demo = {
            "login": "demo",
            "password": "Demo%&/(908409**",
        }
        with self.cursor() as cr:
            env = self.env(cr)
            env["ir.config_parameter"].set_param(
                "auth_brute_force.max_by_ip_user", 3)
            env["ir.config_parameter"].set_param(
                "auth_brute_force.max_by_ip", 4)
            # Clean attempts to be able to count in tests
            env["res.authentication.attempt"].search([]).unlink()
            # Make sure involved users have good passwords
            env.user.password = self.good_password
            env["res.users"].search([
                ("login", "=", self.data_demo["login"]),
            ]).password = self.data_demo["password"]

    # HACK https://github.com/odoo/odoo/pull/24833
    def addons_installed(self, *addons):
        """Know if the specified addons are installed."""
        found = self.env["ir.module.module"].search([
            ("name", "in", addons),
            ("state", "not in", ["uninstalled", "uninstallable"]),
        ])
        return set(addons) - set(found.mapped("name"))

    @mute_logger(*GARBAGE_LOGGERS)
    @patch_cursor
    def test_web_login_existing(self, *args):
        """Remote is banned with real user on web login form."""
        data1 = {
            "login": "admin",
            "password": "1234",  # Wrong
        }
        # Make sure user is logged out
        self.url_open("/web/session/logout", timeout=30)
        # Fail 3 times
        for n in range(3):
            response = self.url_open("/web/login", bytes(urlencode(data1)), 30)
            # If you fail, you get /web/login again
            self.assertTrue(
                response.geturl().endswith("/web/login"),
                "Unexpected URL %s" % response.geturl(),
            )
        # Admin banned, demo not
        with self.cursor() as cr:
            env = self.env(cr)
            self.assertFalse(
                env["res.authentication.attempt"]._trusted(
                    "127.0.0.1",
                    data1["login"],
                ),
            )
            self.assertTrue(
                env["res.authentication.attempt"]._trusted(
                    "127.0.0.1",
                    "demo",
                ),
            )
        # Now I know the password, but login is rejected too
        data1["password"] = self.good_password
        response = self.url_open("/web/login", bytes(urlencode(data1)), 30)
        self.assertTrue(
            response.geturl().endswith("/web/login"),
            "Unexpected URL %s" % response.geturl(),
        )
        # IP has been banned, demo user cannot login
        with self.cursor() as cr:
            env = self.env(cr)
            self.assertFalse(
                env["res.authentication.attempt"]._trusted(
                    "127.0.0.1",
                    "demo",
                ),
            )
        # Attempts recorded
        with self.cursor() as cr:
            env = self.env(cr)
            failed = env["res.authentication.attempt"].search([
                ("result", "=", "failed"),
                ("login", "=", data1["login"]),
                ("remote", "=", "127.0.0.1"),
            ])
            self.assertEqual(len(failed), 3)
            banned = env["res.authentication.attempt"].search([
                ("result", "=", "banned"),
                ("remote", "=", "127.0.0.1"),
            ])
            self.assertEqual(len(banned), 1)
            # Unban
            banned.action_whitelist_add()
        # Try good login, it should work now
        response = self.url_open("/web/login", bytes(urlencode(data1)), 30)
        self.assertTrue(response.geturl().endswith("/web"))

    @mute_logger(*GARBAGE_LOGGERS)
    @patch_cursor
    def test_web_login_unexisting(self, *args):
        """Remote is banned with fake user on web login form."""
        data1 = {
            "login": "administrator",  # Wrong
            "password": self.good_password,
        }
        # Make sure user is logged out
        self.url_open("/web/session/logout", timeout=30)
        # Fail 3 times
        for n in range(3):
            response = self.url_open("/web/login", bytes(urlencode(data1)), 30)
            # If you fail, you get /web/login again
            self.assertTrue(
                response.geturl().endswith("/web/login"),
                "Unexpected URL %s" % response.geturl(),
            )
        # Admin banned, demo not
        with self.cursor() as cr:
            env = self.env(cr)
            self.assertFalse(
                env["res.authentication.attempt"]._trusted(
                    "127.0.0.1",
                    data1["login"],
                ),
            )
            self.assertTrue(
                env["res.authentication.attempt"]._trusted(
                    "127.0.0.1",
                    self.data_demo["login"],
                ),
            )
        # Demo user can login
        response = self.url_open(
            "/web/login",
            bytes(urlencode(self.data_demo)),
            30,
        )
        # If you pass, you get /web
        self.assertTrue(
            response.geturl().endswith("/web"),
            "Unexpected URL %s" % response.geturl(),
        )
        self.url_open("/web/session/logout", timeout=30)
        # Attempts recorded
        with self.cursor() as cr:
            env = self.env(cr)
            failed = env["res.authentication.attempt"].search([
                ("result", "=", "failed"),
                ("login", "=", data1["login"]),
                ("remote", "=", "127.0.0.1"),
            ])
            self.assertEqual(len(failed), 3)
            banned = env["res.authentication.attempt"].search([
                ("result", "=", "banned"),
                ("login", "=", data1["login"]),
                ("remote", "=", "127.0.0.1"),
            ])
            self.assertEqual(len(banned), 0)

    @mute_logger(*GARBAGE_LOGGERS)
    @patch_cursor
    def test_xmlrpc_login_existing(self, *args):
        """Remote is banned with real user on XML-RPC login."""
        data1 = {
            "login": "admin",
            "password": "1234",  # Wrong
        }
        # Fail 3 times
        for n in range(3):
            self.assertFalse(self.xmlrpc_common.authenticate(
                self.env.cr.dbname, data1["login"], data1["password"], {}))
        # Admin banned, demo not
        with self.cursor() as cr:
            env = self.env(cr)
            self.assertFalse(
                env["res.authentication.attempt"]._trusted(
                    "127.0.0.1",
                    data1["login"],
                ),
            )
            self.assertTrue(
                env["res.authentication.attempt"]._trusted(
                    "127.0.0.1",
                    "demo",
                ),
            )
        # Now I know the password, but login is rejected too
        data1["password"] = self.good_password
        self.assertFalse(self.xmlrpc_common.authenticate(
            self.env.cr.dbname, data1["login"], data1["password"], {}))
        # IP has been banned, demo user cannot login
        with self.cursor() as cr:
            env = self.env(cr)
            self.assertFalse(
                env["res.authentication.attempt"]._trusted(
                    "127.0.0.1",
                    "demo",
                ),
            )
        # Attempts recorded
        with self.cursor() as cr:
            env = self.env(cr)
            failed = env["res.authentication.attempt"].search([
                ("result", "=", "failed"),
                ("login", "=", data1["login"]),
                ("remote", "=", "127.0.0.1"),
            ])
            self.assertEqual(len(failed), 3)
            banned = env["res.authentication.attempt"].search([
                ("result", "=", "banned"),
                ("remote", "=", "127.0.0.1"),
            ])
            self.assertEqual(len(banned), 1)
            # Unban
            banned.action_whitelist_add()
        # Try good login, it should work now
        self.assertTrue(self.xmlrpc_common.authenticate(
            self.env.cr.dbname, data1["login"], data1["password"], {}))

    @mute_logger(*GARBAGE_LOGGERS)
    @patch_cursor
    def test_xmlrpc_login_unexisting(self, *args):
        """Remote is banned with fake user on XML-RPC login."""
        data1 = {
            "login": "administrator",  # Wrong
            "password": self.good_password,
        }
        # Fail 3 times
        for n in range(3):
            self.assertFalse(self.xmlrpc_common.authenticate(
                self.env.cr.dbname, data1["login"], data1["password"], {}))
        # Admin banned, demo not
        with self.cursor() as cr:
            env = self.env(cr)
            self.assertFalse(
                env["res.authentication.attempt"]._trusted(
                    "127.0.0.1",
                    data1["login"],
                ),
            )
            self.assertTrue(
                env["res.authentication.attempt"]._trusted(
                    "127.0.0.1",
                    self.data_demo["login"],
                ),
            )
        # Demo user can login
        self.assertTrue(self.xmlrpc_common.authenticate(
            self.env.cr.dbname,
            self.data_demo["login"],
            self.data_demo["password"],
            {},
        ))
        # Attempts recorded
        with self.cursor() as cr:
            env = self.env(cr)
            failed = env["res.authentication.attempt"].search([
                ("result", "=", "failed"),
                ("login", "=", data1["login"]),
                ("remote", "=", "127.0.0.1"),
            ])
            self.assertEqual(len(failed), 3)
            banned = env["res.authentication.attempt"].search([
                ("result", "=", "banned"),
                ("login", "=", data1["login"]),
                ("remote", "=", "127.0.0.1"),
            ])
            self.assertEqual(len(banned), 0)

    @mute_logger(*GARBAGE_LOGGERS)
    def test_orm_login_existing(self, *args):
        """No bans on ORM login with an existing user."""
        data1 = {
            "login": "admin",
            "password": "1234",  # Wrong
        }
        with self.cursor() as cr:
            env = self.env(cr)
            # Fail 3 times
            auth_args = [cr.dbname, data1["login"], data1["password"], {}]
            for n in range(3):
                self.assertRaises(AccessDenied, env["res.users"].authenticate, *auth_args)
            self.assertEqual(
                env["res.authentication.attempt"].search(count=True, args=[]),
                0,
            )
            self.assertTrue(
                env["res.authentication.attempt"]._trusted(
                    "127.0.0.1",
                    data1["login"],
                ),
            )
            # Now I know the password, and login works
            data1["password"] = self.good_password
            self.assertTrue(
                env["res.users"].authenticate(
                    cr.dbname, data1["login"], data1["password"], {}))

    @mute_logger(*GARBAGE_LOGGERS)
    def test_orm_login_unexisting(self, *args):
        """No bans on ORM login with an unexisting user."""
        data1 = {
            "login": "administrator",  # Wrong
            "password": self.good_password,
        }
        with self.cursor() as cr:
            env = self.env(cr)
            auth_args = [cr.dbname, data1["login"], data1["password"], {}]
            # Fail 3 times
            for n in range(3):
                self.assertRaises(AccessDenied, env["res.users"].authenticate, *auth_args)
            self.assertEqual(
                env["res.authentication.attempt"].search(count=True, args=[]),
                0,
            )
            self.assertTrue(
                env["res.authentication.attempt"]._trusted(
                    "127.0.0.1",
                    data1["login"],
                ),
            )
            # Now I know the user, and login works
            data1["login"] = "admin"
            self.assertTrue(
                env["res.users"].authenticate(
                    cr.dbname, data1["login"], data1["password"], {}))
