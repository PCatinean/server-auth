# -*- coding: utf-8 -*-
# Copyright 2017 Tecnativa - Jairo Llopis
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

import logging
from collections import namedtuple
from contextlib import contextmanager
from threading import current_thread

from odoo import api, http, models, SUPERUSER_ID
from odoo.exceptions import AccessDenied

_logger = logging.getLogger(__name__)

AuthResult = namedtuple("Attempt", field_names=["attempt_id", "results"])


class ResUsers(models.Model):
    _inherit = "res.users"

    # Helpers to track authentication attempts
    @classmethod
    @contextmanager
    def _auth_attempt(cls, login):
        """Start an authentication attempt and track its state."""
        # Check if this call is nested
        auth_result = getattr(current_thread(), "auth_result", None)
        if auth_result is None:
            # try to create new attempt in DB
            attempt_id = cls._auth_attempt_new(login)
            if not attempt_id:
                # No attempt was created, so there's nothing to do here
                yield
                return
            auth_result = AuthResult(attempt_id=attempt_id, results=[])
            current_thread().auth_result = auth_result
        try:
            result = "successful"
            auth_result.results.append(result)
            try:
                yield
            except AccessDenied as error:
                result = getattr(error, "reason", "failed")
                auth_result.results[-1] = result  # override the last result
                raise
            finally:
                cls._auth_attempt_update({"result": result})
        finally:
            try:
                auth_result = current_thread().auth_result
                auth_result.results.pop()
                if len(auth_result.results) == 0:
                    del current_thread().auth_result
            except AttributeError:
                pass  # It was deleted already

    @classmethod
    def _auth_attempt_force_raise(cls, login, method):
        """Force a method to raise an AccessDenied on falsey return."""
        with cls._auth_attempt(login):
            result = method()
            if not result:
                # Force exception to record auth failure
                raise AccessDenied()
            return result

    @classmethod
    def _auth_attempt_new(cls, login):
        """Store one authentication attempt, not knowing the result."""
        # Get the right remote address
        try:
            remote_addr = http.request.httprequest.remote_addr
        except (RuntimeError, AttributeError):
            remote_addr = False
        # Exit if it doesn't make sense to store this attempt
        if not remote_addr:
            return False
        # Use a separate cursor to keep changes always
        with cls.pool.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            attempt = env["res.authentication.attempt"].create({
                "login": login,
                "remote": remote_addr,
            })
            return attempt.id

    @classmethod
    def _auth_attempt_update(cls, values):
        """Update a given auth attempt if we still ignore its result."""
        auth_result = getattr(current_thread(), "auth_result", False)
        if not auth_result:
            return {}  # No running auth attempt; nothing to do
        # Use a separate cursor to keep changes always
        with cls.pool.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            auth_id = auth_result.attempt_id
            attempt = env["res.authentication.attempt"].browse(auth_id)
            attempt.write(values)
            return attempt.copy_data()[0] if attempt else {}

    # Override all auth-related core methods
    @classmethod
    def _login(cls, db, login, password):
        return cls._auth_attempt_force_raise(
            login,
            lambda: super(ResUsers, cls)._login(db, login, password),
        )

    @classmethod
    def authenticate(cls, db, login, password, user_agent_env):
        return cls._auth_attempt_force_raise(
            login,
            lambda: super(ResUsers, cls).authenticate(
                db, login, password, user_agent_env),
        )

    @api.model
    def _check_credentials(self, password):
        """This is the most important and specific auth check method.

        When we get here, it means that Odoo already checked the user exists
        in this database.

        Other auth methods usually plug here.
        """
        login = self.env.user.login
        with self._auth_attempt(login):
            # Update login, just in case we stored the UID before
            attempt = self._auth_attempt_update({"login": login})
            remote = attempt.get("remote")
            # Fail if the remote is banned
            trusted = self.env["res.authentication.attempt"]._trusted(
                remote,
                login,
            )
            if not trusted:
                error = AccessDenied()
                error.reason = "banned"
                raise error
            # Continue with other auth systems
            return super(ResUsers, self)._check_credentials(password)
