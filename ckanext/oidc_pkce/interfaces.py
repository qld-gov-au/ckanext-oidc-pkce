# encoding: utf-8

from __future__ import annotations

import logging
import secrets
from typing import Any, Optional

import ckan.plugins.toolkit as tk
from ckan import model
from ckan.logic.action.create import _get_random_username_from_email
from ckan.plugins import Interface

from . import config, signals

log = logging.getLogger(__name__)


class IOidcPkce(Interface):
    """ """

    def get_oidc_user(self, userinfo: dict[str, Any]) -> Optional[model.User]:
        q = model.Session.query(model.User)

        user = q.filter(
            model.User.plugin_extras["oidc_pkce"]["sub"].astext
            == userinfo["sub"]
        ).one_or_none()

        if user:
            signals.user_exist.send(user.id)
            return user

        users = q.filter(
            model.User.email.ilike(userinfo["email"])
        ).all()
        if len(users) > 1:
            log.error("Unable to uniquely identify account, found %s matches for: %s",
                      len(users), userinfo["email"])
            return None
        elif users:
            user = users[0]
            admin = tk.get_action("get_site_user")({"ignore_auth": True}, {})
            user_dict = tk.get_action("user_show")(
                {"user": admin["name"]},
                {"id": user.id, "include_plugin_extras": True},
            )
            # Don't assemble a full user from OIDC as we don't need or want all of it
            data = {
                "fullname": user_dict.get("fullname", userinfo["name"]),
                "plugin_extras": user_dict.get("plugin_extras", None) or {} | self.oidc_info_into_plugin_extras(userinfo)
            }

            if config.munge_password():
                data["password"] = self._generate_password()
            user_dict.update(data)
            user_dict.pop("name")  # Username is untouched, so exclude it from the update payload.
            tk.get_action("user_patch")({"user": admin["name"]}, user_dict)

            signals.user_sync.send(user.id)
            return user

        return self.create_oidc_user(userinfo)

    def _generate_password(self):
        return secrets.token_urlsafe(60) + "1A!a_"

    def oidc_info_into_plugin_extras(
        self, userinfo: dict[str, Any]
    ) -> dict[str, Any]:
        return {"oidc_pkce": userinfo.copy()}

    def oidc_info_into_user_dict(
        self, userinfo: dict[str, Any]
    ) -> dict[str, Any]:
        data = {
            "email": userinfo["email"],
            "name": _get_random_username_from_email(userinfo["email"]),
            "password": self._generate_password(),
            "fullname": userinfo["name"],
            "plugin_extras": self.oidc_info_into_plugin_extras(userinfo),
        }

        if config.same_id():
            data["id"] = userinfo["sub"]

        return data

    def create_oidc_user(self, userinfo: dict[str, Any]) -> model.User:
        user_dict = self.oidc_info_into_user_dict(userinfo)
        admin = tk.get_action("get_site_user")({"ignore_auth": True}, {})
        user = tk.get_action("user_create")({"user": admin["name"]}, user_dict)

        signals.user_create.send(user["id"])
        return model.User.get(user["id"])

    def oidc_login_response(self, user: model.User) -> Any:
        return None
