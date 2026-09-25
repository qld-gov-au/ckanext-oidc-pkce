import pytest

from ckan import model

from ckanext.oidc_pkce import utils
import ckan.plugins.toolkit as tk


@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestSyncUser:
    def test_user_created(self, user_info):
        utils.sync_user(user_info)

        assert model.User.by_email(user_info["email"])

    def test_existing_user_attached(self, user_factory, user_info):
        user = user_factory(email=user_info["email"])
        utils.sync_user(user_info)

        attached = model.User.by_email(user_info["email"])
        if isinstance(attached, list):
            # CKAN < 2.10
            attached = attached[0]

        assert user["id"] == attached.id

    def test_sync_by_case_insensitive_email(self, user_factory, user_info):
        user = user_factory(email=user_info["email"].upper())
        utils.sync_user(user_info)

        attached = model.User.by_email(user_info["email"])
        if isinstance(attached, list):
            # CKAN < 2.10
            attached = attached[0]

        assert user["id"] == attached.id

    @pytest.mark.skipif(tk.check_ckan_version("2.12"), reason="This is for ckan 2.11 and before")
    def test_2_11_sync_ignores_deleted_users(self, user_factory, user_info):
        deleted_user = user_factory(
            email=user_info["email"],
            state="deleted",
        )
        active_user = user_factory(
            email=user_info["email"],
            state="active",
        )

        attached = utils.sync_user(user_info)

        assert attached.id == active_user["id"]
        assert attached.id != deleted_user["id"]

    @pytest.mark.skipif(tk.check_ckan_version("2.12"), reason="This is for ckan 2.11 and before")
    def test_2_11_sync_email_is_unique_with_active_reused_email(self, user_factory, user_info):
        """Configuration to allow only active emails to be linked
        """
        deleted_user = user_factory(
            email=user_info["email"],
            state="deleted",
        )
        active_user = user_factory(
            email=user_info["email"],
            state="active",
        )

        attached = utils.sync_user(user_info)

        assert attached.id == active_user["id"]
        assert attached.id != deleted_user["id"]

    @pytest.mark.skipif(not tk.check_ckan_version("2.12"), reason="This is for ckan 2.12+")
    @pytest.mark.ckan_config("ckan.user.unique_email_states", ["active"])
    def test_2_12_sync_email_is_unique_with_no_active_email_found_new_user_created(self, user_factory, user_info):
        """Configuration to ignore deleted user and create new user account on SSO
        """
        deleted_user = user_factory(
            email=user_info["email"],
            state="deleted",
        )

        attached = utils.sync_user(user_info)

        assert attached.id != deleted_user["id"]

    @pytest.mark.skipif(not tk.check_ckan_version("2.12"), reason="This is for ckan 2.12+")
    @pytest.mark.ckan_config("ckan.user.unique_email_states", ["active", "deleted"])
    def test_2_12_sync_email_is_unique_with_unallowed_reused_email(self, user_factory, user_info):
        """Configuration can allow deleted user to be returned when configured to only have 1 unique email in db
        """

        deleted_user = user_factory(
            email=user_info["email"],
            state="deleted",
        )

        attached = utils.sync_user(user_info)

        assert attached.id == deleted_user["id"]

    @pytest.mark.skipif(not tk.check_ckan_version("2.12"), reason="This is for ckan 2.12+")
    def test_2_12_sync_email_is_not_unique_duplicate_found_error(self, user_factory, user_info):
        """Miss Configuration where deleted is included can return duplicates, so none are returned
        """

        user_factory(
            email=user_info["email"],
            state="deleted",
        )
        user_factory(
            email=user_info["email"],
            state="active",
        )

        # Make both now be included i.e. for long lived systems and requirement changes
        tk.config["ckan.user.unique_email_states"] = ["active", "deleted"]

        attached = utils.sync_user(user_info)

        assert attached is None
