"""
TACACS+ authenticator migrator.

This module handles the migration of TACACS+ authenticators from AWX to Gateway.
"""

from django.conf import settings

from awx.sso.utils.base_migrator import BaseAuthenticatorMigrator


class TACACSMigrator(BaseAuthenticatorMigrator):
    """
    Handles the migration of TACACS+ authenticators from AWX to Gateway.
    """

    CATEGORY = "TACACS+"
    AUTH_TYPE = "ansible_base.authentication.authenticator_plugins.tacacs"

    def get_authenticator_type(self):
        """Get the human-readable authenticator type name."""
        return "TACACS+"

    def get_controller_config(self):
        """
        Export TACACS+ authenticator. A TACACS+ authenticator is only exported if
        required configuration is present.

        Returns:
            list: List of configured TACACS+ authentication providers with their settings
        """
        host = getattr(settings, "TACACSPLUS_HOST", None)
        if not host:
            return []

        port = getattr(settings, "TACACSPLUS_PORT", 49)
        secret = getattr(settings, "TACACSPLUS_SECRET", "")
        session_timeout = getattr(settings, "TACACSPLUS_SESSION_TIMEOUT", 5)
        auth_protocol = getattr(settings, "TACACSPLUS_AUTH_PROTOCOL", "ascii")
        rem_addr = getattr(settings, "TACACSPLUS_REM_ADDR", False)

        config_data = {
            "name": "default",
            "type": self.AUTH_TYPE,
            "enabled": True,
            "create_objects": True,
            "remove_users": False,
            "configuration": {
                "HOST": host,
                "PORT": port,
                "SECRET": secret,
                "SESSION_TIMEOUT": session_timeout,
                "AUTH_PROTOCOL": auth_protocol,
                "REM_ADDR": rem_addr,
            },
        }

        return [
            {
                "category": self.CATEGORY,
                "settings": config_data,
            }
        ]

    def create_gateway_authenticator(self, config):
        """Create a TACACS+ authenticator in Gateway."""
        category = config["category"]
        config_settings = config["settings"]

        # Generate authenticator name and slug
        authenticator_name = "tacacs"
        authenticator_slug = self._generate_authenticator_slug("tacacs", category)

        self._write_output(f"\n--- Processing {category} authenticator ---")
        self._write_output(f"Name: {authenticator_name}")
        self._write_output(f"Slug: {authenticator_slug}")
        self._write_output(f"Type: {config_settings['type']}")

        # Build Gateway authenticator configuration
        gateway_config = {
            "name": authenticator_name,
            "slug": authenticator_slug,
            "type": config_settings["type"],
            "enabled": config_settings["enabled"],
            "create_objects": config_settings["create_objects"],
            "remove_users": config_settings["remove_users"],
            "configuration": config_settings["configuration"],
        }

        # Submit the authenticator (create or update as needed)
        return self.submit_authenticator(gateway_config, config=config)
