"""
RADIUS authenticator migrator.

This module handles the migration of RADIUS authenticators from AWX to Gateway.
"""

from django.conf import settings

from awx.sso.utils.base_migrator import BaseAuthenticatorMigrator


class RADIUSMigrator(BaseAuthenticatorMigrator):
    """
    Handles the migration of RADIUS authenticators from AWX to Gateway.
    """

    CATEGORY = "RADIUS"
    AUTH_TYPE = "ansible_base.authentication.authenticator_plugins.radius"

    def get_authenticator_type(self):
        """Get the human-readable authenticator type name."""
        return "RADIUS"

    def get_controller_config(self):
        """
        Export RADIUS authenticators. A RADIUS authenticator is only exported if
        required configuration is present.

        Returns:
            list: List of configured RADIUS authentication providers with their settings
        """
        server = getattr(settings, "RADIUS_SERVER", None)
        if not server:
            return []

        port = getattr(settings, "RADIUS_PORT", 1812)
        secret = getattr(settings, "RADIUS_SECRET", "")

        config_data = {
            "name": "default",
            "type": self.AUTH_TYPE,
            "enabled": True,
            "create_objects": True,
            "remove_users": False,
            "configuration": {
                "SERVER": server,
                "PORT": port,
                "SECRET": secret,
            },
        }

        return [
            {
                "category": self.CATEGORY,
                "settings": config_data,
            }
        ]

    def create_gateway_authenticator(self, config):
        """Create a RADIUS authenticator in Gateway."""
        category = config["category"]
        config_settings = config["settings"]
        name = config_settings["name"]

        # Generate authenticator name and slug
        authenticator_name = f"AWX-{category.replace('-', '_').title()}-{name}"
        authenticator_slug = self._generate_authenticator_slug("radius", category)

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
