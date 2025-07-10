"""
SAML authenticator migrator.

This module handles the migration of SAML authenticators from AWX to Gateway.
"""

from django.conf import settings

from awx.main.utils.gateway_mapping import org_map_to_gateway_format, team_map_to_gateway_format
from awx.sso.utils.base_migrator import BaseAuthenticatorMigrator


def _split_chunks(data: str, length: int = 64) -> list[str]:
    return [data[i : i + length] for i in range(0, len(data), length)]


def _to_pem_cert(data: str) -> list[str]:
    items = ["-----BEGIN CERTIFICATE-----"]
    items += _split_chunks(data)
    items.append("-----END CERTIFICATE-----")
    return items


class SAMLMigrator(BaseAuthenticatorMigrator):
    """
    Handles the migration of SAML authenticators from AWX to Gateway.
    """

    CATEGORY = "SAML"
    AUTH_TYPE = "ansible_base.authentication.authenticator_plugins.saml"

    def get_authenticator_type(self):
        """Get the human-readable authenticator type name."""
        return "SAML"

    def get_controller_config(self):
        """
        Export SAML authenticators. A SAML authenticator is only exported if
        required configuration is present.

        Returns:
            list: List of configured SAML authentication providers with their settings
        """
        found_configs = []

        enabled = True
        remove_users = True
        create_objects = getattr(settings, "SAML_AUTO_CREATE_OBJECTS", True)
        idps = getattr(settings, "SOCIAL_AUTH_SAML_ENABLED_IDPS", {})
        security_config = getattr(settings, "SOCIAL_AUTH_SAML_SECURITY_CONFIG", {})

        org_map_value = getattr(settings, "SOCIAL_AUTH_SAML_ORGANIZATION_MAP", None)
        team_map_value = getattr(settings, "SOCIAL_AUTH_SAML_TEAM_MAP", None)
        extra_data = getattr(settings, "SOCIAL_AUTH_SAML_EXTRA_DATA", None)
        support_contact = getattr(settings, "SOCIAL_AUTH_SAML_SUPPORT_CONTACT", {})
        technical_contact = getattr(settings, "SOCIAL_AUTH_SAML_TECHNICAL_CONTACT", {})
        org_info = getattr(settings, "SOCIAL_AUTH_SAML_ORG_INFO", {})

        sp_private_key = getattr(settings, "SOCIAL_AUTH_SAML_SP_PRIVATE_KEY", None)
        sp_public_cert = getattr(settings, "SOCIAL_AUTH_SAML_SP_PUBLIC_CERT", None)
        sp_entity_id = getattr(settings, "SOCIAL_AUTH_SAML_SP_ENTITY_ID", None)
        sp_extra = getattr(settings, "SOCIAL_AUTH_SAML_SP_EXTRA", {})

        org_mappers, next_order = org_map_to_gateway_format(org_map_value, start_order=1)
        team_mappers, _ = team_map_to_gateway_format(team_map_value, start_order=next_order)

        for name, value in idps.items():
            config_data = {
                "name": name,
                "type": self.AUTH_TYPE,
                "enabled": enabled,
                "create_objects": create_objects,
                "remove_users": remove_users,
                "configuration": {
                    "IDP_URL": value.get("url"),
                    "IDP_X509_CERT": "\n".join(_to_pem_cert(value.get("x509cert"))),
                    "IDP_ENTITY_ID": value.get("entity_id"),
                    "IDP_ATTR_EMAIL": value.get("attr_email"),
                    "IDP_ATTR_USERNAME": value.get("attr_username"),
                    "IDP_ATTR_FIRST_NAME": value.get("attr_first_name"),
                    "IDP_ATTR_LAST_NAME": value.get("attr_last_name"),
                    "IDP_ATTR_USER_PERMANENT_ID": value.get("attr_user_permanent_id"),
                    "IDP_GROUPS": value.get("attr_groups"),
                    "SP_ENTITY_ID": sp_entity_id,
                    "SP_PUBLIC_CERT": sp_public_cert,
                    "SP_PRIVATE_KEY": sp_private_key,
                    "ORG_INFO": org_info,
                    "TECHNICAL_CONTACT": technical_contact,
                    "SUPPORT_CONTACT": support_contact,
                    "SECURITY_CONFIG": security_config,
                    "SP_EXTRA": sp_extra,
                    "EXTRA_DATA": extra_data,
                },
            }

            found_configs.append(
                {
                    "category": self.CATEGORY,
                    "settings": config_data,
                    "org_mappers": org_mappers,
                    "team_mappers": team_mappers,
                }
            )
        return found_configs

    def create_gateway_authenticator(self, config):
        """Create a SAML authenticator in Gateway."""
        category = config["category"]
        config_settings = config["settings"]
        name = config_settings["name"]

        # Generate authenticator name and slug
        authenticator_name = f"AWX-{category.replace('-', '_').title()}-{name}"
        authenticator_slug = self._generate_authenticator_slug("saml", category, name)

        self._write_output(f"\n--- Processing {category} authenticator ---")
        self._write_output(f"Name: {authenticator_name}")
        self._write_output(f"Slug: {authenticator_slug}")
        self._write_output(f"Type: {config_settings['type']}")

        # Build Gateway authenticator configuration
        gateway_config = {
            "name": authenticator_name,
            "slug": authenticator_slug,
            "type": config_settings["type"],
            "enabled": True,
            "create_objects": True,  # Allow Gateway to create users/orgs/teams
            "remove_users": False,  # Don't remove users by default
            "configuration": config_settings["configuration"],
        }

        # CALLBACK_URL - automatically created by Gateway
        ignore_keys = ["CALLBACK_URL"]

        # Submit the authenticator (create or update as needed)
        return self.submit_authenticator(gateway_config, ignore_keys, config)
