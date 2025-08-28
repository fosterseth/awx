"""
SAML authenticator migrator.

This module handles the migration of SAML authenticators from AWX to Gateway.
"""

from django.conf import settings

from awx.main.utils.gateway_mapping import org_map_to_gateway_format, team_map_to_gateway_format
from awx.sso.utils.base_migrator import BaseAuthenticatorMigrator

ROLE_MAPPER = {
    "is_superuser_role": {"role": None, "map_type": "is_superuser", "revoke": "remove_superusers"},
    "is_system_auditor_role": {"role": "Platform Auditor", "map_type": "role", "revoke": "remove_system_auditors"},
}

ATTRIBUTE_VALUE_MAPPER = {
    "is_superuser_attr": {"role": None, "map_type": "is_superuser", "value": "is_superuser_value", "revoke": "remove_superusers"},
    "is_system_auditor_attr": {"role": "Platform Auditor", "map_type": "role", "value": "is_system_auditor_value", "revoke": "remove_system_auditors"},
}

ORG_ATTRIBUTE_MAPPER = {
    "saml_attr": {"role": "Organization Member", "revoke": "remove"},
    "saml_admin_attr": {"role": "Organization Admin", "revoke": "remove_admins"},
}


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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.next_order = 1
        self.team_mappers = []

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

        enabled = False
        remove_users = True
        create_objects = getattr(settings, "SAML_AUTO_CREATE_OBJECTS", True)
        idps = getattr(settings, "SOCIAL_AUTH_SAML_ENABLED_IDPS", {})
        security_config = getattr(settings, "SOCIAL_AUTH_SAML_SECURITY_CONFIG", {})

        # Get org and team mappings using the new fallback functions
        org_map_value = self.get_social_org_map("SOCIAL_AUTH_SAML_ORGANIZATION_MAP")
        team_map_value = self.get_social_team_map("SOCIAL_AUTH_SAML_TEAM_MAP")
        self.extra_data = getattr(settings, "SOCIAL_AUTH_SAML_EXTRA_DATA", [])
        self._add_to_extra_data(['Role', 'Role'])

        support_contact = getattr(settings, "SOCIAL_AUTH_SAML_SUPPORT_CONTACT", {})
        technical_contact = getattr(settings, "SOCIAL_AUTH_SAML_TECHNICAL_CONTACT", {})
        org_info = getattr(settings, "SOCIAL_AUTH_SAML_ORG_INFO", {})

        sp_private_key = getattr(settings, "SOCIAL_AUTH_SAML_SP_PRIVATE_KEY", None)
        sp_public_cert = getattr(settings, "SOCIAL_AUTH_SAML_SP_PUBLIC_CERT", None)
        sp_entity_id = getattr(settings, "SOCIAL_AUTH_SAML_SP_ENTITY_ID", None)
        sp_extra = getattr(settings, "SOCIAL_AUTH_SAML_SP_EXTRA", {})
        saml_team_attr = getattr(settings, "SOCIAL_AUTH_SAML_TEAM_ATTR", {})
        org_attr = getattr(settings, "SOCIAL_AUTH_SAML_ORGANIZATION_ATTR", {})
        user_flags_by_attr = getattr(settings, "SOCIAL_AUTH_SAML_USER_FLAGS_BY_ATTR", {})
        login_redirect_override = getattr(settings, "LOGIN_REDIRECT_OVERRIDE", None)

        org_mappers, self.next_order = org_map_to_gateway_format(org_map_value, start_order=self.next_order)
        self.team_mappers, self.next_order = team_map_to_gateway_format(team_map_value, start_order=self.next_order)

        self._team_attr_to_gateway_format(saml_team_attr)
        self._user_flags_by_role_to_gateway_format(user_flags_by_attr)
        self._user_flags_by_attr_value_to_gateway_format(user_flags_by_attr)
        self._org_attr_to_gateway_format(org_attr)

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
                    "EXTRA_DATA": self.extra_data,
                },
            }

            found_configs.append(
                {
                    "category": self.CATEGORY,
                    "settings": config_data,
                    "org_mappers": org_mappers,
                    "team_mappers": self.team_mappers,
                    "login_redirect_override": login_redirect_override,
                }
            )
        return found_configs

    def create_gateway_authenticator(self, config):
        """Create a SAML authenticator in Gateway."""
        category = config["category"]
        config_settings = config["settings"]
        name = config_settings["name"]

        # Generate authenticator name and slug
        authenticator_name = f"{category.replace('-', '_').title()}-{name}"
        authenticator_slug = self._generate_authenticator_slug("saml", name)

        self._write_output(f"\n--- Processing {category} authenticator ---")
        self._write_output(f"Name: {authenticator_name}")
        self._write_output(f"Slug: {authenticator_slug}")
        self._write_output(f"Type: {config_settings['type']}")

        # Build Gateway authenticator configuration
        gateway_config = {
            "name": authenticator_name,
            "slug": authenticator_slug,
            "type": config_settings["type"],
            "enabled": False,
            "create_objects": True,  # Allow Gateway to create users/orgs/teams
            "remove_users": False,  # Don't remove users by default
            "configuration": config_settings["configuration"],
        }

        # CALLBACK_URL - automatically created by Gateway
        ignore_keys = ["CALLBACK_URL", "SP_PRIVATE_KEY"]

        # Submit the authenticator (create or update as needed)
        result = self.submit_authenticator(gateway_config, ignore_keys, config)

        # Handle LOGIN_REDIRECT_OVERRIDE if applicable
        valid_login_urls = [f'/sso/login/saml/?idp={name}', f'/sso/login/saml/?idp={name}/']
        self.handle_login_override(config, valid_login_urls)

        return result

    def _team_attr_to_gateway_format(self, saml_team_attr):
        saml_attr = saml_team_attr.get("saml_attr")
        if not saml_attr:
            return

        revoke = saml_team_attr.get('remove', True)
        self._add_to_extra_data([saml_attr, saml_attr])

        for item in saml_team_attr["team_org_map"]:
            team_list = item["team"]
            if isinstance(team_list, str):
                team_list = [team_list]
            team = item.get("team_alias") or item["team"]
            self.team_mappers.append(
                {
                    "map_type": "team",
                    "role": "Team Member",
                    "organization": item["organization"],
                    "team": team,
                    "name": "Team" + "-" + team + "-" + item["organization"],
                    "revoke": revoke,
                    "authenticator": -1,
                    "triggers": {"attributes": {saml_attr: {"in": team_list}, "join_condition": "or"}},
                    "order": self.next_order,
                }
            )
            self.next_order += 1

    def _user_flags_by_role_to_gateway_format(self, user_flags_by_attr):
        for k, v in ROLE_MAPPER.items():
            if k in user_flags_by_attr:
                if v['role']:
                    name = f"Role-{v['role']}"
                else:
                    name = f"Role-{v['map_type']}"

                revoke = user_flags_by_attr.get(v['revoke'], True)
                self.team_mappers.append(
                    {
                        "map_type": v["map_type"],
                        "role": v["role"],
                        "name": name,
                        "organization": None,
                        "team": None,
                        "revoke": revoke,
                        "order": self.next_order,
                        "authenticator": -1,
                        "triggers": {
                            "attributes": {
                                "Role": {"in": user_flags_by_attr[k]},
                                "join_condition": "or",
                            }
                        },
                    }
                )
                self.next_order += 1

    def _user_flags_by_attr_value_to_gateway_format(self, user_flags_by_attr):
        for k, v in ATTRIBUTE_VALUE_MAPPER.items():
            if k in user_flags_by_attr:
                value = user_flags_by_attr.get(v['value'])

                if value:
                    if isinstance(value, list):
                        value = {'in': value}
                    else:
                        value = {'in': [value]}
                else:
                    value = {}

                revoke = user_flags_by_attr.get(v['revoke'], True)
                attr_name = user_flags_by_attr[k]
                self._add_to_extra_data([attr_name, attr_name])

                if v['role']:
                    name = f"Role-{v['role']}-attr"
                else:
                    name = f"Role-{v['map_type']}-attr"

                self.team_mappers.append(
                    {
                        "map_type": v["map_type"],
                        "role": v["role"],
                        "name": name,
                        "organization": None,
                        "team": None,
                        "revoke": revoke,
                        "order": self.next_order,
                        "authenticator": -1,
                        "triggers": {
                            "attributes": {
                                attr_name: value,
                                "join_condition": "or",
                            }
                        },
                    }
                )
                self.next_order += 1

    def _org_attr_to_gateway_format(self, org_attr):
        for k, v in ORG_ATTRIBUTE_MAPPER.items():
            if k in org_attr:
                attr_name = org_attr.get(k)
                organization = "{% " + f"for_attr_value('{attr_name}')" + " %}"
                revoke = org_attr.get(v['revoke'], True)

                self._add_to_extra_data([attr_name, attr_name])

                name = f"Role-{v['role']}-attr"
                self.team_mappers.append(
                    {
                        "map_type": 'organization',
                        "role": v['role'],
                        "name": name,
                        "organization": organization,
                        "team": None,
                        "revoke": revoke,
                        "order": self.next_order,
                        "authenticator": -1,
                        "triggers": {
                            "attributes": {
                                attr_name: {},
                                "join_condition": "or",
                            }
                        },
                    }
                )
                self.next_order += 1

    def _add_to_extra_data(self, item: list):
        if item not in self.extra_data:
            self.extra_data.append(item)
