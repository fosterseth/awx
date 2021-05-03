# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Wayne Witzel III <wayne@riotousliving.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):

    # Automation Platform Controller documentation fragment
    DOCUMENTATION = r'''
options:
  tower_host:
    description:
    - URL to your Automation Platform Controller instance.
    - If value not set, will try environment variable C(TOWER_HOST) and then config files
    - If value not specified by any means, the value of C(127.0.0.1) will be used
    type: str
  tower_username:
    description:
    - Username for your controller instance.
    - If value not set, will try environment variable C(TOWER_USERNAME) and then config files
    type: str
  tower_password:
    description:
    - Password for your controller instance.
    - If value not set, will try environment variable C(TOWER_PASSWORD) and then config files
    type: str
  validate_certs:
    description:
    - Whether to allow insecure connections.
    - If C(no), SSL certificates will not be validated.
    - This should only be used on personally controlled sites using self-signed certificates.
    - If value not set, will try environment variable C(TOWER_VERIFY_SSL) and then config files
    type: bool
    aliases: [ tower_verify_ssl ]
  tower_config_file:
    description:
    - Path to the controller config file.
    - If provided, the other locations for config files will not be considered.
    type: path

notes:
- If no I(config_file) is provided we will attempt to use the tower-cli library
  defaults to find your host information.
- I(config_file) should be in the following format
    host=hostname
    username=username
    password=password
'''
