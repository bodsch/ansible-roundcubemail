#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2024, Bodo Schulz <bodo@boone-schulz.de>

from __future__ import print_function

# import os
# import re
import json

from ansible.module_utils.basic import AnsibleModule

__metaclass__ = type


class RoundcubeConfig(object):
    """
        Main Class
    """
    module = None

    # Beispiel für mehrdimensionale JSON-Daten
    json_data = '''
    {
        "name": "Max",
        "alter": 25,
        "adresse": {
            "straße": "Hauptstraße 1",
            "stadt": "Berlin",
            "plz": "10115"
        },
        "interessen": [
            {
                "name": "Programmieren",
                "level": "fortgeschritten"
            },
            {
                "name": "Musik",
                "level": "Anfänger"
            },
            {
                "name": "Reisen",
                "level": "mittel"
            }
        ]
    }
    '''

    def __init__(self, module):
        """

        """
        self.module = module
        self.config = self.module.params.get("config")
        self.config_path = self.module.params.get("config_path")

    def run(self):
        """

        """
        self.module.log(msg=f"search into: {self.config_path}")

        self.module.log(f"{type(self.config)}")

        # JSON in ein Python-Dictionary umwandeln
        if not isinstance(self.config, dict):
            data = json.loads(self.config)
        else:
            data = self.config

        self.module.log(f"{type(data)}")

        # PHP Array generieren
        php_output = "<?php\n$data = " + self.dict_to_php_array(data) + ";\n?>"

        self.module.log(php_output)

        return dict(
            changed=False,
            failed=True,
            msg=php_output
        )

        # PHP Array ausgeben
        print(php_output)

    def dict_to_php_array(self, d, indent=0):
        """
            Funktion zum Erstellen eines PHP-Arrays
        """
        self.module.log(f"dict_to_php_array(self, {d}, indent={indent})")


        php_array = "array(\n"
        for key, value in d.items():
            if isinstance(value, dict):
                php_array += f"  '{key}' => {self.dict_to_php_array(value)},\n"
            elif isinstance(value, list):
                php_array += f"  '{key}' => array(\n"

                for item in value:
                    if isinstance(item, dict):
                        php_array += f"    {self.dict_to_php_array(item)},\n"
                    else:
                        php_array += f"    '{item}',\n"
                php_array += "  ),\n"
            else:
                php_array += f"  '{key}' => '{value}',\n"

        php_array += ")"

        return php_array


def main():
    """

    """
    argument_spec = dict(
        config=dict(
            required=True,
            type=dict
        ),
        config_path=dict(
            required=False,
            default="/var/www/roundcube/config"
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    r = RoundcubeConfig(module)
    result = r.run()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
