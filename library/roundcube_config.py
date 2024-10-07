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
        # self.module.log(msg=f"search into: {self.config_path}")
        # self.module.log(f"{type(self.config)}")

        data = self.config_opts()

        # PHP Array generieren
        php_output = "<?php\n$config = " + self.dict_to_php_array(data) + ";\n?>"

        self.module.log(php_output)

        return dict(
            changed=False,
            failed=True,
            msg=php_output
        )

    def config_opts(self):

        data = dict()

        # JSON in ein Python-Dictionary umwandeln
        if not isinstance(self.config, dict):
            config_data = json.loads(self.config)
        else:
            config_data = self.config

        # self.module.log(f"{type(config_data)}")
        # config_data = self.__values_as_string(values=config_data)
        # self.module.log(f"{type(config_data)}")

        if config_data:
            database = config_data.get("database", None)

            if database:
                if database.get("dsnw"):
                    data['dsnw'] = database.get("dsnw")
                if database.get("dsnr"):
                    data['dsnr'] = database.get("dsnr")
                if database.get("dsnw_noread"):
                    data['dsnw_noread'] = database.get("dsnw_noread")
                if database.get("persistent"):
                    data['persistent'] = database.get("persistent")
                if database.get("prefix"):
                    data['prefix'] = database.get("prefix")
                if database.get("table_dsn"):
                    data['table_dsn'] = database.get("table_dsn")
                if database.get("max_allowed_packet"):
                    data['max_allowed_packet'] = database.get("max_allowed_packet")

            logging = config_data.get("logging", None)

            if logging:

                log_driver = logging.get("driver", None)
                if log_driver and log_driver in ['syslog', 'stdout', 'file']:
                    data['log_driver'] = log_driver
                if logging.get("date_format", None):
                    data["log_date_format"] = logging.get("date_format")

                if logging.get("session_id", None):
                    data["log_session_id"] = int(logging.get("session_id"))

                if logging.get("file_ext", None):
                    data["log_file_ext"] = logging.get("file_ext")

                syslog = logging.get("syslog", None)

                if syslog and syslog.get("id"):
                    data["syslog_id"] = syslog.get("id")
                if syslog and syslog.get("facility"):
                    data["syslog_facility"] = syslog.get("facility")

                if logging.get("per_user_logging", None) is not None:
                    data["per_user_logging"] = logging.get("per_user_logging")
                if logging.get("smtp_log", None) is not None:
                    data["smtp_log"] = logging.get("smtp_log")
                if logging.get("log_logins", None) is not None:
                    data["log_logins"] = logging.get("log_logins")

                debug = logging.get("debug", None)

                if debug:
                    if debug.get("session", None) is not None:
                        data["session_debug"] = debug.get("session")
                    if debug.get("sql") is not None:
                        data["sql_debug"] = debug.get("sql")
                    if debug.get("imap") is not None:
                        data["imap_debug"] = debug.get("imap")
                    if debug.get("ldap") is not None:
                        data["ldap_debug"] = debug.get("ldap")
                    if debug.get("smtp") is not None:
                        data["smtp_debug"] = debug.get("smtp")
                    if debug.get("memcache") is not None:
                        data["memcache_debug"] = debug.get("memcache")
                    if debug.get("apc") is not None:
                        data["apc_debug"] = debug.get("apc")
                    if debug.get("redis") is not None:
                        data["redis_debug"] = debug.get("redis")

            imap = config_data.get("imap", None)

            if imap:
                if imap.get("host", None):
                    data['imap_host'] = imap.get("host", None)
                if imap.get("auth_type", None):
                    data['imap_auth_type'] = imap.get("auth_type", None)

                if imap.get("conn_options", None):
                    data['imap_conn_options'] = imap.get("conn_options")
                    """
                    data['imap_conn_options'] = [
                    //  'ssl'         => [
                    //     'verify_peer'  => true,
                    //     'verify_depth' => 3,
                    //     'cafile'       => '/etc/openssl/certs/ca.crt',
                    //   ],
                    // ];
                    """
                if imap.get("conn_options", None):
                    data['imap_conn_options'] = imap.get("conn_options")
                if imap.get("timeout", None):
                    data['imap_timeout'] = imap.get("timeout")
                if imap.get("auth_cid", None):
                    data['imap_auth_cid'] = imap.get("auth_cid")
                if imap.get("auth_pw", None):
                    data['imap_auth_pw'] = imap.get("auth_pw")
                if imap.get("delimiter", None):
                    data['imap_delimiter'] = imap.get("delimiter")
                if imap.get("vendor", None):
                    data['imap_vendor'] = imap.get("vendor")
                # namespace
                namespace = imap.get("namespace", {})

                if namespace:
                    if namespace.get("personal", None):
                        data['imap_ns_personal'] = namespace.get("personal")
                    if namespace.get("other", None):
                        data['imap_ns_other']    = namespace.get("other")
                    if namespace.get("shared", None):
                        data['imap_ns_shared']   = namespace.get("shared")

                if imap.get("force_caps", None):
                    data['imap_force_caps'] = imap.get("force_caps")
                if imap.get("force_lsub", None):
                    data['imap_force_lsub'] = imap.get("force_lsub")
                if imap.get("force_ns", None):
                    data['imap_force_ns'] = imap.get("force_ns")
                if imap.get("skip_hidden_folders", None):
                    data['imap_skip_hidden_folders'] = imap.get("skip_hidden_folders")
                if imap.get("dual_use_folders", None):
                    data['imap_dual_use_folders'] = imap.get("dual_use_folders")
                if imap.get("disabled_caps", None):
                    data['imap_disabled_caps'] = imap.get("disabled_caps")
                if imap.get("log_session", None):
                    data['imap_log_session'] = imap.get("log_session")
                if imap.get("cache", None):
                    data['imap_cache'] = imap.get("cache")
                if imap.get("messages_cache", None):
                    data['messages_cache'] = imap.get("messages_cache")
                if imap.get("cache_ttl", None):
                    data['imap_cache_ttl'] = imap.get("cache_ttl")
                if imap.get("messages_cache_ttl", None):
                    data['messages_cache_ttl'] = imap.get("messages_cache_ttl")
                if imap.get("cache_threshold", None):
                    data['messages_cache_threshold'] = imap.get("cache_threshold")

            smtp = config_data.get("smtp", None)

            if smtp:
                if smtp.get("host", None):
                    data['smtp_host'] = smtp.get("host", None)
                if smtp.get("user", None):
                    data['smtp_user'] = smtp.get("user", None)
                if smtp.get("pass", None):
                    data['smtp_pass'] = smtp.get("pass", None)
                if smtp.get("auth_type", None) and smtp.get("auth_type") in ['DIGEST-MD5', 'CRAM-MD5', 'LOGIN', 'PLAIN']:
                    data['smtp_auth_type'] = smtp.get("auth_type")
                if smtp.get("auth_cid", None):
                    data['smtp_auth_cid'] = smtp.get("auth_cid", None)
                if smtp.get("auth_pw", None):
                    data['smtp_auth_pw'] = smtp.get("auth_pw", None)
                if smtp.get("xclient_login", None):
                    data['smtp_xclient_login'] = smtp.get("xclient_login", None)
                if smtp.get("xclient_addr", None):
                    data['smtp_xclient_addr'] = smtp.get("xclient_addr", None)
                if smtp.get("helo_host", None):
                    data['smtp_helo_host'] = smtp.get("helo_host", None)
                if smtp.get("timeout", None):
                    data['smtp_timeout'] = smtp.get("timeout", None)
                if smtp.get("conn_options", None):
                    data['smtp_conn_options'] = smtp.get("conn_options")

            oauth = config_data.get("oauth", None)

            if oauth:
                oauth_provider = oauth.get("provider", None)
                oauth_provider_name = oauth.get("provider_name", None)
                if oauth_provider and oauth_provider_name:
                    data['oauth_provider'] = oauth_provider
                    data['oauth_provider_name'] = oauth_provider_name
                    if oauth.get("client_id", None):
                        data['oauth_client_id'] = oauth.get("client_id", None)
                    if oauth.get("client_secret", None):
                        data['oauth_client_secret'] = oauth.get("client_secret", None)
                    if oauth.get("auth_uri", None):
                        data['oauth_auth_uri'] = oauth.get("auth_uri", None)
                    if oauth.get("token_uri", None):
                        data['oauth_token_uri'] = oauth.get("token_uri", None)
                    if oauth.get("identity_uri", None):
                        data['oauth_identity_uri'] = oauth.get("identity_uri", None)
                    if oauth.get("verify_peer", None):
                        data['oauth_verify_peer'] = oauth.get("verify_peer", None)
                    if oauth.get("scope", None):
                        data['oauth_scope'] = oauth.get("scope", None)
                    if oauth.get("auth_parameters", None):
                        data['oauth_auth_parameters'] = oauth.get("auth_parameters", None)
                    if oauth.get("identity_fields", None):
                        data['oauth_identity_fields'] = oauth.get("identity_fields", None)
                    if oauth.get("login_redirect", None):
                        data['oauth_login_redirect'] = oauth.get("login_redirect", None)

            ldap = config_data.get("ldap", None)

            if ldap:
                if ldap.get("cache", None) and ldap.get("cache", None) in ['db', 'apc', 'memcache', 'memcached']:
                    data['ldap_cache'] = ldap.get("cache", None)
                if ldap.get("cache_ttl", None):
                    data['ldap_cache_ttl'] = ldap.get("cache_ttl", None)

            caches = config_data.get("caches", None)

            if caches:
                memcache = caches.get("memcache", {})
                redis = caches.get("redis", {})
                apc = caches.get("apc", {})

                if memcache:

                    if memcache.get("hosts", None):
                        data["memcache_hosts"] = memcache.get("hosts")
                    if memcache.get("pconnect", None):
                        data["memcache_pconnect"] = memcache.get("pconnect")
                    if memcache.get("timeout", None):
                        data["memcache_timeout"] = memcache.get("timeout")
                    if memcache.get("retry_interval", None):
                        data["memcache_retry_interval"] = memcache.get("retry_interval")
                    if memcache.get("max_allowed_packet", None):
                        data["memcache_max_allowed_packet"] = memcache.get("max_allowed_packet")

                if redis:
                    if redis.get("hosts", None):
                        data["redis_hosts"] = redis.get("hosts")
                    if redis.get("max_allowed_packet", None):
                        data["redis_max_allowed_packet"] = redis.get("max_allowed_packet")

                if apc:
                    if apc.get("max_allowed_packet", None):
                        data["apc_max_allowed_packet"] = apc.get("max_allowed_packet")

            system = config_data.get("system", None)

            if system:
                pass

            plugins = config_data.get("plugins", None)

            if plugins:
                pass

            ui = config_data.get("ui", None)

            if ui:
                pass

            addressbook = config_data.get("addressbook", None)

            if addressbook:
                pass

            user_pref = config_data.get("user_pref", None)

            if user_pref:
                pass

        self.module.log(f"{type(data)}")

        return data

    def dict_to_php_array(self, d, indent=0):
        """
        """
        # self.module.log(f"dict_to_php_array(self, {d}, indent={indent})")
        php_array = "array(\n"
        indent += 2

        for key, value in d.items():
            php_array += " " * indent
            if isinstance(key, str):
                php_array += f"'{key}' => "
            else:
                php_array += f"{key} => "

            if isinstance(value, dict):
                php_array += self.dict_to_php_array(value, indent) + ",\n"
            else:
                # php_array += " " * (indent + 2)
                if isinstance(value, bool):
                    v = str(value).lower()
                    php_array += f"{v},\n"
                elif isinstance(value, int):
                    php_array += f"{value},\n"

                elif isinstance(value, list):
                    php_array += "array(\n"
                    for item in value:
                        php_array += " " * (indent + 2)
                        if isinstance(item, dict):
                            php_array += self.dict_to_php_array(item, indent + 2) + ",\n"
                        else:
                            php_array += f"'{item}',\n"
                    php_array += " " * indent + "),\n"
                elif isinstance(value, str):
                    php_array += f"'{value}',\n"
                else:
                    php_array += f"{value},\n"
        indent -= 2
        php_array += " " * indent + ")"

        return php_array

    # def dict_to_php_array(self, d, indent=2):
    #     """
    #         Funktion zum Erstellen eines PHP-Arrays
    #     """
    #     self.module.log(f"dict_to_php_array(self, {d}, indent={indent})")
    #
    #     php_array = "array(\n"
    #     for key, value in d.items():
    #         """
    #             self.module.log(f" - {value} / {type(value)}")
    #         """
    #
    #         if isinstance(value, dict):
    #             php_array += f"{('  '*indent)}'{key}' => {self.dict_to_php_array(value, indent=indent+2)},\n"
    #         elif isinstance(value, bool):
    #             v = str(value).lower()
    #             php_array += f"{('  '*indent)}'{key}' => {v},\n"
    #         elif isinstance(value, int):
    #             php_array += f"{('  '*indent)}'{key}' => {value},\n"
    #         elif isinstance(value, list):
    #             php_array += f"{('  '*indent)}'{key}' => array(\n"
    #             for item in value:
    #                 # self.module.log(f" - {item} / {type(item)}")
    #                 if isinstance(item, dict):
    #                     php_array += f"{('  '*indent)}{self.dict_to_php_array(item, indent=indent+2)},\n"
    #                 elif isinstance(item, int):
    #                     php_array += f"{('  '*indent)}{item},\n"
    #                 elif isinstance(item, bool):
    #                     php_array += f"{('  '*indent)}{str(item).lower()},\n"
    #                 else:
    #                     php_array += f"{('  '*indent)}'{item}',\n"
    #             php_array += f"{('  '*indent)}),\n"
    #         else:
    #             php_array += f"{('  '*indent)}'{key}' => '{value}',\n"
    #
    #     php_array += ")"
    #
    #     return php_array

    def __values_as_string(self, values):
        """
        """
        result = {}
        self.module.log(msg=f"{json.dumps(values, indent=2, sort_keys=False)}")

        if isinstance(values, dict):
            for k, v in sorted(values.items()):
                if isinstance(v, bool):
                    v = str(v).lower()
                result[k] = str(v)

        self.module.log(msg=f"{json.dumps(result, indent=2, sort_keys=False)}")
        return result

    def valid_list_data(self, data, valid_entries):
        """
        """
        result = []

        if isinstance(data, list):
            data.sort()
            valid_entries.sort()
            result = list(set(data).intersection(valid_entries))
            result.sort()
        # display.v(f"=result: {result}")
        return result


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



"""
  auth_type = [x.upper() for x in auth_type]
  auth_type = self.valid_list_data(auth_type, valid_entries=['DIGEST-MD5', 'CRAM-MD5', 'LOGIN', 'PLAIN'])
  if auth_type:
      data['smtp_auth_type'] = auth_type

"""
