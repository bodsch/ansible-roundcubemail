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
                if system.get("enable_installer"):
                    data['enable_installer'] = system.get("enable_installer")
                if system.get("dont_override"):
                    data['dont_override'] = system.get("dont_override")
                if system.get("disabled_actions"):
                    data['disabled_actions'] = system.get("disabled_actions")
                if system.get("advanced_prefs"):
                    data['advanced_prefs'] = system.get("advanced_prefs")
                if system.get("support_url"):
                    data['support_url'] = system.get("support_url")
                if system.get("blankpage_url"):
                    data['blankpage_url'] = system.get("blankpage_url")
                if system.get("skin_logo"):
                    data['skin_logo'] = system.get("skin_logo")
                if system.get("auto_create_user"):
                    data['auto_create_user'] = system.get("auto_create_user")
                if system.get("user_aliases"):
                    data['user_aliases'] = system.get("user_aliases")
                if system.get("log_dir"):
                    data['log_dir'] = system.get("log_dir")
                if system.get("temp_dir"):
                    data['temp_dir'] = system.get("temp_dir")
                if system.get("temp_dir_ttl"):
                    data['temp_dir_ttl'] = system.get("temp_dir_ttl")
                if system.get("force_https"):
                    data['force_https'] = system.get("force_https")
                if system.get("use_https"):
                    data['use_https'] = system.get("use_https")
                if system.get("login_autocomplete"):
                    data['login_autocomplete'] = system.get("login_autocomplete")
                if system.get("login_lc"):
                    data['login_lc'] = system.get("login_lc")
                if system.get("login_username_maxlen"):
                    data['login_username_maxlen'] = system.get("login_username_maxlen")
                if system.get("login_password_maxlen"):
                    data['login_password_maxlen'] = system.get("login_password_maxlen")
                if system.get("login_username_filter"):
                    data['login_username_filter'] = system.get("login_username_filter")
                if system.get("login_rate_limit"):
                    data['login_rate_limit'] = system.get("login_rate_limit")
                if system.get("skin_include_php"):
                    data['skin_include_php'] = system.get("skin_include_php")
                if system.get("display_product_info"):
                    data['display_product_info'] = system.get("display_product_info")
                if system.get("session_lifetime"):
                    data['session_lifetime'] = system.get("session_lifetime")
                if system.get("session_domain"):
                    data['session_domain'] = system.get("session_domain")
                if system.get("session_name"):
                    data['session_name'] = system.get("session_name")
                if system.get("session_auth_name"):
                    data['session_auth_name'] = system.get("session_auth_name")
                if system.get("session_path"):
                    data['session_path'] = system.get("session_path")
                if system.get("session_samesite"):
                    data['session_samesite'] = system.get("session_samesite")
                if system.get("session_storage"):
                    data['session_storage'] = system.get("session_storage")
                if system.get("proxy_whitelist"):
                    data['proxy_whitelist'] = system.get("proxy_whitelist")
                if system.get("trusted_host_patterns"):
                    data['trusted_host_patterns'] = system.get("trusted_host_patterns")
                if system.get("ip_check"):
                    data['ip_check'] = system.get("ip_check")
                if system.get("x_frame_options"):
                    data['x_frame_options'] = system.get("x_frame_options")

                if system.get("des_key"):
                    data['des_key'] = system.get("des_key")
                if system.get("cipher_method"):
                    data['cipher_method'] = system.get("cipher_method")
                if system.get("username_domain"):
                    data['username_domain'] = system.get("username_domain")
                if system.get("username_domain_forced"):
                    data['username_domain_forced'] = system.get("username_domain_forced")
                if system.get("mail_domain"):
                    data['mail_domain'] = system.get("mail_domain")
                if system.get("password_charset"):
                    data['password_charset'] = system.get("password_charset")
                if system.get("sendmail_delay"):
                    data['sendmail_delay'] = system.get("sendmail_delay")
                if system.get("max_message_size"):
                    data['max_message_size'] = system.get("max_message_size")
                if system.get("max_recipients"):
                    data['max_recipients'] = system.get("max_recipients")
                if system.get("max_disclosed_recipients"):
                    data['max_disclosed_recipients'] = system.get("max_disclosed_recipients")
                if system.get("max_group_members"):
                    data['max_group_members'] = system.get("max_group_members")
                if system.get("product_name"):
                    data['product_name'] = system.get("product_name")
                if system.get("useragent"):
                    data['useragent'] = system.get("useragent")
                if system.get("include_host_config"):
                    data['include_host_config'] = system.get("include_host_config")
                if system.get("generic_message_footer"):
                    data['generic_message_footer'] = system.get("generic_message_footer")
                if system.get("generic_message_footer_html"):
                    data['generic_message_footer_html'] = system.get("generic_message_footer_html")
                if system.get("http_received_header"):
                    data['http_received_header'] = system.get("http_received_header")
                if system.get("http_received_header_encrypt"):
                    data['http_received_header_encrypt'] = system.get("http_received_header_encrypt")
                if system.get("line_length"):
                    data['line_length'] = system.get("line_length")
                if system.get("send_format_flowed"):
                    data['send_format_flowed'] = system.get("send_format_flowed")
                if system.get("mdn_use_from"):
                    data['mdn_use_from'] = system.get("mdn_use_from")
                if system.get("identities_level"):
                    data['identities_level'] = system.get("identities_level")
                if system.get("identity_image_size"):
                    data['identity_image_size'] = system.get("identity_image_size")
                if system.get("response_image_size"):
                    data['response_image_size'] = system.get("response_image_size")
                if system.get("client_mimetypes"):
                    data['client_mimetypes'] = system.get("client_mimetypes")
                if system.get("mime_magic"):
                    data['mime_magic'] = system.get("mime_magic")
                if system.get("mime_types"):
                    data['mime_types'] = system.get("mime_types")
                if system.get("im_convert_path"):
                    data['im_convert_path'] = system.get("im_convert_path")
                if system.get("im_identify_path"):
                    data['im_identify_path'] = system.get("im_identify_path")
                if system.get("image_thumbnail_size"):
                    data['image_thumbnail_size'] = system.get("image_thumbnail_size")
                if system.get("contact_photo_size"):
                    data['contact_photo_size'] = system.get("contact_photo_size")
                if system.get("email_dns_check"):
                    data['email_dns_check'] = system.get("email_dns_check")
                if system.get("no_save_sent_messages"):
                    data['no_save_sent_messages'] = system.get("no_save_sent_messages")
                if system.get("use_secure_urls"):
                    data['use_secure_urls'] = system.get("use_secure_urls")
                if system.get("request_path"):
                    data['request_path'] = system.get("request_path")
                if system.get("assets_path"):
                    data['assets_path'] = system.get("assets_path")
                if system.get("assets_dir"):
                    data['assets_dir'] = system.get("assets_dir")
                if system.get("http_client"):
                    data['http_client'] = system.get("http_client")
                if system.get("subject_reply_prefixes"):
                    data['subject_reply_prefixes'] = system.get("subject_reply_prefixes")
                if system.get("subject_forward_prefixes"):
                    data['subject_forward_prefixes'] = system.get("subject_forward_prefixes")
                if system.get("response_prefix"):
                    data['response_prefix'] = system.get("response_prefix")
                if system.get("forward_prefix"):
                    data['forward_prefix'] = system.get("forward_prefix")

            plugins = config_data.get("plugins", None)

            if plugins:
                if plugins.get("plugins"):
                    data['plugins'] = plugins.get("plugins")

            ui = config_data.get("ui", None)

            if ui:
                if ui.get("message_sort_col"):
                    data['message_sort_col'] = ui.get("message_sort_col")
                if ui.get("message_sort_order"):
                    data['message_sort_order'] = ui.get("message_sort_order")
                if ui.get("list_cols"):
                    data['list_cols'] = ui.get("list_cols")
                if ui.get("language"):
                    data['language'] = ui.get("language")
                if ui.get("date_format"):
                    data['date_format'] = ui.get("date_format")
                if ui.get("date_formats"):
                    data['date_formats'] = ui.get("date_formats")
                if ui.get("time_format"):
                    data['time_format'] = ui.get("time_format")
                if ui.get("time_formats"):
                    data['time_formats'] = ui.get("time_formats")
                if ui.get("date_short"):
                    data['date_short'] = ui.get("date_short")
                if ui.get("date_long"):
                    data['date_long'] = ui.get("date_long")
                if ui.get("drafts_mbox"):
                    data['drafts_mbox'] = ui.get("drafts_mbox")
                if ui.get("junk_mbox"):
                    data['junk_mbox'] = ui.get("junk_mbox")
                if ui.get("sent_mbox"):
                    data['sent_mbox'] = ui.get("sent_mbox")
                if ui.get("trash_mbox"):
                    data['trash_mbox'] = ui.get("trash_mbox")
                if ui.get("create_default_folders"):
                    data['create_default_folders'] = ui.get("create_default_folders")
                if ui.get("protect_default_folders"):
                    data['protect_default_folders'] = ui.get("protect_default_folders")
                if ui.get("show_real_foldernames"):
                    data['show_real_foldernames'] = ui.get("show_real_foldernames")
                if ui.get("quota_zero_as_unlimited"):
                    data['quota_zero_as_unlimited'] = ui.get("quota_zero_as_unlimited")
                if ui.get("enable_spellcheck"):
                    data['enable_spellcheck'] = ui.get("enable_spellcheck")
                if ui.get("spellcheck_dictionary"):
                    data['spellcheck_dictionary'] = ui.get("spellcheck_dictionary")
                if ui.get("spellcheck_engine"):
                    data['spellcheck_engine'] = ui.get("spellcheck_engine")
                if ui.get("spellcheck_uri"):
                    data['spellcheck_uri'] = ui.get("spellcheck_uri")
                if ui.get("spellcheck_languages"):
                    data['spellcheck_languages'] = ui.get("spellcheck_languages")
                if ui.get("spellcheck_ignore_caps"):
                    data['spellcheck_ignore_caps'] = ui.get("spellcheck_ignore_caps")
                if ui.get("spellcheck_ignore_nums"):
                    data['spellcheck_ignore_nums'] = ui.get("spellcheck_ignore_nums")
                if ui.get("spellcheck_ignore_syms"):
                    data['spellcheck_ignore_syms'] = ui.get("spellcheck_ignore_syms")
                if ui.get("sig_max_lines"):
                    data['sig_max_lines'] = ui.get("sig_max_lines")
                if ui.get("max_pagesize"):
                    data['max_pagesize'] = ui.get("max_pagesize")
                if ui.get("min_refresh_interval"):
                    data['min_refresh_interval'] = ui.get("min_refresh_interval")
                if ui.get("undo_timeout"):
                    data['undo_timeout'] = ui.get("undo_timeout")
                if ui.get("compose_responses_static"):
                    data['compose_responses_static'] = ui.get("compose_responses_static")
                if ui.get("keyservers"):
                    data['keyservers'] = ui.get("keyservers")
                if ui.get("mailvelope_main_keyring"):
                    data['mailvelope_main_keyring'] = ui.get("mailvelope_main_keyring")
                if ui.get("mailvelope_keysize"):
                    data['mailvelope_keysize'] = ui.get("mailvelope_keysize")
                if ui.get("html2text_links"):
                    data['html2text_links'] = ui.get("html2text_links")
                if ui.get("html2text_width"):
                    data['html2text_width'] = ui.get("html2text_width")

            addressbook = config_data.get("addressbook", None)

            if addressbook:
                if addressbook.get("type"):
                    data['address_book_type'] = addressbook.get("type")
                if addressbook.get("ldap_public"):
                    data['ldap_public'] = addressbook.get("ldap_public")

                autocomplete = addressbook.get("autocomplete")

                if autocomplete:
                    if autocomplete.get("addressbooks"):
                        data['autocomplete_addressbooks'] = autocomplete.get("addressbooks")
                    if autocomplete.get("min_length"):
                        data['autocomplete_min_length'] = autocomplete.get("min_length")
                    if autocomplete.get("threads"):
                        data['autocomplete_threads'] = autocomplete.get("threads")
                    if autocomplete.get("max"):
                        data['autocomplete_max'] = autocomplete.get("max")
                if addressbook.get("address_template"):
                    data['address_template'] = addressbook.get("address_template")
                if addressbook.get("search_mode"):
                    data['addressbook_search_mode'] = addressbook.get("search_mode")
                if addressbook.get("contactlist_fields"):
                    data['contactlist_fields'] = addressbook.get("contactlist_fields")
                if addressbook.get("contact_search_name"):
                    data['contact_search_name'] = addressbook.get("contact_search_name")
                if addressbook.get("contact_form_mode"):
                    data['contact_form_mode'] = addressbook.get("contact_form_mode")
                if addressbook.get("collected_recipients"):
                    data['collected_recipients'] = addressbook.get("collected_recipients")
                if addressbook.get("collected_senders"):
                    data['collected_senders'] = addressbook.get("collected_senders")

            user_pref = config_data.get("user_pref", None)

            if user_pref:
                if user_pref.get("default_charset"):
                    data['default_charset'] = user_pref.get("default_charset")
                if user_pref.get("skin"):
                    data['skin'] = user_pref.get("skin")
                if user_pref.get("skins_allowed"):
                    data['skins_allowed'] = user_pref.get("skins_allowed")
                if user_pref.get("standard_windows"):
                    data['standard_windows'] = user_pref.get("standard_windows")
                if user_pref.get("mail_pagesize"):
                    data['mail_pagesize'] = user_pref.get("mail_pagesize")
                if user_pref.get("addressbook_pagesize"):
                    data['addressbook_pagesize'] = user_pref.get("addressbook_pagesize")
                if user_pref.get("addressbook_sort_col"):
                    data['addressbook_sort_col'] = user_pref.get("addressbook_sort_col")
                if user_pref.get("addressbook_name_listing"):
                    data['addressbook_name_listing'] = user_pref.get("addressbook_name_listing")
                if user_pref.get("timezone"):
                    data['timezone'] = user_pref.get("timezone")
                if user_pref.get("prefer_html"):
                    data['prefer_html'] = user_pref.get("prefer_html")
                if user_pref.get("show_images"):
                    data['show_images'] = user_pref.get("show_images")
                if user_pref.get("message_extwin"):
                    data['message_extwin'] = user_pref.get("message_extwin")
                if user_pref.get("compose_extwin"):
                    data['compose_extwin'] = user_pref.get("compose_extwin")
                if user_pref.get("htmleditor"):
                    data['htmleditor'] = user_pref.get("htmleditor")
                if user_pref.get("compose_save_localstorage"):
                    data['compose_save_localstorage'] = user_pref.get("compose_save_localstorage")
                if user_pref.get("prettydate"):
                    data['prettydate'] = user_pref.get("prettydate")
                if user_pref.get("draft_autosave"):
                    data['draft_autosave'] = user_pref.get("draft_autosave")
                if user_pref.get("layout"):
                    data['layout'] = user_pref.get("layout")
                if user_pref.get("mail_read_time"):
                    data['mail_read_time'] = user_pref.get("mail_read_time")
                if user_pref.get("logout_purge"):
                    data['logout_purge'] = user_pref.get("logout_purge")
                if user_pref.get("logout_expunge"):
                    data['logout_expunge'] = user_pref.get("logout_expunge")
                if user_pref.get("inline_images"):
                    data['inline_images'] = user_pref.get("inline_images")
                if user_pref.get("mime_param_folding"):
                    data['mime_param_folding'] = user_pref.get("mime_param_folding")
                if user_pref.get("skip_deleted"):
                    data['skip_deleted'] = user_pref.get("skip_deleted")
                if user_pref.get("read_when_deleted"):
                    data['read_when_deleted'] = user_pref.get("read_when_deleted")
                if user_pref.get("flag_for_deletion"):
                    data['flag_for_deletion'] = user_pref.get("flag_for_deletion")
                if user_pref.get("refresh_interval"):
                    data['refresh_interval'] = user_pref.get("refresh_interval")
                if user_pref.get("check_all_folders"):
                    data['check_all_folders'] = user_pref.get("check_all_folders")
                if user_pref.get("default_list_mode"):
                    data['default_list_mode'] = user_pref.get("default_list_mode")
                if user_pref.get("autoexpand_threads"):
                    data['autoexpand_threads'] = user_pref.get("autoexpand_threads")
                if user_pref.get("reply_mode"):
                    data['reply_mode'] = user_pref.get("reply_mode")
                if user_pref.get("strip_existing_sig"):
                    data['strip_existing_sig'] = user_pref.get("strip_existing_sig")
                if user_pref.get("show_sig"):
                    data['show_sig'] = user_pref.get("show_sig")
                if user_pref.get("sig_below"):
                    data['sig_below'] = user_pref.get("sig_below")
                if user_pref.get("sig_separator"):
                    data['sig_separator'] = user_pref.get("sig_separator")
                if user_pref.get("force_7bit"):
                    data['force_7bit'] = user_pref.get("force_7bit")
                if user_pref.get("search_mods"):
                    data['search_mods'] = user_pref.get("search_mods")
                if user_pref.get("addressbook_search_mods"):
                    data['addressbook_search_mods'] = user_pref.get("addressbook_search_mods")
                if user_pref.get("delete_junk"):
                    data['delete_junk'] = user_pref.get("delete_junk")
                if user_pref.get("mdn_requests"):
                    data['mdn_requests'] = user_pref.get("mdn_requests")
                if user_pref.get("mdn_default"):
                    data['mdn_default'] = user_pref.get("mdn_default")
                if user_pref.get("dsn_default"):
                    data['dsn_default'] = user_pref.get("dsn_default")
                if user_pref.get("reply_same_folder"):
                    data['reply_same_folder'] = user_pref.get("reply_same_folder")
                if user_pref.get("forward_attachment"):
                    data['forward_attachment'] = user_pref.get("forward_attachment")
                if user_pref.get("default_addressbook"):
                    data['default_addressbook'] = user_pref.get("default_addressbook")
                if user_pref.get("spellcheck_before_send"):
                    data['spellcheck_before_send'] = user_pref.get("spellcheck_before_send")
                if user_pref.get("autocomplete_single"):
                    data['autocomplete_single'] = user_pref.get("autocomplete_single")
                if user_pref.get("default_font"):
                    data['default_font'] = user_pref.get("default_font")
                if user_pref.get("default_font_size"):
                    data['default_font_size'] = user_pref.get("default_font_size")
                if user_pref.get("message_show_email"):
                    data['message_show_email'] = user_pref.get("message_show_email")
                if user_pref.get("reply_all_mode"):
                    data['reply_all_mode'] = user_pref.get("reply_all_mode")

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
