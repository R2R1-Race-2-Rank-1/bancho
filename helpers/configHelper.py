import os

class config:
    def __init__(self, file=None):
        self.default = False
        self.fileName = file
        
        if not self.checkConfig():
            self.default = True

    @property
    def config(self):
        
        return {
            "db": {
                "host": self.get("db", "host"),
                "username": self.get("db", "username"),
                "password": self.get("db", "password"),
                "database": self.get("db", "database"),
                "workers": self.get("db", "workers"),
            },
            "redis": {
                "host": self.get("redis", "host"),
                "port": self.get("redis", "port"),
                "database": self.get("redis", "database"),
                "password": self.get("redis", "password"),
            },
            "server": {
                "port": self.get("server", "port"),
                "threads": self.get("server", "threads"),
                "gzip": self.get("server", "gzip"),
                "gziplevel": self.get("server", "gziplevel"),
                "cikey": self.get("server", "cikey"),
                "letsapiurl": self.get("server", "letsapiurl"),
            },
            "cheesegull": {
                "apiurl": self.get("cheesegull", "apiurl"),
                "apikey": self.get("cheesegull", "apikey"),
            },
            "debug": {
                "enable": self.get("debug", "enable"),
                "packets": self.get("debug", "packets"),
                "time": self.get("debug", "time"),
            },
            "sentry": {
                "enable": self.get("sentry", "enable"),
                "banchodsn": self.get("sentry", "banchodsn"),
                "ircdsn": self.get("sentry", "ircdsn"),
            },
            "discord": {
                "enable": self.get("discord", "enable"),
                "boturl": self.get("discord", "boturl"),
                "devgroup": self.get("discord", "devgroup"),
            },
            "datadog": {
                "enable": self.get("datadog", "enable"),
                "apikey": self.get("datadog", "apikey"),
                "appkey": self.get("datadog", "appkey"),
            },
            "irc": {
                "enable": self.get("irc", "enable"),
                "port": self.get("irc", "port"),
                "hostname": self.get("irc", "hostname"),
            },
            "localize": {
                "enable": self.get("localize", "enable"),
                "ipapiurl": self.get("localize", "ipapiurl"),
            },
        }

    def checkConfig(self):
        try:
            self.get("db", "host")
            self.get("db", "username") 
            self.get("db", "password")
            self.get("db", "database")
            self.get("db", "workers")

            self.get("redis", "host")
            self.get("redis", "port")
            self.get("redis", "database")
            self.get("redis", "password")

            self.get("server", "port")
            self.get("server", "threads")
            self.get("server", "gzip")
            self.get("server", "gziplevel")
            self.get("server", "cikey")
            self.get("server", "letsapiurl")

            self.get("cheesegull", "apiurl")
            self.get("cheesegull", "apikey")

            self.get("debug", "enable")
            self.get("debug", "packets")
            self.get("debug", "time")

            self.get("sentry", "enable")
            self.get("sentry", "banchodsn")
            self.get("sentry", "ircdsn")

            self.get("discord", "enable")
            self.get("discord", "boturl")
            self.get("discord", "devgroup")

            self.get("datadog", "enable")
            self.get("datadog", "apikey")
            self.get("datadog", "appkey")

            self.get("irc", "enable")
            self.get("irc", "port")
            self.get("irc", "hostname")

            self.get("localize", "enable")
            self.get("localize", "ipapiurl")
            
            return True
        except KeyError:
            return False

    def get(self, section, key):
        env_map = {
            ("db", "host"): "DB_HOST",
            ("db", "username"): "DB_USER", 
            ("db", "password"): "DB_PASS",
            ("db", "database"): "DB_NAME",
            ("db", "workers"): "DB_WORKERS",
            
            ("redis", "host"): "REDIS_HOST",
            ("redis", "port"): "REDIS_PORT",
            ("redis", "database"): "REDIS_DB",
            ("redis", "password"): "REDIS_PASS",
            
            ("server", "port"): "APP_PORT",
            ("server", "threads"): "SERVICE_READINESS_TIMEOUT",
            ("server", "gzip"): "APP_GZIP",
            ("server", "gziplevel"): "APP_GZIP_LEVEL", 
            ("server", "cikey"): "APP_CI_KEY",
            ("server", "letsapiurl"): "SCORE_SERVICE_BASE_URL",
            
            ("cheesegull", "apiurl"): "BEATMAPS_SERVICE_BASE_URL",
            ("cheesegull", "apikey"): "APP_API_KEY",
            
            ("debug", "enable"): "DEBUG",
            ("debug", "packets"): "DEBUG",
            ("debug", "time"): "DEBUG",
            
            ("sentry", "enable"): "SENTRY_ENABLE",
            ("sentry", "banchodsn"): "SENTRY_BANCHO_DSN", 
            ("sentry", "ircdsn"): "SENTRY_IRC_DSN",
            
            ("discord", "enable"): "DISCORD_ENABLE",
            ("discord", "boturl"): "DISCORD_SERVER_URL",
            ("discord", "devgroup"): "DISCORD_CLIENT_ID",
            
            ("datadog", "enable"): "DATADOG_ENABLE",
            ("datadog", "apikey"): "DATADOG_API_KEY",
            ("datadog", "appkey"): "DATADOG_APP_KEY",
            
            ("irc", "enable"): "IRC_ENABLE",
            ("irc", "port"): "IRC_PORT", 
            ("irc", "hostname"): "IRC_HOSTNAME",
            
            ("localize", "enable"): "LOCALIZE_ENABLE",
            ("localize", "ipapiurl"): "IP_LOOKUP_URL",
        }
        
        env_var = env_map.get((section, key))
        if env_var:
            value = os.getenv(env_var)
            if value is not None:
                return value
        
        defaults = {
            ("server", "threads"): "16",
            ("sentry", "enable"): "0",
            ("sentry", "banchodsn"): "",
            ("sentry", "ircdsn"): "", 
            ("discord", "enable"): "0",
            ("datadog", "enable"): "0",
            ("datadog", "apikey"): "",
            ("datadog", "appkey"): "",
            ("irc", "enable"): "1",
            ("irc", "port"): "6667",
            ("irc", "hostname"): "ripple",
        }
        
        default_value = defaults.get((section, key))
        if default_value is not None:
            return default_value
            
        raise KeyError(f"Environment variable not found for {section}.{key}")

    def set(self, section, key, value):
        pass

    def generateDefaultConfig(self):
        pass
