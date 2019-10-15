import logging
import sys
import os
from datadog import initialize, api
import yaml
import requests
import re
import json

class Utils():
    def __init__(self):
        debug = os.environ.get('DEBUG', None)
        if debug:
            logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
        else:
            logging.basicConfig(stream=sys.stdout, level=logging.INFO)
        logging.getLogger('datadog.api').setLevel(logging.WARNING)
        api_key = os.environ.get('datadog_api_key', None)
        app_key = os.environ.get('datadog_app_key', None)
        if not api_key:
            logging.error(
                "ERROR: no environment variable 'datadog_api_key' defined!")
            sys.exit(1)
        if not app_key:
            logging.error(
                "ERROR: no environment variable 'datadog_app_key' defined!")
            sys.exit(1)
        options = {
            'api_key': api_key,
            'app_key': app_key
        }
        self.teams = {
            "agent-tools":
                {
                    "notifications": "ae-notif",
                    "alerts": "ae-alerts",
                },
            "consumer":
                {
                    "notifications": "consumer-notif",
                    "alerts": "consumer-alerts",
                },
            "data-platform":
                {
                    "notifications": "data-platform-notif",
                    "alerts": "data_ingestion_alerts",
                },
            "data-science-engineering":
                {
                    "notifications": "data-science-notif",
                    "alerts": "data-science-alerts",
                },
            "operations":
                {
                    "notifications": "infrastructure-notif",
                    "alerts": "infrastructure-alerts",
                },
            "panel":
                {
                    "notifications": "panel-notif",
                    "alerts": "panel-alerts",
                },
            "platform":
                {
                    "notifications": "platform-notif",
                    "alerts": "platform-alerts",
                },
        }
        initialize(**options)

    def return_teams(self):
        return self.teams

    def existing_monitor_names(self):
        monitor_names = {}
        all_monitors = api.Monitor.get_all()
        for monitor in all_monitors:
            monitor_names[monitor['name']] = {}
            monitor_names[monitor['name']]['id'] = monitor['id']
        return monitor_names

    def keys_exists(self, element, *keys):
        '''Check if *keys (nested) exists in `element` (dict).'''
        if not isinstance(element, dict):
            raise AttributeError('keys_exists() expects dict as first argument.')
        if len(keys) == 0:
            raise AttributeError(
                'keys_exists() expects at least two arguments, one given.')
        _element = element
        for key in keys:
            try:
                _element = _element[key]
            except KeyError:
                return False
        return True

    def valid_doc(self, file_name):
        '''Only return single-document objects, pyyaml doesn't support multi-doc objects.'''
        logging.debug("Checking: %s" % (file_name))
        f = open(file_name, "r")
        contents = f.read()
        f.close()
        num_docs = 1
        for line in contents.split('\n'):
            result = re.search("---", line)
            if result:
                num_docs = num_docs + 1
        logging.debug("valid_doc number docs: %d" % (num_docs))
        if num_docs == 1:
            return contents
        else:
            logging.debug("too many docs in %s, skipping." % (file_name))

    def read_yaml_config(self, yaml_config):
        try:
            logging.debug(yaml_config)
            with open(yaml_config, 'r') as file_handle:
                logging.debug(type(file_handle))
                config = yaml.safe_load(file_handle)
                return config
        except Exception as e:
            logging.error("Error while reading config file %s: %s" %
                          (yaml_config, str(e)))
            sys.exit(1)

    def find_yaml_files(self, check_dir):
        configs = []
        if os.path.isdir(check_dir):
            for root, dirs, files in os.walk(check_dir):
                # honestly I just put this here to get pylint to shut up
                logging.debug(dirs)
                for file in files:
                    if (file.endswith(".yaml")) or (file.endswith(".yml")):
                        configs.append(os.path.join(root, file))
            if not configs:
                logging.warning("No yaml files found under %s" % (check_dir))
        else:
                logging.info("No directory: %s" % (check_dir))
        return configs

    def search_monitors_directory(self):
        cwd = os.getcwd()
        monitors = "%s/monitors" % (cwd)
        return self.find_yaml_files(monitors)

    def search_infrastructure_directory(self):
        cwd = os.getcwd()
        monitors = "%s/infrastructure_monitors" % (cwd)
        return self.find_yaml_files(monitors)

    def upsert_monitor(self, config, silenced=None):
        '''A naive update that always executes, should be improved to do a diff first.'''
        logging.debug(config)
        if silenced:
            config['options']['silenced'] = {'*': None}
        all_existing_monitors = self.existing_monitor_names()
        logging.debug(config)
        if config['name'] in all_existing_monitors.keys():
            logging.info("*** Monitor %s is updating: %s ***" %
                         (config['name'], all_existing_monitors[config['name']]['id']))
            api.Monitor.update(
                int(all_existing_monitors[config['name']]['id']),
                type=config['type'],
                query=config['query'],
                name=config['name'],
                message=config['message'],
                tags=config['tags'],
                options=config['options']
            )
        else:
            logging.info("*** Monitor %s is creating ***" % (config['name']))
            api.Monitor.create(
                type=config['type'],
                query=config['query'],
                name=config['name'],
                message=config['message'],
                tags=config['tags'],
                options=config['options']
            )

    def get_all_tags(self):
        x = api.Tag.get_all()
        return x['tags']

    def find_tag_by_string(self, tag_name, ignore_case=None):
        return_tags = []
        all_tags = self.get_all_tags()
        if ignore_case:
            tag_name = re.compile(tag_name, re.IGNORECASE)
        for tag_key in all_tags.keys():
            result = re.search(tag_name, tag_key)
            if result:
                logging.debug("matched on: %s" % (tag_key))
                tmp_dict = {}
                tmp_dict[tag_key] = all_tags[tag_key]
                logging.debug(all_tags[tag_key])
                return_tags.append(tmp_dict)
        return return_tags

    def return_environments(self):
        environment_tags = self.find_tag_by_string('^env:.*$')
        all_envs = []
        for environment in environment_tags:
            for env_tmp in environment.keys():
                all_envs.append(env_tmp.split(':')[1])
        return sorted(all_envs)

    def emit_event(self, title, text, tags, priority, alert_type, aggregation_key, source_type_name):
        event_response = api.Event.create(title=title, text=text, tags=tags, priority=priority, alert_type=alert_type, aggregation_key=aggregation_key, source_type_name=source_type_name)
        return event_response

    def notify_slack(self, team, message, topic=None, notification_level="notifications"):
        if team in self.teams:
            payload = {}
            payload['channels'] = [self.teams[team][notification_level]]
            payload['message'] = message
            if topic:
                payload['topic'] = topic
            r = requests.post('http://slack.corp.com',
                                data=json.dumps(payload), timeout=2.0)
            r.raise_for_status()
        else:
            logging.warning("No team %s in teams dictionary!" % (team))
