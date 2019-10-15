#!/usr/bin/env python
import argparse
import logging
import sys
import os
import re
import yaml
from jinja2 import Template, Environment, FileSystemLoader

# Goals:
# k8s_container_cpu_exceeding_request: CPU exceeds request over 10 minutes - if cpu request configured
# k8s_container_memory_exceeding_request: Memory exceeds request over 10 minutes - if memory request configured
# k8s_pod_none_running: 0 ready pods over 10 minutes
# k8s_pod_frequent_restarts: Pods flapping over 5 minutes
# Can I even do the below?  How to ID svc?
# svc_anomaly_detection_latency: Anomaly detection on latency
# svc_anomaly_detection_requests: Anomaly detection on Requests
# svc_anomaly_detection_errors: Anomaly detection on Errors

# allow for exclusion of various template via annotation:
# ci.corp.com/automon-exclude: '[comma separated list of filename minus -template.yaml]'

# keeping this consistent with util.py
debug = os.environ.get('DEBUG', None)

if debug:
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
else:
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)

if os.path.isdir('/k8s/classes'):
    sys.path.append('/k8s/classes')
    logging.info("added path: /k8s/classes")
elif os.path.isdir('./classes'):
    sys.path.append('./classes')
    logging.info("added path: ./classes")
else:
    sys.exit("No classes found!")

if os.path.isdir('/k8s/templates/automon'):
    process_dir = '/k8s/templates/automon'
    logging.info("template path: /k8s/templates/automon")
elif os.path.isdir('./templates/automon'):
    process_dir = './templates/automon'
    logging.info("template path: ./templates/automon")
else:
    sys.exit("No process_dir found!")

from utils import Utils

utils = Utils()

parser = argparse.ArgumentParser()
parser.add_argument("--team", action="store", dest="team",
                    default=None, help="REQUIRED: Define a team for template processing")
parser.add_argument("--environment", action="store", dest="environment",
                    default=None, help="REQUIRED: Define an environment for template processing")
parser.add_argument("--deployment", action="store", dest="deployment",
                    help="REQUIRED: Define a deployment for template processing.", required=True)
parser.add_argument("--watchtype", action="store", dest="watchtype",
                    help="REQUIRED: Define a watchtype (deployment, statefulset, daemonset) for template processing", required=True)
parser.add_argument("--namespace", action="store", dest="namespace",
                    default="default", help="Define a namespace for template processing")
parser.add_argument("--notif", action="store_true",
                    dest="notif", default=None, help="force to notif channel")
parser.add_argument("--silence", action="store_true", dest="silence",
                    default=None, help="mute all monitors")
args = parser.parse_args()

if args.environment == "staging":
    args.environment = "beta"
    args.namespace = "staging"

# datadog metrics are different than the generics I've been using:
watchtype_map = {
    "deployment": "deployment",
    "statefulset": "stateful_set",
    "daemonset": "daemon_set",
}

def printerr(chk_list, msg):
    print(msg)
    for i in chk_list:
        print(i)

def validate(chk_value, chk_list, msg):
    if not chk_value:
        printerr(chk_list, msg)
        sys.exit(1)
    if chk_value not in chk_list:
        printerr(chk_list, msg)
        sys.exit(1)

# TODO: get this list from datadog!
err_msg = "** ERROR - you must specify a valid team!\n[new integrations must be created to add teams to this list.]\nValid teams:"
validate(args.team, [
        'operations', 'panel', 'data-platform', 'platform', 'data-science-engineering', 'agent-tools', 'consumer'], err_msg)

err_msg = "** ERROR - you must specify a valid environment!\nValid environments:"
validate(args.environment, utils.return_environments(), err_msg)

def process_automon_templates(args, all_templates):
    teams = utils.return_teams()
    for template_file in all_templates:
        if args.environment == "beta":
            notify_team = "@slack-%s" % (teams[args.team]['alerts'])
        elif args.notif:
            notify_team = "@slack-%s" % (teams[args.team]['notifications'])
        else:
            notify_team = "@opsgenie-%s" % (args.team)
        process_yaml = template_file.split('/')[-1]
        logging.debug("process_yaml: " + process_yaml)
        file_loader = FileSystemLoader(process_dir)
        env = Environment(loader=file_loader)
        template = env.get_template(process_yaml)
        template_output = template.render(
            corp_env=args.environment, deployment=args.deployment, team_name=args.team, team=notify_team, team_notif=teams[args.team]['notifications'], namespace=args.namespace, watchtype=watchtype_map[args.watchtype])
        logging.debug("*** template_output type:")
        logging.debug(type(template_output))
        logging.debug(template_output)
        yaml_config = yaml.safe_load(template_output)
        if args.silence:
            yaml_config['options']['silenced'] = {'*': None}
        logging.debug(yaml_config)
        utils.upsert_monitor(yaml_config)

def check_annotations(config):
    excludes = []
    if utils.keys_exists(config, "metadata", "annotations", "ci.corp.com/automon-exclude"):
        for i in config['metadata']['annotations']['ci.corp.com/automon-exclude'].split(','):
            excludes.append(i.strip())
    return excludes

def check_resources(config):
    '''We cannot validate resources if they're not configured, check if they're defined.
    Any deployment, daemonset, or statefulset w/o requests or limits defined will disable
    ALL checks, so we should just define them!'''
    excludes = []
    has_cpu_requests = True
    has_cpu_limits = True
    has_memory_requests = True
    has_memory_limits = True
    for container in config['spec']['template']['spec']['containers']:
        if not utils.keys_exists(container, "resources","requests", "cpu"):
            logging.debug("%s has no cpu requests configured" % (config['metadata']['name']))
            has_cpu_requests = False
        if not utils.keys_exists(container, "resources", "limits", "cpu"):
            logging.debug("%s has no cpu limits configured" %
                          (config['metadata']['name']))
            has_cpu_limits = False
        if not utils.keys_exists(container, "resources", "requests", "memory"):
            logging.debug("%s has no memory requests configured" %
                          (config['metadata']['name']))
            has_memory_requests = False
        if not utils.keys_exists(container, "resources", "limits", "memory"):
            logging.debug("%s has no memory limits configured" %
                          (config['metadata']['name']))
            has_memory_limits = False
    # using regex-able strings here in case we key off these in other places
    if not has_memory_requests:
        excludes.append('k8s_container_memory_requests_')
    if not has_memory_limits:
        excludes.append('k8s_container_memory_limits_')
    if not has_cpu_requests:
        excludes.append('k8s_container_cpu_requests_')
    if not has_cpu_limits:
        excludes.append('k8s_container_cpu_limits_')
    logging.debug("Resource excludes:")
    logging.debug(excludes)
    return excludes

def check_k8s(k8s_config_file):
    '''Validate configs are single-document and a supported type.'''
    if utils.valid_doc(k8s_config_file):
        k8s_contents = utils.read_yaml_config(k8s_config_file)
        lc_kind = k8s_contents['kind'].lower()
        # if no deployments or statefulsets, do nothing
        valid_kinds = ['daemonset', 'deployment', 'statefulset']
        if lc_kind in valid_kinds:
            return k8s_contents
        else:
            return None

if __name__ == "__main__":
    # read list of global templates
    global_templates = utils.find_yaml_files(process_dir)
    # TODO hack debug remove me
    fake_container_templates = [
        './templates/automon/k8s_container_cpu_exceeding_limits-template.yaml',
        './templates/automon/k8s_container_memory_exceeding_limits-template.yaml',
    ]
    fake_svc_templates = [
        './templates/automon/svc_anomaly_detection_latency-template.yaml',
        './templates/automon/svc_anomaly_detection_requests-template.yaml',
        './templates/automon/svc_anomaly_detection_errors-template.yaml',
    ]
    # global_templates += fake_container_templates
    # global_templates += fake_svc_templates
    # TODO END hack debug remove me
    logging.debug("Global templates:")
    logging.debug(global_templates)
    annotation_excluded = []
    resource_excluded = []
    # interate through k8s configs and create exclusions:
    k8s_file_location = './k8s/%s' % (args.environment)
    logging.info("Reading k8s configs under: %s" % (k8s_file_location))
    # TODO hack debug remove me
    # k8s_file_location = './test_k8s/%s' % (args.environment)
    # TODO END hack debug remove me
    k8s_files = utils.find_yaml_files(k8s_file_location)
    for k8s_file in k8s_files:
        if check_k8s(k8s_file):
            k8s_contents = check_k8s(k8s_file)
            logging.debug(k8s_contents)
            # get list of excludes in k8s annotations
            for exclude in check_annotations(k8s_contents):
                annotation_excluded.append(exclude)
                logging.info("adding annotation exclusion: %s" % (exclude))
            # set exclusions if we're missing cpu or memory resources
            for resource in check_resources(k8s_contents):
                for t in global_templates:
                    result = re.search(resource, t)
                    if result:
                        logging.info("adding resource exclusion: %s" % (t))
                        resource_excluded.append(t)
    logging.debug("annotation_excluded: %s" % (annotation_excluded))
    logging.debug("resource_excluded: %s" % (resource_excluded))
    # remove annotation exclusions from global templates
    for exclusion in annotation_excluded:
        check_string = ("%s/%s-template.yaml" % (process_dir, exclusion))
        logging.debug("check_string: %s" % (check_string))
        if check_string in global_templates:
            logging.debug("Removing: %s" % (check_string))
            global_templates.remove(check_string)
    # add resource exclusions from global templates if config doesn't include resources
    for exclusion in resource_excluded:
        if exclusion in global_templates:
            logging.debug("Removing: %s" % (exclusion))
            global_templates.remove(exclusion)
    logging.debug(global_templates)
    # also add custom templates:
    custom_automon_dir = './automon'
    if os.path.isdir(custom_automon_dir):
        custom_templates = utils.find_yaml_files(custom_automon_dir)
        logging.info("adding custom_templates:")
        logging.info(custom_templates)
    else:
        custom_templates = []
        logging.debug('No custom automon template dir %s' %
                      (custom_automon_dir))
    all_templates = global_templates + custom_templates
    logging.info("Processing automon templates: %s" % (all_templates))
    process_automon_templates(args, all_templates)
