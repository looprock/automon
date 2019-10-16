# Introduction
DISCLAIMER: This wasn't intented as a generalized tool and will probably require some modification to use!

We store our manifests inside a folder: /k8s/*environment*. The script reads all the manifests inside 
this folder and searches for the types: daemonset, deployment, statefulset and executes any template
*not* included in 'global_exclusions' against that manifest.

# Arguments
**--team** - REQUIRED: Define a team for template processing

**--environment** - REQUIRED: Define an environment for template processing

**--deployment** - REQUIRED: Define a deployment for template processing.

**--watchtype** - REQUIRED: Define a watchtype (deployment, statefulset, daemonset) for template processing

**--namespace** - Define a namespace for template processing

**--notif** - force to notif channel

**--silence** - mute all monitors

# Template variables
The following variables are passed through from the arguments you pass into the ‘deploy’ script:

**corp_env** - any valid datadog tag starting with ‘env:’

**deployment** - This is the name of the deployment, statefulset, or daemonset passed in through the deploy script

**team_name** - the literal value of the team argument passed in from the deploy script; supported values: agent-tools, consumer, data-platform, data-science-engineering, operations, panel, platform

**team** - this is the typically used in the message context, and identifies the actual notification channel.

-if the environment is beta, this is set to the team’s alerting slack channel

-if team_notif is set to true, this is set to the team’s notification slack channel

-otherwise, this is set to the team’s opsgenie notifications

**namespace** - the namespace passed in from the deploy script

**watchtype** - the watchtype passed in from the deploy script; supported values: deployment, statefulset, daemonset

# k8s requests/limits monitor templates
The script searched valid manifest for memory and cpu requests and limits configurations, and, those exist, it will execute any templates with the names:

k8s_container_cpu_limits/requests_*anything*

k8s_container_limits/memory_requests_*anything*

# Custom monitor templates
Automon supports the dynamic creation of monitors based on YAML objects. 
To use this facility, create a directory ‘automon’ under your build root 
with YAML files defining the monitors you wish to be created. The specifics 
of the definition can be found here:

https://docs.datadoghq.com/api/?lang=python#monitors

## Custom template example
You can pass in the raw YAML without using any of the variables above or use the variables above in your template.

```name: "kube {{corp_env}}: {{namespace}} {{deployment}} Frequent Restarts"
type: "query alert"
query: "change(avg(last_5m),last_5m):avg:kubernetes.containers.restarts{env:{{corp_env}},kube_{{watchtype}}:{{deployment}},kube_namespace:{{namespace}}} > 5"
message: "{{team}}"
options:
  notify_audit: False
  require_full_window: True
  thresholds:
    critical: 5.0
    warning: 4.0
    critical_recovery: 1
    warning_recovery: 1
tags:
  - "base_service:kubernetes"
  - "k8s_resource_type:pod"
  - "env:{{corp_env}}"
  - "team:{{team_name}}"
```

# k8s based anomaly detection monitors
This method uses a Kubernetes annotation in the deployment to define one or more anomaly detection monitors 
for a specific service. By scoping this to a specific monitor type which doesn’t require much information 
we can generate monitors with a minimal amount of input from the person actually required to apply the 
changes, making it low effort but high impact process. This  method could also be turned into inputs for a 
Kubernetes Operator that might be in the works.


To create an anomaly detection monitor in Datadog, you would just need to create an annotation of the format:

ci.corp.com/anomaly-monitor.[service]: [comma separated list of metrics or aliases]

example: ci.corp.com/anomaly-monitor.my-server: trace.servlet.request.errors,grpc

If you use one of the pre-defined ‘aliases’, that will be expanded to multiple metrics references, otherwise that metric will be used verbatim. 

Those metrics will be fed to the _generic_anomaly_detection-template.yaml_ template.

## Flow 
![alt text](https://github.com/looprock/automon/blob/master/Automon_flow.png "Automon Flow")

## Aliases
**aiohttp:** - trace.aiohttp.request.errors, trace.aiohttp.request.duration, trace.aiohttp.request.hits

**akka:** - trace.akka_http.request.errors, trace.akka_http.request.duration, trace.aiohttp.request.hits

**express:** - trace.express.request.duration, trace.express.request.hits

**graphql:** - trace.graphql.execute.duration, trace.graphql.execute.hits, trace.graphql.parse.duration, trace.graphql.parse.hits

**grpc:** - trace.grpc.server.errors, trace.grpc.server.duration, trace.grpc.server.hits

**http:** - trace.http.request.errors, trace.http.request.duration, trace.http.request.hits

**koa:** - trace.koa.request.errors, trace.koa.request.duration, trace.koa.request.hits

**okhttp:** - trace.okhttp.http.errors, trace.okhttp.http.duration, trace.okhttp.http.hits

**outbound:** - trace.outbound.profile_event.duration, trace.outbound.profile_event.hits

**pg:** - trace.pg.query.errors, trace.pg.query.duration, trace.pg.query.hits

**restify:** - trace.restify.request.errors, trace.restify.request.duration, trace.restify.request.hits

**servlet:** - trace.servlet.request.errors, trace.servlet.request.duration, trace.servlet.request.hits