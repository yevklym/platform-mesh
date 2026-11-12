# Copyright The Platform Mesh Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Opt-in headless authorization compositions. Loaded by platform-mesh.Tiltfile.
load("./probes.py", "configure_authz_probes")
load("../../tilt/helpers.py", "TILT_DIR", "IMAGE_PREFIX", "profile_chart", "service", "component_binary", "writable_rootfs")
load("../../tilt/tiltfiles/settings.Tiltfile", "AUTHZ_PROFILE", "NAMESPACE", "TEMPLATE_VARS", "GO_DEPS", "KUBECTL")

INTENT = AUTHZ_PROFILE != "authz-baseline"
BACKEND = "rbac" if AUTHZ_PROFILE == "authz-rbac" else "openfga"

# Trusted test provisioning uses a dedicated copy of the existing admin config.
local_resource(
    "authz-admin-secret",
    resource_deps=["export-kcp-admin-kubeconfig"],
    allow_parallel=True,
    dir=TILT_DIR,
    cmd=KUBECTL + " create secret generic authz-poc-kubeconfig --from-file=kubeconfig=.secret/kcp-admin.kubeconfig --dry-run=client -o yaml | " + KUBECTL + " apply -f -",
    labels=["authz-poc"],
)
service("account-operator", NAMESPACE, TEMPLATE_VARS, path="operators/account-operator", deps=GO_DEPS)

flags = ["--initializer-idp-enabled=false", "--initializer-invite-enabled=false", "--initializer-workspace-auth-enabled=false"]
if INTENT:
    flags = flags + ["--authorization-intent-enabled"]

security_values = {
    "initContainer": {"enabled": not INTENT},
    "initializer": {"kubeconfigSecret": "authz-poc-kubeconfig", "extraArgs": flags},
    "terminator": {"kubeconfigSecret": "authz-poc-kubeconfig", "extraArgs": flags},
    "operator": {"extraArgs": flags},
}
if not INTENT:
    service("security-operator", NAMESPACE, TEMPLATE_VARS, path="operators/security-operator", deps=GO_DEPS,
            overrides=security_values,
            workloads=["security-operator", "security-operator-generator", "security-operator-initializer", "security-operator-system", "security-operator-terminator"])
    service("rebac-authz-webhook", NAMESPACE, TEMPLATE_VARS, path="services/rebac-authz-webhook", deps=GO_DEPS)
else:
    component_binary("security-operator", "operators/security-operator", GO_DEPS, IMAGE_PREFIX + "security-operator", labels=["authz-poc"])
    rendered = writable_rootfs(profile_chart("security-operator", NAMESPACE, TEMPLATE_VARS, security_values), IMAGE_PREFIX + "security-operator")
    objects = []
    prototype = None
    for obj in decode_yaml_stream(rendered):
        if obj.get("kind") == "Deployment":
            if obj["metadata"]["name"] not in ["security-operator-initializer", "security-operator-terminator"]:
                continue
            if obj["metadata"]["name"] == "security-operator-initializer":
                prototype = obj
        objects.append(obj)
    k8s_yaml(encode_yaml_stream(objects))
    for name in ["security-operator-initializer", "security-operator-terminator"]:
        k8s_resource(name, resource_deps=["platform-mesh-operator", "authz-admin-secret"], labels=["authz-poc"])

    args = ["authz", "--backend=" + BACKEND, "--kcp-kubeconfig=/api-kubeconfig/kubeconfig",
            "--workspace=root:orgs,root:orgs:org-a,root:orgs:org-a:account-a,root:orgs:org-b"]
    if BACKEND == "openfga":
        webhook = decode_yaml_stream(profile_chart("rebac-authz-webhook", NAMESPACE, TEMPLATE_VARS))
        for obj in webhook:
            if obj.get("kind") != "Deployment":
                continue
            pod = obj["spec"]["template"]["spec"]
            container = pod["containers"][0]
            container["image"] = prototype["spec"]["template"]["spec"]["containers"][0]["image"]
            container["args"] = args + ["--checks-only", "--fga-target=openfga:8081", "--listen=:9443", "--tls-cert=/config/tls.crt", "--tls-key=/config/tls.key"]
            configure_authz_probes(container)
            for volume in pod.get("volumes", []):
                if volume["name"] == "api-kubeconfig":
                    volume["secret"]["secretName"] = "authz-poc-kubeconfig"
        k8s_yaml(writable_rootfs(encode_yaml_stream(webhook), IMAGE_PREFIX + "security-operator"))
        k8s_resource("rebac-authz-webhook", resource_deps=["authz-admin-secret", "authz-controller"], labels=["authz-poc"])

    projector = decode_yaml(encode_yaml(prototype))
    projector["metadata"]["name"] = "authz-controller"
    projector["spec"]["selector"]["matchLabels"] = {"app": "authz-controller"}
    projector["spec"]["template"]["metadata"]["labels"] = {"app": "authz-controller"}
    container = projector["spec"]["template"]["spec"]["containers"][0]
    container["args"] = args + ["--projection-only"] + (["--fga-target=openfga:8081"] if BACKEND == "openfga" else [])
    configure_authz_probes(container)
    k8s_yaml(encode_yaml(projector))
    k8s_resource("authz-controller", resource_deps=["authz-admin-secret"] + (["openfga"] if BACKEND == "openfga" else []), labels=["authz-poc"])
include("../../tilt/tiltfiles/httpbin.Tiltfile")
