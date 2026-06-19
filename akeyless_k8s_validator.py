#!/usr/bin/env python3
"""
akeyless_k8s_validator.py
─────────────────────────
Validates an Akeyless K8s auth configuration against the live Kubernetes cluster.

Two modes
─────────
1. Full mode  – supply --token + --gateway-url
   Enumerates all running gateways, finds configs whose k8s_host matches your
   current kubeconfig context, then validates CA cert + Token Reviewer JWT.

2. Direct mode – supply --config-json <file>  (or pipe the JSON to stdin)
   Feed the output of:
       akeyless gateway-get-k8s-auth-config -n <name> -u <gw-url>
   directly.  Reads the active kubeconfig context for the cluster endpoint /
   CA cert comparison, then validates the Token Reviewer JWT.

Usage examples
──────────────
  # Direct mode (paste the JSON you already have)
  akeyless gateway-get-k8s-auth-config -n /pep/prod/... -u https://gw/ \
      | python akeyless_k8s_validator.py --config-json -

  # Full mode
  python akeyless_k8s_validator.py \
      --token t-xxxxx \
      --gateway-url https://pepcksm.mypepsico.com/akeyless/

Dependencies:  none (stdlib only — requires Python 3.9+ and kubectl on PATH)
"""

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.request
import urllib.error
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
# Colour helpers (no third-party deps)
# ──────────────────────────────────────────────────────────────────────────────
_USE_COLOUR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text


def green(t):  return _c("92", t)
def red(t):    return _c("91", t)
def yellow(t): return _c("93", t)
def cyan(t):   return _c("96", t)
def bold(t):   return _c("1",  t)


def ok(msg):   print(f"  {green('✔')}  {msg}")
def fail(msg): print(f"  {red('✗')}  {msg}")
def info(msg): print(f"  {cyan('·')}  {msg}")
def warn(msg): print(f"  {yellow('!')}  {msg}")
def section(title): print(f"\n{bold('═══ ' + title + ' ═══')}")


# ──────────────────────────────────────────────────────────────────────────────
# kubeconfig helpers  (zero third-party deps — uses kubectl if available,
#                      otherwise falls back to a lightweight YAML line parser)
# ──────────────────────────────────────────────────────────────────────────────
def _kubectl(*args) -> str:
    """Run a kubectl command and return stdout, or raise RuntimeError."""
    import subprocess
    result = subprocess.run(["kubectl"] + list(args),
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def current_cluster_info_via_kubectl() -> tuple[str, str, str]:
    """Use kubectl to extract (context, server, base64_ca) – no YAML parser needed."""
    ctx   = _kubectl("config", "current-context")
    server = _kubectl("config", "view", "--minify",
                      "-o", "jsonpath={.clusters[0].cluster.server}")
    # Try inline CA data first
    ca_b64 = _kubectl("config", "view", "--minify", "--raw",
                      "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}")
    if not ca_b64:
        # CA stored as a file path
        ca_file = _kubectl("config", "view", "--minify",
                           "-o", "jsonpath={.clusters[0].cluster.certificate-authority}")
        if ca_file:
            with open(ca_file, "rb") as f:
                ca_b64 = base64.b64encode(f.read()).decode()
    return ctx, server.rstrip("/"), ca_b64


def _parse_kubeconfig_fallback(kube_path: str) -> tuple[str, str, str]:
    """
    Minimal line-by-line kubeconfig parser that avoids PyYAML.
    Handles the common single-context kubeconfig layout produced by
    gcloud / az aks get-credentials / eksctl.
    """
    with open(kube_path) as f:
        lines = f.readlines()

    def find_value(key: str) -> str:
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(key + ":"):
                return stripped[len(key) + 1:].strip()
        return ""

    ctx    = find_value("current-context")
    server = find_value("server").rstrip("/")
    ca_b64 = find_value("certificate-authority-data")
    ca_file = find_value("certificate-authority")
    if not ca_b64 and ca_file:
        with open(ca_file, "rb") as f:
            ca_b64 = base64.b64encode(f.read()).decode()
    return ctx, server, ca_b64


def current_cluster_info() -> tuple[str, str, str]:
    """Return (context_name, server_url, base64_ca_cert) using the best available method."""
    # Prefer kubectl — it handles merges, env overrides, exec plugins, etc.
    try:
        ctx, server, ca_b64 = current_cluster_info_via_kubectl()
        info(f"Context : {ctx}")
        info(f"Server  : {server}")
        return ctx, server, ca_b64
    except Exception as e:
        if "kubectl" in str(e).lower() or "No such file" in str(e):
            warn("kubectl not found, falling back to direct kubeconfig parse")
        else:
            warn(f"kubectl query failed ({e}), falling back to direct parse")

    kube_path = os.environ.get("KUBECONFIG", str(Path.home() / ".kube" / "config"))
    info(f"Kubeconfig: {kube_path}")
    ctx, server, ca_b64 = _parse_kubeconfig_fallback(kube_path)
    info(f"Context : {ctx}")
    info(f"Server  : {server}")
    return ctx, server, ca_b64


# ──────────────────────────────────────────────────────────────────────────────
# HTTP helpers (stdlib only)
# ──────────────────────────────────────────────────────────────────────────────
def _ssl_ctx(verify: bool = True) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_get(url: str, token: str, verify_ssl: bool = True, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}",
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(verify_ssl), timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} from {url}: {body}")


def http_post_json(url: str, payload: dict, token: str,
                   verify_ssl: bool = True, timeout: int = 30) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(verify_ssl), timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} from {url}: {body}")


# ──────────────────────────────────────────────────────────────────────────────
# Akeyless gateway helpers
# ──────────────────────────────────────────────────────────────────────────────
def list_gateways(api_url: str, token: str) -> list[dict]:
    url = api_url.rstrip("/") + "/v2/list-gateways"
    body = http_post_json(url, {"token": token}, token)
    return body.get("clusters", [])


def get_k8s_auth_configs(gateway_cluster_url: str, token: str) -> list[dict]:
    url = gateway_cluster_url.rstrip("/") + "/config/k8s-auths"
    try:
        data = http_get(url, token)
        return data.get("k8s_auths", [])
    except Exception as e:
        warn(f"Could not fetch k8s-auths from {gateway_cluster_url}: {e}")
        return []


# ──────────────────────────────────────────────────────────────────────────────
# Validation logic
# ──────────────────────────────────────────────────────────────────────────────
def validate_ca_cert(config: dict, local_ca_b64: str, verbose: bool = False) -> bool:
    section("CA Certificate Comparison")
    stored = config.get("k8s_ca_cert", "")
    if verbose:
        info(f"Stored  CA (b64, first 60): {stored[:60]}…")
        info(f"Local   CA (b64, first 60): {local_ca_b64[:60]}…")

    # Normalise: strip whitespace / newlines that base64 encoding can introduce
    s_norm = stored.replace("\n", "").strip()
    l_norm = local_ca_b64.replace("\n", "").strip()

    if s_norm == l_norm:
        ok("CA cert in Akeyless config matches kubeconfig CA cert")
        return True
    else:
        fail("CA cert MISMATCH – the cert stored in Akeyless does not match your kubeconfig")
        if verbose:
            info(f"Stored : {s_norm}")
            info(f"Local  : {l_norm}")
        return False


def validate_token_reviewer(config: dict, verbose: bool = False) -> bool:
    section("Token Reviewer JWT")
    k8s_host = config.get("k8s_host", "").rstrip("/")
    reviewer_jwt = config.get("k8s_token_reviewer_jwt", "")

    if not reviewer_jwt:
        fail("k8s_token_reviewer_jwt is empty – nothing to validate")
        return False

    if not k8s_host:
        fail("k8s_host is empty – cannot call TokenReview API")
        return False

    url = f"{k8s_host}/apis/authentication.k8s.io/v1/tokenreviews"
    info(f"POST → {url}")

    payload = {
        "kind": "TokenReview",
        "apiVersion": "authentication.k8s.io/v1",
        "spec": {"token": reviewer_jwt},
    }

    try:
        resp = http_post_json(url, payload, reviewer_jwt, verify_ssl=False)
    except Exception as e:
        fail(f"TokenReview request failed: {e}")
        return False

    if verbose:
        info(f"Response: {json.dumps(resp, indent=2)}")

    status = resp.get("status", {})
    authenticated = status.get("authenticated", False)

    if authenticated:
        username = status.get("user", {}).get("username", "<unknown>")
        groups   = status.get("user", {}).get("groups", [])
        ok(f"Token Reviewer JWT is valid")
        info(f"Authenticated as: {green(username)}")
        if groups:
            info(f"Groups: {', '.join(groups)}")
        return True
    else:
        fail("Token Reviewer JWT is NOT valid (authenticated=false)")
        error_detail = resp.get("status", {}).get("error", "")
        if error_detail:
            info(f"Error detail: {red(error_detail)}")
        return False


def validate_host_reachable(config: dict) -> bool:
    section("K8s API Server Reachability")
    host = config.get("k8s_host", "").rstrip("/")
    url  = host + "/readyz"
    info(f"GET → {url}")
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=_ssl_ctx(False), timeout=10) as r:
            body = r.read().decode(errors="replace")
        if "ok" in body.lower() or r.status == 200:
            ok(f"K8s API server is reachable at {host}")
        else:
            warn(f"Unexpected response ({r.status}): {body[:200]}")
        return True
    except Exception as e:
        fail(f"Cannot reach K8s API server at {host}: {e}")
        return False


def print_config_summary(config: dict):
    section("Auth Config Summary")
    fields = [
        ("Name",               "name"),
        ("Auth Method Access ID", "auth_method_access_id"),
        ("K8s Host",           "k8s_host"),
        ("K8s Auth Type",      "k8s_auth_type"),
        ("Cluster API Type",   "cluster_api_type"),
        ("K8s Issuer",         "k8s_issuer"),
        ("Disable ISS Check",  "disable_iss_validation"),
        ("Token Expiration(s)","am_token_expiration"),
    ]
    for label, key in fields:
        val = config.get(key)
        if val is not None:
            info(f"{label:<26}: {cyan(str(val))}")


def run_validation(config: dict, local_server: str, local_ca_b64: str,
                   verbose: bool, skip_reachability: bool) -> bool:
    print_config_summary(config)

    # Check host match vs kubeconfig
    section("K8s Host Comparison")
    stored_host = config.get("k8s_host", "").rstrip("/")
    local_host  = local_server.rstrip("/")
    if stored_host == local_host:
        ok(f"k8s_host matches kubeconfig server: {green(stored_host)}")
    else:
        warn(f"k8s_host in config  : {stored_host}")
        warn(f"kubeconfig server   : {local_host}")
        warn("Hosts differ – you may be validating against the wrong cluster")

    results = {}

    if not skip_reachability:
        results["reachable"] = validate_host_reachable(config)

    if local_ca_b64:
        results["ca_cert"] = validate_ca_cert(config, local_ca_b64, verbose)
    else:
        warn("No local CA cert found in kubeconfig – skipping CA comparison")

    results["token_reviewer"] = validate_token_reviewer(config, verbose)

    # ── Summary ──────────────────────────────────────────────────────────────
    section("Results")
    all_passed = True
    checks = {
        "reachable":      "K8s API server reachable",
        "ca_cert":        "CA cert matches",
        "token_reviewer": "Token Reviewer JWT valid",
    }
    for key, label in checks.items():
        if key not in results:
            info(f"{label:<35} skipped")
        elif results[key]:
            ok(f"{label}")
        else:
            fail(f"{label}")
            all_passed = False

    print()
    if all_passed:
        print(green(bold("All checks passed ✔")))
    else:
        print(red(bold("One or more checks FAILED ✗")))

    return all_passed


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="Validate an Akeyless K8s auth configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Mode A – direct JSON
    p.add_argument(
        "--config-json", metavar="FILE|-",
        help="Path to gateway-get-k8s-auth-config JSON output, or '-' to read stdin",
    )

    # Mode B – full gateway enumeration
    p.add_argument("--token",       "-t", metavar="TOKEN",
                   help="Akeyless token (required for full mode)")
    p.add_argument("--gateway-url", "-u", metavar="URL",
                   default="https://api.akeyless.io",
                   help="Akeyless API Gateway URL")
    p.add_argument("--config-name", "-n", metavar="NAME",
                   help="Filter to a specific k8s auth config name (full mode)")

    # Common
    p.add_argument("--kubeconfig", metavar="PATH",
                   help="Path to kubeconfig (default: ~/.kube/config)")
    p.add_argument("--skip-reachability", action="store_true",
                   help="Skip the K8s API server reachability check")
    p.add_argument("--verbose", "-v", action="store_true")

    return p.parse_args()


def main():
    args = parse_args()

    if args.kubeconfig:
        os.environ["KUBECONFIG"] = args.kubeconfig

    # ── Load kubeconfig ───────────────────────────────────────────────────────
    section("Kubeconfig")
    try:
        _, local_server, local_ca_b64 = current_cluster_info()
    except FileNotFoundError as e:
        warn(f"Could not load kubeconfig: {e}")
        warn("CA cert comparison and host comparison will be skipped")
        local_server = ""
        local_ca_b64 = ""

    exit_code = 0

    # ─────────────────────────────────────────────────────────────────────────
    # Mode A: direct JSON
    # ─────────────────────────────────────────────────────────────────────────
    if args.config_json:
        section("Direct Config Validation")
        if args.config_json == "-":
            raw = sys.stdin.read()
        else:
            with open(args.config_json) as f:
                raw = f.read()
        config = json.loads(raw)
        passed = run_validation(config, local_server, local_ca_b64,
                                args.verbose, args.skip_reachability)
        sys.exit(0 if passed else 1)

    # ─────────────────────────────────────────────────────────────────────────
    # Mode B: full gateway enumeration
    # ─────────────────────────────────────────────────────────────────────────
    if not args.token:
        token_env = os.environ.get("AKEYLESS_TOKEN", "")
        if not token_env:
            sys.exit(red("Provide --token / AKEYLESS_TOKEN, or use --config-json for direct mode"))
        args.token = token_env

    section("Gateway Enumeration")
    info(f"Gateway URL: {args.gateway_url}")

    try:
        gateways = list_gateways(args.gateway_url, args.token)
    except Exception as e:
        sys.exit(red(f"Failed to list gateways: {e}"))

    running = [g for g in gateways if g.get("status") == "Running"]
    info(f"Running gateways found: {len(running)}")

    matched_configs = []

    for gw in running:
        cluster_url = gw.get("clusterUrl") or gw.get("cluster_url", "")
        display_name = gw.get("displayName") or gw.get("display_name", "")
        cluster_name = gw.get("clusterName") or gw.get("cluster_name", "")
        gw_label = display_name or cluster_name

        if not cluster_url:
            if args.verbose:
                warn(f"Skipping gateway '{gw_label}' – no clusterUrl")
            continue

        if args.verbose:
            info(f"Fetching k8s auth configs from: {gw_label} ({cluster_url})")

        configs = get_k8s_auth_configs(cluster_url, args.token)

        for cfg in configs:
            # Filter by name if requested
            if args.config_name and cfg.get("name") != args.config_name:
                continue
            # Filter by matching host if we have a local server
            if local_server and cfg.get("k8s_host", "").rstrip("/") != local_server.rstrip("/"):
                if args.verbose:
                    warn(f"Skipping config '{cfg.get('name')}' – host mismatch")
                continue
            matched_configs.append((gw_label, cfg))

    if not matched_configs:
        fail("No matching K8s auth configs found across all running gateways")
        if local_server:
            info(f"Looked for k8s_host == {local_server}")
        sys.exit(1)

    for gw_label, config in matched_configs:
        print(f"\n{bold('Gateway: ' + gw_label)}")
        passed = run_validation(config, local_server, local_ca_b64,
                                args.verbose, args.skip_reachability)
        if not passed:
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()