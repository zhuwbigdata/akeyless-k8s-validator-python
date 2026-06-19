README.md

kubectx to set the context to the k8s cluster where the application is installed, not the gateway cluster.

akeyless gateway-get-k8s-auth-config   -n k8s-conf   -u https://gw-gke.wz.cs.akeyless.fans > gw-gke-k8s-conf.json

python3 akeyless_k8s_validator.py --config-json gw-gke-k8s-conf.json

Inside a pod, use the CMD to validate.
./akeyless auth --access-id p-cyzzfc44hst9km --access-type k8s --gateway-url https://gw-gke.wz.cs.akeyless.fans --k8s-auth-config-name k8s-conf


$ python3 akeyless_k8s_validator.py --config-json gw-gke-k8s-conf.json

═══ Kubeconfig ═══
  ·  Context : gke_customer-success-391112_us-central1_waynez-k8s-demo
  ·  Server  : https://35.184.233.145

═══ Direct Config Validation ═══

═══ Auth Config Summary ═══
  ·  Name                      : k8s-conf
  ·  Auth Method Access ID     : p-cyzzfc44hst9km
  ·  K8s Host                  : https://35.184.233.145
  ·  K8s Auth Type             : bearer_token
  ·  Cluster API Type          : native_k8s
  ·  K8s Issuer                : https://container.googleapis.com/v1/projects/customer-success-391112/locations/us-central1/clusters/waynez-k8s-demo
  ·  Disable ISS Check         : True
  ·  Token Expiration(s)       : 300

═══ K8s Host Comparison ═══
  ✔  k8s_host matches kubeconfig server: https://35.184.233.145

═══ K8s API Server Reachability ═══
  ·  GET → https://35.184.233.145/readyz
  ✔  K8s API server is reachable at https://35.184.233.145

═══ CA Certificate Comparison ═══
  ✔  CA cert in Akeyless config matches kubeconfig CA cert

═══ Token Reviewer JWT ═══
  ·  POST → https://35.184.233.145/apis/authentication.k8s.io/v1/tokenreviews
  ✔  Token Reviewer JWT is valid
  ·  Authenticated as: system:serviceaccount:default:gateway-token-reviewer
  ·  Groups: system:serviceaccounts, system:serviceaccounts:default, system:authenticated

═══ Results ═══
  ✔  K8s API server reachable
  ✔  CA cert matches
  ✔  Token Reviewer JWT valid

All checks passed ✔

