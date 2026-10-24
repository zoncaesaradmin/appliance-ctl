# Three-server install inventory (implementation in progress)

The new embedded-etcd topology uses one install-time inventory on each host.
It is **not** part of the signed, portable appliance bundle and contains no
K3s tokens or private keys. The file below describes the intended cluster;
the installer must still prove host identity, connectivity, TLS, and etcd
membership before treating installation as complete.

```json
{
  "topology": "three-server-etcd-v1",
  "bootstrapNode": "server-a",
  "nodes": [
    {"name": "server-a", "address": "10.20.0.11"},
    {"name": "server-b", "address": "10.20.0.12"},
    {"name": "server-c", "address": "10.20.0.13"}
  ]
}
```

The three addresses must be distinct, reachable unicast IPv4 addresses assigned
to their respective servers. They may be private LAN/VPC addresses or directly
assigned VPS addresses. All three nodes are K3s servers and schedulable; there
is no agent or dedicated worker role.

There is deliberately no floating address or mandatory load balancer for the
Kubernetes milestone. The API endpoints are the three direct URLs derived from
this file, in bootstrap-first order:

```
https://10.20.0.11:6443
https://10.20.0.12:6443
https://10.20.0.13:6443
```

The K3s server certificate includes all three addresses. A caller that needs
N-1 API availability must try the next address after a connection failure; a
single URL in kubeconfig or another client does not automatically fail over.
The first joining servers initially contact the bootstrap address, after which
they become independently usable API targets. Operators must restrict etcd
ports 2379/2380 to the three server addresses even where those addresses are
publicly routed. A highly available product HTTPS origin is an application-HA
milestone and is not claimed by this Kubernetes-only topology.

For a signed three-server release, do not run the legacy `zonctl install`
command. The explicit, resumable sequence is:

1. On `bootstrapNode`, run `zonctl cluster-server-stage` with the inventory.
2. On that node, issue one protected `cluster-server-enrollment-create`
   artifact for each other inventory node. Transfer each artifact out of band.
3. On the two peers, run `cluster-server-stage` with its artifact and the
   bootstrap signer fingerprint. Both peers become K3s servers, never agents.
4. On `bootstrapNode`, run `zonctl cluster-finalize`. It refuses to deploy
   product charts until three Ready schedulable servers, all direct API URLs,
   and exactly three voting embedded-etcd members pass validation.

Every operation verifies the signed bundle and inventory before mutation.
Interrupted stage/finalize runs are rerunnable with the same inputs. Legacy
releases without a topology declaration continue to use their existing paths
while migration tooling is developed.

After three servers are running, the read-only command below checks the
Kubernetes/embedded-etcd substrate:

```sh
zonctl cluster-ha-check --bundle-dir <signed-bundle> --cluster-inventory <path>
```

It requires all three planned nodes to be Ready, schedulable,
control-plane/etcd labelled, on the signed K3s version and planned server
addresses, plus a linearizable three-voter etcd member-list response and a
healthy response from every peer via the K3s-managed client certificate.
Passing this check does not establish application HA. `cluster-finalize` is
the separate product-deployment step after this substrate gate.

Cluster-wide recovery and day-two maintenance are not part of this first
Kubernetes-HA milestone. On any staged or finalized three-server host,
`backup`, `restore`, `repair`, `upgrade`, `uninstall`, and `factory-reset`
must fail closed rather than operate on one local etcd member. Preserve the
state and use the documented recovery procedure until a quorum-aware snapshot,
restore, rolling-upgrade, and member-replacement implementation has passed its
failure drills. Read-only `status`, `verify`, support bundles, and
`cluster-ha-check` remain available for diagnosis.
