# Carnet where the internet is not

Two environments, and they want different things.

**On-premises.** Your own datacentre or private cloud. Outbound internet exists but goes
through a proxy; TLS is intercepted by your own root CA; images must come from an
internal registry as policy; your Jira, your GitLab and your model gateway are all on
RFC 1918 addresses. This is the majority case and most of this page is one paragraph per
setting, because each is one setting.

**The sealed estate.** A bank, a defence contractor, a hospital. No outbound path at all.
Software arrives as a file a person carries in. Everything above applies, plus the
install itself has to work with no network — which is the second half of this page.

Carnet is the right shape for both. It brings its own Postgres or uses yours, uses your
identity provider, holds one key you generate, has no model key and no vendor account,
and phones nothing home: no analytics, no error reporter, no update check. What follows
are the seams where a product developed on the open internet had to be told where it
was. Every one is configuration. None is a fork.

## On-premises: one setting each

Everything here goes in `deploy/.env`; `deploy/.env.example` documents each with the
reasoning, and `deploy/README.md` is the deployment narrative this page assumes you have
read.

### Your networks

`CARNET_EGRESS_INTERNAL_HOSTS=10.0.0.0/8,fd00::/8` — the operator consenting to the
deployment's own networks, in CIDR. Without it, every connector host must resolve to a
public address, which on a private network is none of them; that was the refusal that
stopped the first install this page was written for. A name that resolves inside a
claimed network is admitted for where it resolves, so the whole estate is one entry
rather than a hostname per connector and a restart to add each. Link-local (cloud
metadata) stays refused whatever this says, and a claim that covers it is refused at
start. Tenants still approve each host individually (`carnet --allow-host`); this only
stops *private address* from being the reason a host they approved cannot be dialled.

### Your certificate authority

`REQUESTS_CA_BUNDLE=/etc/carnet/ca/corporate-ca.pem`, plus the commented volume on the
`api` service in `compose.yaml` that mounts the file. This is the root that re-signs
intercepted TLS at your proxy, or that issues your internal services' certificates. The
file *replaces* the bundled public roots rather than adding to them, so if anything is
still dialled direct to the internet, concatenate the public roots into it. `SSL_CERT_FILE`
is deliberately not offered: a blank one empties the trust store.

### Your proxy

`CARNET_EGRESS_PROXY=http://proxy.corp:3128` (or `http://user:pass@…`). Dials to the
internet then go through the proxy **by name** — the proxy resolves, which is what a
CONNECT proxy is for and why an external name that does not resolve inside the building
still works. Your own networks are dialled direct and keep every check. Three things:

- `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` are never read, and one of them set while
  this is empty refuses at start. A Docker daemon's proxy config injects them into every
  container; the refusal exists because before it, an ambient proxy quietly disabled the
  door's TLS pin.
- Kerberos and NTLM proxies do not work. Basic credentials in the URL do.
- **The proxy must not buffer `text/event-stream`.** `/v1/chat/completions` streams a
  model's answer while it is still arriving; a proxy that holds a body to inspect it
  delays the first chunk past `CARNET_MODEL_CHUNK_TIMEOUT`, and the engineer sees a
  model call that hangs and then fails on a deployment that is working. There is no
  application-side fix — a buffered stream is indistinguishable from a slow model — so
  the symptom to look for is exactly that timeout, and the fix is a proxy rule.

What the declaration trades: the door's DNS-rebinding check on the resolved address
moves to the proxy. Right for a proxy that already governs every packet leaving the
building; wrong for a cloud deployment that set the variable because it seemed harmless.
`backend/src/carnet/tools/mcp/egress.py`'s docstring has the argument in full.

### Your certificate on the front door

`CARNET_TLS_MODE=files`, with `cert.pem` (the chain) and `key.pem` in `./tls` beside
`compose.yaml` and the commented volume on the `front` service uncommented. Or
`internal` for Caddy's own CA on an intranet name. `acme`, the default, needs Let's
Encrypt to reach port 80 on this machine and will not work behind a firewall. If TLS
terminates at your own load balancer instead, `deploy/README.md` — *Your ingress instead
of the front door* — is the contract to reproduce, including the one obligation
streaming added: do not buffer the response body.

### Your registry

`CARNET_BASE_REGISTRY=harbor.corp/dockerhub` — the mirror the four base images come
from. The images stay pinned by digest, and that is the point: a mirror preserves
digests, so a retargeted build pulls **the same bytes from a different address** and the
reproducibility the pin exists for is not spent. A path after the host is fine
(`artifactory.corp/docker-remote`); the image names (`library/python:3.12-slim@sha256:…`)
follow the prefix unchanged, which is where Docker Hub's official images live in every
mirror that proxies it. The unmodified default is `docker.io`, and a build with nothing
set is byte-for-byte what it was.

The published image, `ghcr.io/carnet-mcp/carnet`, is the `api` target of the same
Dockerfile, and a mirror that proxies GHCR can serve it too; the compose stack builds
from the checkout by default and does not need it.

### Building behind the proxy

The build itself — `npm ci` and `pip install --require-hashes` inside the image — reaches
the public npm and PyPI registries. Docker passes its own proxy configuration into the
build as the predefined `HTTP_PROXY`/`HTTPS_PROXY` build arguments, and both package
managers honour them; that is enough for a proxy that passes TLS through. A proxy that
**re-signs** TLS breaks both — each verifies its registry against the public roots baked
into the base image — and the honest answer is not to teach the build about your CA but
to build where the internet is genuine and carry the image, which is the next section.

## The sealed estate: the artefact a person carries in

The install does not need the internet because the *build* does not need to happen
there. `npm ci` and `pip install` run inside the image, on a connected machine. Ship the
built image and neither registry is ever contacted again. Everything below is that.

### On the connected side

From a checkout, on a machine with Docker and an internet connection:

```bash
backend/scripts/offline_bundle.sh --platform linux/amd64
```

`--platform` is not optional in practice. `docker save` writes the image this daemon
holds, for this daemon's architecture; a laptop is arm64 and the servers it is bound for
are almost always amd64, and a bundle built without the flag loads cleanly and then
refuses to start with `exec format error` on a machine where nobody can pull the right
one. Name the target's architecture. The build runs under emulation and is slow.

The script builds `carnet-api` and `carnet-front` from the current commit, pulls the
Postgres image `compose.yaml` pins, and writes one tarball,
`backend/var/offline/carnet-offline-<version>-<os>-<arch>.tar`, holding:

| | |
| --- | --- |
| `images.tar.gz` | the three images, `docker save` output |
| `deploy/` | the compose file, `.env.example`, the Caddyfile, the entrypoint, the initdb script, the Dockerfile, the deployment README |
| `carnet.example.yaml` | every key of the fileborne door's file, for the `docker run` shape |
| `docs/OFFLINE.md`, `docs/UPGRADING.md`, `docs/GUIDE.md` | this page, the upgrade contract, and how to register a connector and broker a model — carried because a sealed estate cannot go and read them |
| `LICENSE`, `NOTICE` | the licence, because the far side has no link to click |
| `MANIFEST` | version, commit, date, platform, and each image's layer digests |
| `SHA256SUMS` | over every other file |
| `verify.sh` | the far side's check, twice |

It prints the tarball's own sha256. **Record that where the far side can read it** — a
ticket, a signed message — and carry the tarball in. Verify the published image's
signature on this side, while you can (`cosign verify`, in the README); the far side
cannot, and the next section says what it can do instead.

### On the far side

Unpack it somewhere your container runtime can read. On Linux that is anywhere. On
Docker Desktop it must be one of the shared folders, and `/tmp` is not one of them:
a bind mount from an unshared path arrives **empty**, the bundled database never runs
its init script, and the only thing you see is `migrate` exiting with `password
authentication failed for user "carnet_app"`. `verify.sh --loaded` checks this for you
and says so in those words.

```bash
sha256sum carnet-offline-*.tar          # first, against the value that was recorded
tar -xf carnet-offline-*.tar
cd carnet-offline-*/
./verify.sh                             # every file matches SHA256SUMS
docker load -i images.tar.gz
./verify.sh --loaded                    # the images, the architecture, and the mounts

cd deploy
cp .env.example .env && chmod 600 .env
docker run --rm carnet-api carnet --generate-key   # runs from the loaded image, no network
```

Then `.env`, and every line of it is one of the settings above:

```bash
CARNET_SECRET_KEY=…                          # from --generate-key; keep it in your secret store
CARNET_DOMAIN=carnet.corp.example            # the name people will type
CARNET_TLS_MODE=files                        # or internal; acme cannot work here
CARNET_DB_IMAGE=postgres:16                  # the loaded tag — see below
CARNET_EGRESS_INTERNAL_HOSTS=10.0.0.0/8      # your estate, in CIDR
REQUESTS_CA_BUNDLE=/etc/carnet/ca/corporate-ca.pem   # if your services' certificates are yours; mount it
CARNET_OIDC_ISSUER=…                         # your identity provider, on your network
CARNET_OIDC_CLIENT_ID=…
CARNET_BOOTSTRAP_ADMIN=…
```

And up — **without `--build`**:

```bash
docker compose up -d
```

`deploy/README.md` says `up -d --build`, and here the flag is wrong: there is nothing to
build from and nowhere to pull from. Compose finds `carnet-api`, `carnet-front` and
`postgres:16` already loaded and starts them; its default pull policy is *missing*, so
an image that is present is never fetched. `migrate` runs first and `api` waits for it,
exactly as on the open internet. Then `--add-tenant` and `--add-idp` from the README's
day one, against your identity provider.

**Why `CARNET_DB_IMAGE`.** `compose.yaml` pins the database as
`postgres:16@sha256:…`. Whether that digest still names the image after `docker load`
depends on which image store the far side's Docker uses, and nobody should have to know
which they run: `docker save` writes an OCI layout whose `index.json` carries the
digest, so a Docker on the **containerd image store** keeps it and the pinned reference
resolves, while one on the **classic image store** reads the legacy `manifest.json`
beside it, which carries tags and no digest, loses it, and tries to pull from a registry
that is not there. The tag is in the tarball either way, so the setting names the tag.
`MANIFEST` records that the tag *is* the pinned digest, and `verify.sh --loaded` checks
the layer lists, which are content-addressed and identical under both stores, so nothing
is given up but the spelling.

**If `migrate` exits with a password failure**, read the paragraph above about where
you unpacked the bundle, and run `./verify.sh --loaded` again. The role that failed to
authenticate is created by `deploy/initdb/01-app-role.sh`, which the database runs only
on a first start and only if it can see the file.

**What the first `up` does.** `migrate` creates the schema and exits; `api` starts and
goes healthy on one real database round trip; `front` starts and, under `files`, serves
your certificate at once — nothing is obtained from anybody. If `CARNET_TLS_MODE` was
left at `acme` with a real name, Caddy tries to reach Let's Encrypt, cannot, retries
forever, and the front door never answers on 443: `docker compose logs front` says
`obtaining certificate` over and over. Set `files` or `internal`.

**Upgrades** are another tarball. `docker load` the new one, `docker compose up -d`, and
compose sees a new image behind the same tag, recreates the containers, and runs the new
`migrate` before the new `api` serves. `docs/UPGRADING.md` — in the bundle — is the
contract for what a migration may do to your database, and the rule for settings a
release added stands: read its section 5 before the `up`.

### What does not work in a sealed estate

The useful half of this page.

- **`cosign verify`.** Keyless signing verifies against Fulcio and Rekor, which are on the
  internet. What you have instead is weaker and should be described as such: the
  tarball's sha256, recorded on the connected side, says the tarball was not altered on
  the way; `SHA256SUMS` says each file inside is the file that was checked; `MANIFEST`
  says which commit built it and which layers each image has. Together they prove *these
  are the bytes that were carried in*. They do not prove who built them. Only the
  signature says that, and it has to be checked on the connected side, by the person
  who then records the sha256.
- **`acme`.** Let's Encrypt cannot reach you and you cannot reach it. `files` or
  `internal`.
- **The README's four-line quickstart.** `curl raw.githubusercontent.com` and `docker run
  ghcr.io/…` both need the internet. The fileborne door itself works from the loaded
  image: `docker run … carnet-api` in place of `ghcr.io/carnet-mcp/carnet`, and
  `carnet.example.yaml` is in the bundle.
- **Anything on the internet.** Every connector host must be inside the estate and
  inside a claimed network; a public vendor's API is not reachable and no setting makes
  it so. The company's own model gateway is — `docs/GUIDE.md`'s *Put Carnet in front of
  Azure OpenAI* is the shape, pointed at an internal address. A vault
  (`CARNET_VAULT_URL`) must be inside too.
- **`carnet --local` and `pip install`.** The developer path is a `pip install` and stays
  one. The sealed estate gets the image.
- **`git pull && docker compose up -d --build`.** The upgrade line in `deploy/README.md`
  is replaced by the tarball, above.
- **Kerberos and NTLM proxies**, where there is a proxy at all.
- **One bundle, one architecture.** `docker save` carries the daemon's platform. A mixed
  estate needs a bundle per architecture, each built with its own `--platform`.

### What is still wrong, stated plainly

- **Nobody has run this in a real bank.** The failure that prompted it was reported, not
  reproduced; the seams above were found by reading the install path against what a
  sealed network does. That is a good method and not the same as an install. The first
  real one will find another.
- **The manifest is not a signature**, and this page has tried not to dress it up as
  one. A signed bundle — a detached signature over `SHA256SUMS` under a key the far side
  already trusts — is the honest next step, and it waits for the first customer who asks
  for it in words.
- **DNS has no deadline.** `socket.getaddrinfo` takes no timeout, so a stalled internal
  resolver holds a door call for the OS resolver's timeout. An on-premises estate has
  more internal resolvers than a cloud one, so this gets more likely rather than less.
  Known, and deliberately not fixed here: it needs a resolver thread or a resolver
  library, and everything on this page is a seam rather than machinery.
- **The proxy path gives up the resolved-address check**, and no documentation makes
  that free. The refusal of an ambient proxy variable is the mitigation; a deliberate
  `CARNET_EGRESS_PROXY` on a cloud deployment weakens its own SSRF posture and only the
  docstring will say so.
