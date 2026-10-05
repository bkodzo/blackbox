# Deployment

## Principles

- **Keep the signing key away from the log.** Anyone who can read the key can
  write a log that verifies. Store it in its own directory, readable only by
  the gateway, and never next to the log or its backups.
- **Ship checkpoints off the host.** Checkpoints are printed to stdout by
  default. Send stdout to a log collector or another machine, so someone who
  controls the gateway host cannot truncate the log and the checkpoints
  together.
- **Make the gateway the only route to the model server.** blackbox records
  only traffic sent to it. Use network policy so agents cannot reach the model
  server directly.
- **Control who can reach the gateway.** It has no authentication of its own;
  anyone who can reach it can use the model server through it. Bind it to
  localhost or a private network.
- **Run one gateway per log.** The gateway locks its log, so a second one
  pointed at the same file refuses to start. A supervisor that restarts the
  gateway should wait for the old process to exit, or retry until it has.
- **Give auditors the public key separately.** Verification is only as good as
  the public key it is checked against.

## Container

The image is published as `ghcr.io/bkodzo/blackbox`. It runs as a non-root
user, so run it as your own user to let it write to mounted directories:

```
mkdir -p keys data
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/keys:/keys" \
  ghcr.io/bkodzo/blackbox init --dir /keys

docker run -d -p 127.0.0.1:8080:8080 --user "$(id -u):$(id -g)" \
  -v "$PWD/keys:/keys:ro" -v "$PWD/data:/data" \
  ghcr.io/bkodzo/blackbox serve --listen 0.0.0.0:8080 \
  --key /keys/key.ed25519 --upstream http://host.docker.internal:PORT
```

The key directory is mounted read-only and separately from the data
directory. Inside a container the gateway has to listen on `0.0.0.0`, so the
port is published only on `127.0.0.1`. `docker logs` keeps the checkpoint lines
printed to stdout.

To verify the log from the container:

```
docker run --rm -v "$PWD/keys:/keys:ro" -v "$PWD/data:/data:ro" \
  ghcr.io/bkodzo/blackbox verify --pub /keys/key.pub
```

## Release integrity

Release archives and the container image are signed with Sigstore cosign
(keyless) and come with SBOMs and build provenance attestations, which can be
checked with `gh attestation verify` or `cosign verify`.
