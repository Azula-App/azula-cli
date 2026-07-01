# azula shell container

Run `azula serve` inside a container so the app's **terminal** connects to a real
bash shell running in it — over iroh, end-to-end encrypted, with **no inbound
ports** (iroh holepunches over the container's normal internet egress).

## Run

```sh
cd azula-cli
docker compose up --build -d
```

## Connect

Grab the connect code from the logs and paste it into the app (＋ connect a peer):

```sh
docker compose logs | sed -n '/Paste this code/,/^$/p'
```

Then open the resulting conversation → the **terminal** tab. Type directly in it:
arrow keys recall history, Tab completes, Ctrl-C interrupts.

## Notes

- The node identity is persisted in the `azula-identity` volume, so the connect
  code stays the same across `docker compose restart`.
- Needs outbound internet (iroh relays/discovery + TLS via `ca-certificates`).
- Stop with `docker compose down` (add `-v` to also wipe the identity volume).
