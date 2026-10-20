# Key management

This page lists every key that signs or protects Signalith. For each one it says where
the key is kept, how to replace it on a schedule, and what to do if it leaks.
The project's maintainers use the [project keys](#project-keys). Anyone running
Signalith uses the [keys on your own servers](#keys-on-your-own-servers).

## Project keys

These keys sign what the project publishes. Servers and agents check the signatures
before they install anything.

| Key | Signs | Private key is kept | Public key is trusted from |
| --- | --- | --- | --- |
| Root key | Revocation lists; it can also sign a content bundle or an agent manifest when an online key has to be replaced at once | Offline only, never in GitHub | `internal/keytrust/root.keys` |
| Agent release key | The manifest of agent programs that [agents update to](signalith-agent.md#updates) | `SIGNALITH_AGENT_KEY`, a secret of the `release` environment | `internal/agentproto/release.keys` |
| Content key | [Content update](detections.md#content-updates) bundles | `SIGNALITH_CONTENT_KEY` secret | `internal/content/trusted.keys` |
| GPG release key | `.deb` and `.rpm` packages, `SHA256SUMS`, and the apt and dnf repositories | `SIGNALITH_GPG_PRIVATE_KEY` secret | `signalith-release-key.asc` on each release |
| Sigstore | Release files, container images and the Helm chart | No key to keep: GitHub vouches for the workflow run | The release workflow's identity ([Check a download](install-packages.md#check-a-download)) |

The root key, the agent release key and the content key are all Ed25519 keys. Each
signature file starts with a key ID: the first 12 hex digits of the SHA-256 of the
public key. That ID is how a key is named when it is revoked. Each key signs one kind of
thing only. The root key is the exception, since it has to be able to stand in for a
leaked key.

[Releasing](releasing.md#signing-keys) explains how each online key is made and stored.

### The root key

The root key never touches GitHub or a computer that is online for long. It has two
jobs:

- It signs **revocation lists**. A revocation list names keys that are no longer
  trusted. A list must be signed by a root key, and it can never revoke a root key.
  A leaked online key therefore cannot be used to undo its own revocation.
- It can **stand in for an online key**. Servers and agents trust content bundles and
  agent manifests signed by the root key as well. If an online key leaks, the next
  bundle or agent release can be signed with the root key right away, and users do not
  have to wait for a release that trusts a new online key.

To make it, on a computer you trust, preferably one that is offline:

```sh
signalith content keygen
```

The command prints a private key and a public key. The private key goes in your
password manager, with a second copy on paper or a USB stick in a safe place. Delete it
from the computer afterwards. The public key goes on its own line in
`internal/keytrust/root.keys`. Servers and agents built from that file trust the key
from then on.

### Revocation lists

A revocation list is a small JSON file, `signalith-revoked.json`, with its signature
in `signalith-revoked.json.sig`. Both files are published on the
[content release](https://github.com/jrsamsanchez/Signalith/releases/tag/content), next
to the content bundle. This is how the list reaches servers and agents:

- When a server checks for content updates, it downloads the list from the same place
  as the bundle (the **Content update address**). It keeps the list in `keytrust/`
  in its state folder. If the installed content update was signed with a key the list
  revokes, the server removes it and goes back to the rules built into Signalith.
- A server refuses agent programs whose manifest was signed with a revoked key, so it
  offers no update to its agents.
- When an agent fetches an update, the server hands it the list. The agent and its
  updater each keep their own copy. The updater keeps its copy next to the previous
  agent program, where the agent's sandbox cannot write.
- A copy that has been kept is only replaced by a newer list, one with a later
  `issued` time. A server or agent that has seen a revocation keeps it, even if it is
  later handed an old list or none.
- A server that does not check for content updates, or has no internet access, takes a
  list with `signalith content import-revocations`.
- Each release also lists the revoked key IDs in `internal/keytrust/revoked.keys`. A
  new install refuses those keys before it has seen any list.

Lists only take effect in a build that has a root key in `internal/keytrust/root.keys`.
A build without one cannot check a list, so only `revoked.keys` applies to it.

If you set your own **Content update address**, the mirror must also serve
`signalith-revoked.json` and `signalith-revoked.json.sig` next to the bundle. Otherwise
your servers never see a new list.

A server that has a kept list but cannot read it refuses all content updates and agent
updates until it can. Forgetting a revocation would be worse. Its log and the
Detections page say so. The usual cause is a `keytrust/` folder, or a file in it, that
does not belong to the user Signalith runs as. Fix the owner, for example with
`sudo chown -R signalith: /var/lib/signalith/keytrust`, or import the list again.
A kept list signed by a root key that a later release dropped cannot be read either,
until a list signed by a current root key arrives (see [Root key](#replacing-a-key-on-a-schedule)).

To see which keys a server refuses:

```sh
signalith content revocations
```

## Replacing a key on a schedule

Replace an online key when someone who could read it leaves the project, or when it
is due. The GPG key expires after three years. The other keys do not expire.

**Agent release key and content key.** Neither change breaks existing installs:

1. Make a new key, as [Releasing](releasing.md#signing-keys) says.
2. Add the new public key next to the old one, in `internal/agentproto/release.keys`
   or `internal/content/trusted.keys`, and make a release.
3. Once that release is out, put the new private key in the secret.
4. One or two releases later, remove the old public key. Then add its ID to
   `internal/keytrust/revoked.keys`, with a note saying it was retired.

**GPG release key.** Make the new key before the old one expires, as
[Releasing](releasing.md#gpg-linux-packages-and-checksums) says. Publish the new
fingerprint wherever the old one is published. Leave the old key in the
`signalith-release-key.asc` of one release, so apt and dnf users can move to the new
key. The Package repositories workflow then shows whether installs from the
repositories still work.

**Root key.** Add a second root key to `root.keys` and make a release. Once that
release is in wide use, the old root key can be removed. A root key cannot be revoked
by a list, so a root key is retired by releasing without it.

Before the release that drops the old root key, sign the published revocation list
again with the new root key and publish it. Also add the IDs it revokes to
`internal/keytrust/revoked.keys`. A server keeps refusing content and agent updates
while its kept list is signed by a root key it no longer trusts, until it gets a list
signed by a current one. It takes such a list even when it is no newer.

```sh
export SIGNALITH_ROOT_KEY='<new root private key>'
signalith content revoke -o new/signalith-revoked.json -from signalith-revoked.json -note "signed with the new root key" <a key ID already in the list>
```

`-from` takes a list signed by any root key the build trusts.

## A signing key leaked

Work through these steps in order. They assume the person doing them holds the root
key and can change the repository's secrets.

1. **Stop the key being used.** On GitHub, open **Settings** > **Secrets and
   variables** > **Actions**, and **Settings** > **Environments** > `release`. Delete
   the leaked secret. Check the **Actions** tab for runs you did not start.
2. **Find its key ID.** It is the first word of any `.sig` file the key signed.
   `signalith content sign` also prints it.
3. **Revoke it.** On the offline computer, with the root key:

   ```sh
   export SIGNALITH_ROOT_KEY='<root private key>'
   signalith content revoke -o signalith-revoked.json -note "content key leaked 2026-10-21" <key ID>
   ```

   If a list was published before, download it with its `.sig` and add to it with
   `-from`, so the keys it already revokes stay revoked:

   ```sh
   signalith content revoke -o new/signalith-revoked.json -from signalith-revoked.json -note "..." <key ID>
   ```

   The command refuses to revoke a root key. It warns when this build does not trust
   the root key you used.
4. **Publish the list** on the content release:

   ```sh
   gh release upload content signalith-revoked.json signalith-revoked.json.sig --clobber
   ```

   Servers that check for content updates take the list at their next check. Servers
   with no internet access need the two files copied over, and then:

   ```sh
   sudo -u signalith signalith content import-revocations signalith-revoked.json
   ```

   Run it as the user Signalith runs as, so the service can read the files it keeps.
   Run as root, it refuses a state folder that belongs to another user.

5. **Make a new key.** Put it in the secret, and add its public key to the trusted
   file. Until a release trusts the new key, sign the next bundle or agent release
   with the root key. Add the leaked key's ID to `internal/keytrust/revoked.keys`, and
   remove its public key from the trusted file. Make a release.
6. **Tell users.** Publish a security advisory. Say which key leaked, its ID, the time
   window, and that the revocation is published. Tell users to upgrade, and to run
   `signalith content import-revocations` on servers that have no internet access.

**If the GPG key leaked:** delete the secrets. Then publish the key's revocation
certificate (`gpg --gen-revoke`) with the next release and on the website. Make a new
key and publish its fingerprint. Rebuild the apt and dnf repositories,
and tell users to import the new `signalith-release-key.asc`.

**If the root key leaked:** a list cannot revoke a root key. Make a new root key and
release without the old one in `root.keys`. Before that release, sign the published
list again with the new root key, publish it, and add the IDs it revokes to
`revoked.keys`, as for [replacing the root key](#replacing-a-key-on-a-schedule).
Revoke any online key the attacker could have replaced. Write an advisory telling users to upgrade. Until they do, they trust
what the old root key signs.

**Sigstore** has no key to leak. What an attacker would need is a way to run the
release workflow. The repository protects this with a ruleset on `v*` tags and with
the `release` environment.

## Keys on your own servers

These keys belong to your installation, not to the project.

| Key | What it protects | Replace it with |
| --- | --- | --- |
| Master key | Passwords and API keys stored in settings, and archives | `signalith secrets rotate-master` ([Changing the key](encryption.md#changing-the-key)) |
| Cluster key | Shared settings between servers | **Rotate cluster key** on the Servers page, or `signalith cluster rotate-key` ([Shared settings and the cluster key](servers.md#shared-settings-and-the-cluster-key)) |
| Cluster certificate authority | HTTPS between servers and to OpenSearch | [One certificate authority](servers.md#one-certificate-authority) |
| A server's OpenSearch certificate | One server's access to OpenSearch | [Ending a server's OpenSearch access at once](servers.md#ending-a-servers-opensearch-access-at-once) |
| Agent tokens | An agent sending events | Revoke the token on **Add data** > **Signalith Agent**, or with `signalith tokens` |
| API tokens and passwords | People and scripts signing in | [Users](users.md) |

If one of these leaks, replace it straight away with the command or page in the
table. The old value stops working once it is replaced. Keep a backup of the master key
until every backup made with the old key has expired
([Backing up the key](encryption.md#backing-up-the-key)).
