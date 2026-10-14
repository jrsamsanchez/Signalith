#!/bin/sh
# Builds Signalith's signed apt and dnf package repositories from .deb and
# .rpm packages.
#
#   deploy/repos/build.sh PKGDIR OUTDIR URL
#
# PKGDIR holds the packages, OUTDIR gets apt/ and rpm/, and URL is where
# OUTDIR will be served (https://signalith.io for the published repos). The
# signing key is the secret key in gpg's keyring (GNUPGHOME); set
# SIGNALITH_GPG_PASSPHRASE when it has a passphrase. Needs gpg,
# apt-ftparchive (apt-utils), createrepo_c and rpmsign.
#
# apt checks the signed Release file; dnf checks the signed repository
# metadata and each package's own signature, so .rpm packages that are not
# signed yet (releases made before the key existed) are signed here.
set -eu
pkgs=${1:?usage: build.sh PKGDIR OUTDIR URL}
out=${2:?usage: build.sh PKGDIR OUTDIR URL}
url=${3:?usage: build.sh PKGDIR OUTDIR URL}
url=${url%/}
pkgs=$(cd "$pkgs" && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

key=$(gpg --batch --list-secret-keys --with-colons | awk -F: '$1 == "fpr" { print $10; exit }')
[ -n "$key" ] || { echo "no secret key in the gpg keyring"; exit 1; }
printf '%s' "${SIGNALITH_GPG_PASSPHRASE:-}" > "$work/passphrase"
sign() {
  gpg --batch --yes --pinentry-mode loopback --passphrase-file "$work/passphrase" --local-user "$key" "$@"
}

# apt: https://signalith.io/apt stable main
apt=$out/apt
mkdir -p "$apt/pool/main"
cp "$pkgs"/*.deb "$apt/pool/main/"
for arch in amd64 arm64; do
  dir=$apt/dists/stable/main/binary-$arch
  mkdir -p "$dir"
  (cd "$apt" && apt-ftparchive --arch "$arch" packages pool/main) > "$dir/Packages"
  gzip -9nk "$dir/Packages"
done
(cd "$apt/dists/stable" && apt-ftparchive \
  -o APT::FTPArchive::Release::Origin=Signalith \
  -o APT::FTPArchive::Release::Label=Signalith \
  -o APT::FTPArchive::Release::Suite=stable \
  -o APT::FTPArchive::Release::Codename=stable \
  -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
  -o APT::FTPArchive::Release::Components=main \
  -o APT::FTPArchive::Release::Description="Signalith packages" \
  release . > "$work/Release")
mv "$work/Release" "$apt/dists/stable/Release"
sign --clearsign -o "$apt/dists/stable/InRelease" "$apt/dists/stable/Release"
sign --armor --detach-sign -o "$apt/dists/stable/Release.gpg" "$apt/dists/stable/Release"
gpg --batch --armor --export "$key" > "$apt/signalith.asc"

# dnf, yum and zypper: https://signalith.io/rpm
rpm=$out/rpm
mkdir -p "$rpm/packages"
cp "$pkgs"/*.rpm "$rpm/packages/"
cp "$apt/signalith.asc" "$rpm/signalith.asc"
for f in "$rpm"/packages/*.rpm; do
  if [ "$(rpm -qp --nosignature --qf '%{RSAHEADER:pgpsig}' "$f" 2>/dev/null)" = "(none)" ]; then
    rpmsign --define "_gpg_name $key" \
      --define "_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback --passphrase-file $work/passphrase" \
      --addsign "$f" >/dev/null
  fi
done
createrepo_c --quiet "$rpm"
sign --armor --detach-sign -o "$rpm/repodata/repomd.xml.asc" "$rpm/repodata/repomd.xml"
cat > "$rpm/signalith.repo" <<REPO
[signalith]
name=Signalith
baseurl=$url/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$url/rpm/signalith.asc
REPO

echo "Built the apt and rpm repositories in $out, signed with $key."
