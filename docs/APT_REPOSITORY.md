# APT Repository Guide

## Build the Debian Package

Run these commands on a Debian or Ubuntu builder:

```bash
sudo apt update
sudo apt install -y build-essential debhelper dh-python dpkg-dev gnupg apt-utils
cd /path/to/aegis
./scripts/build_deb.sh
```

The generated `.deb` file is written to the parent directory of the repository.

## Repository Layout

This example creates a simple `stable` repository served over HTTPS:

```bash
mkdir -p repo/pool/main
mkdir -p repo/dists/stable/main/binary-amd64
cp ../aegis_*.deb repo/pool/main/
cd repo
dpkg-scanpackages --multiversion pool > dists/stable/main/binary-amd64/Packages
gzip -kf dists/stable/main/binary-amd64/Packages
```

## Generate Release Metadata

```bash
cat > apt-ftparchive.conf <<'EOF'
APT::FTPArchive::Release {
  Origin "AEGIS";
  Label "AEGIS";
  Suite "stable";
  Codename "stable";
  Architectures "amd64";
  Components "main";
  Description "AEGIS APT Repository";
};
EOF

apt-ftparchive -c apt-ftparchive.conf release dists/stable > dists/stable/Release
gpg --default-key YOUR_KEY_ID --armor --detach-sign -o dists/stable/Release.gpg dists/stable/Release
gpg --default-key YOUR_KEY_ID --clearsign -o dists/stable/InRelease dists/stable/Release
```

Publish the `repo/` directory through any HTTPS web server.

## Client Setup

```bash
curl -fsSL https://repo.example.com/public.key | sudo gpg --dearmor -o /usr/share/keyrings/aegis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/aegis-archive-keyring.gpg] https://repo.example.com stable main" | sudo tee /etc/apt/sources.list.d/aegis.list >/dev/null
sudo apt update
sudo apt install aegis
```

The package installs the service unit but does not enable or start it automatically.

## After Installation

```bash
sudo editor /etc/aegis/config.yaml
sudo systemctl enable --now aegis
sudo systemctl status aegis
```

If you want to manage multiple distributions or multiple package versions, switch from the manual layout above to `reprepro` or `aptly`.
