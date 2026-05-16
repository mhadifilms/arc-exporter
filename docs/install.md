# Install

`arc-exporter` is a single Python package that works on macOS, Windows, and Linux.

## macOS

### Homebrew (recommended)

```bash
brew install mhadifilms/tap/arc-exporter
```

### pipx (any Python install)

```bash
pipx install arc-exporter
```

### Double-click launcher

If you don't normally use the terminal, download
[`arc-exporter.command`](https://github.com/mhadifilms/arc-exporter/releases/latest/download/arc-exporter.command),
put it on your Desktop, and double-click. The first run installs the CLI for you.

## Windows

### winget

```powershell
winget install arc-exporter
```

### Single-file `.exe`

Download `arc-exporter-windows-x86_64.exe` from the
[Releases page](https://github.com/mhadifilms/arc-exporter/releases/latest) and
drop it anywhere on your `PATH`.

### `.msi` installer

For organisations that want a proper installer, download the `.msi` from the same
Releases page.

## Linux

### Debian / Ubuntu

```bash
curl -fsSL https://github.com/mhadifilms/arc-exporter/releases/latest/download/arc-exporter.deb -o /tmp/arc.deb
sudo apt-get install -y /tmp/arc.deb
```

### Fedora / RHEL

```bash
sudo dnf install -y \
  https://github.com/mhadifilms/arc-exporter/releases/latest/download/arc-exporter.rpm
```

### AppImage / single-file binary

Download `arc-exporter-linux-x86_64` from the
[Releases page](https://github.com/mhadifilms/arc-exporter/releases/latest),
`chmod +x` it, and run it from anywhere.

## One-liner

The script at [`packaging/install.sh`](https://github.com/mhadifilms/arc-exporter/blob/main/packaging/install.sh)
detects your OS and chooses the right installer above. You can run it directly:

```bash
curl -fsSL https://arc-exporter.dev/install.sh | bash
```

## Verifying the install

```bash
arc-exporter --version
arc-exporter doctor
```
