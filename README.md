# VibeDNS

Ask several DNS servers about a name, side by side with what Windows itself answers.

Type a name, pick a record type and press Query. Every resolver gets a column: Windows first
(through the same DNS client your apps use, so the hosts file, NRPT rules and Windows' own DoH
count), then each network adapter's DNS servers, then Cloudflare, Google and Quad9, and any
servers you add yourself, over UDP, TCP, DNS over TLS or DNS over HTTPS. When the answers differ,
the column says so and, when it can be known, why: a hosts file line, an NRPT rule, a search
suffix. Trace walks the delegation from the root servers down, like `dig +trace`. Think of it as
dig for Windows, with a window.

It is written in Rust with a native Slint interface, no browser engine inside, and needs no admin
rights.

## What it doesn't do

It doesn't change your DNS settings, edit records, run a DNS server or validate DNSSEC itself
(the AD flag is shown as the resolver's own claim). The one thing it changes on the PC is the
Windows DNS cache, and only when you press Flush.

## What it connects to

Only the DNS servers in its columns (yours, and Cloudflare, Google and Quad9 unless you turn them
off), the servers a trace goes through, and getvibeware.com when you press About's "Check this
install". It has no updater and sends nothing else.

## What it keeps

Settings in `%APPDATA%\com.tedkj.vibedns` and the last 50 lookups in
`%LOCALAPPDATA%\com.tedkj.vibedns`. Uninstalling leaves both, so a reinstall finds them where
they were; delete the folders if you want them gone.

## Download

Get the installer from [Releases](https://github.com/tedkj/vibedns/releases) or
[getvibeware.com](https://getvibeware.com). It installs for your user only, without admin rights.
The installer, VibeDNS.exe and its uninstaller are code signed by "Open Source Developer Ted
Kenneth Johansen" (right-click, Properties, Digital Signatures). The certificate is new, so
Windows SmartScreen may still warn before it runs. You can also compare the installer's SHA-256
with the one on the release page:

```powershell
Get-FileHash .\VibeDNS_0.1.0-preview_x64-setup.exe
```

VibeDNS doesn't update itself: get a new version from Releases.

## Building from source

You need a current stable Rust toolchain on Windows (the MSVC target).

```sh
cargo build --release --locked
```

The app is then at `target\release\vibedns.exe`. `vendor/` holds Slint's `i-slint-core` 1.18.1
with one small repaint fix; `vendor/README.md` says what changed and why.

### Building the installer

`installer\build.ps1` builds the app and its installer,
`target\release\bundle\VibeDNS_<version>_x64-setup.exe`. It needs the official NSIS 3.13:
download `nsis-3.13.zip` from SourceForge (SHA-256
`ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8`) and unpack it to
`_tools\nsis-3.13` in the folder that holds this repository (`..\_tools\nsis-3.13`). The script
checks that whole folder against a pinned hash before it runs anything from it.
`installer\notices.ps1` writes `THIRD-PARTY-NOTICES.txt` for each build (every crate the app
links, with its licence text), and the installer puts it and `LICENSE` next to the app.

## License

[AGPL-3.0](LICENSE) (AGPL-3.0-only). Use it, change it, share it. If you hand out a changed
version, or run one as a service for other people, you share your changes under the same license.
Slint is used under its GPLv3 option.

Made in Norway by Ted K. Johansen.
