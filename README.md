# wyzecrack

Watch and record Wyze cameras on a local network without authentication.

wyzecrack exploits unpatched Wyze cam (v2 and v3) firmwares that still trust eMudhra intermediate CAs. It MITMs the camera to sniff its master secret, asks the Wyze cloud for its UID, and connects directly to it to stream its feed.

## Get started

You need a Linux computer on the same network as the cameras, with `sudo`,
`iptables` and [uv](https://docs.astral.sh/uv/). Install wyzecrack and
start it:

```
uv tool install git+https://github.com/rohanssrao/wyzecrack
wyzecrack
```

wyzecrack will open in your browser. Pick a camera to watch it live.

Watching a camera for the first time takes a few minutes as wyzecrack routes that camera through your computer with ARP spoofing and reads the
camera's key (ENR) from what it sends to Wyze. The camera reconnects to
Wyze a few times meanwhile, and its network goes back to normal
afterwards. From then on, live views start within seconds.

Every live view is recorded. When you press **Stop**, the recording
appears under the camera's live view. The files are in a `captures`
folder in the directory you started wyzecrack from. To keep a camera's
motion clips too, turn on **Save this camera's motion clips** on its page.
Clips are copied while wyzecrack is running.

Tested with the Wyze Cam v3 (firmware 4.36.16 and 4.36.17) and the Wyze
Cam v2 (4.9.9).

## More

- [Guide](docs/guide.md): commands for scripts, options, files and
  troubleshooting
- [How it works](docs/how-it-works.md)

## Credits

The camera protocol code follows the TUTK and Wyze support in
[go2rtc](https://github.com/AlexxIT/go2rtc) (MIT License, see
[NOTICE](NOTICE)).

## License

wyzecrack is licensed under the [GNU Affero General Public License v3.0
or later](LICENSE).
