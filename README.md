# wyzecrack

Watch and record your Wyze cameras in your browser, straight from the
cameras on your home network.

Only use it with cameras you own or are allowed to test.

## Get started

You need a Linux computer on the same network as the cameras, with `sudo`,
`iptables` and [uv](https://docs.astral.sh/uv/). Install wyzecrack and
start it:

```
uv tool install git+https://github.com/rohanssrao/wyzecrack
wyzecrack
```

wyzecrack asks for your sudo password and opens a page in your browser.
Pick a camera to watch it live: in 1080p in Chrome, Edge or Brave, as
still frames in other browsers.

Picking a camera for the first time takes a minute or two, sometimes up
to four. wyzecrack routes that camera through your computer and reads the
camera's key from what the camera sends to Wyze. The camera reconnects to
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
