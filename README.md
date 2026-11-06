# wyzecrack

Watch and record your Wyze cameras in your browser, straight from the
cameras on your home network.

Only use it with cameras you own or are allowed to test.

## Get started

You need a Linux computer on the same network as the cameras, with `sudo`
and [uv](https://docs.astral.sh/uv/). From this folder:

```
uv tool install .
wyzecrack
```

wyzecrack asks for your password and opens a page in your browser. Pick a
camera to watch it live in 1080p.

The first time you pick a camera takes two to four minutes. wyzecrack
routes that camera through your computer and reads the camera's key from
what it sends to Wyze. The camera reconnects to Wyze a few times
meanwhile, and its network goes back to normal afterwards. From then on,
live views start within seconds.

Press **Stop** to keep the recording. Recordings are listed under the
camera's live view and saved in a `captures` folder where you started
wyzecrack. To keep a camera's motion clips too, turn on **Save this
camera's motion clips** there; they're saved while the page is open.

Tested with the Wyze Cam v3 (firmware 4.36.16 and 4.36.17) and the Wyze
Cam v2 (4.9.9).

## More

- [Guide](docs/guide.md): commands for scripts, options, files and
  troubleshooting
- [How it works](docs/how-it-works.md)
