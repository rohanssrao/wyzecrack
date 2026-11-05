"""Still frames for browsers that can't decode H.264 themselves.

The page plays the live view with WebCodecs, which needs the browser's own
H.264 decoder. Builds without one (Firefox and WebKit without proprietary
codecs, for example) would show a black stage. For those, the page asks
for this fallback: the stream is decoded here with PyAV and sent as JPEG
frames, at most MAX_FPS a second and at most WIDTH pixels wide.

Decoding runs in its own thread, so the camera session's receive loop never
waits for it. When the thread falls behind, it drops frames until the next
key frame (every P-frame depends on the one before it).
"""
import io
import queue
import threading
import time

MAX_FPS = 10
WIDTH = 1280
QUALITY = 75


class JpegFeed:
    """feed(frame) with each live.Frame; on_jpeg(t, jpeg bytes) gets the
    pictures. close() stops the thread."""

    def __init__(self, on_jpeg):
        self.on_jpeg = on_jpeg
        self.q = queue.Queue(maxsize=60)
        self.need_key = True
        self._stop = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def feed(self, frame):
        if self.need_key and not frame.key:
            return
        try:
            self.q.put_nowait(frame)
            self.need_key = False
        except queue.Full:
            # behind: start over at the next key frame
            self.need_key = True
            with self.q.mutex:
                self.q.queue.clear()
            self.q.put_nowait(None)          # tells the decoder to reset

    def close(self):
        self._stop = True
        try:
            self.q.put_nowait(None)
        except queue.Full:
            pass

    def _run(self):
        import av
        codec = av.CodecContext.create("h264", "r")
        last = 0.0
        while not self._stop:
            f = self.q.get()
            if f is None:
                codec = av.CodecContext.create("h264", "r")
                continue
            try:
                pictures = codec.decode(av.Packet(f.data))
            except av.error.FFmpegError:
                continue
            for pic in pictures:
                now = time.monotonic()
                if now - last < 1 / MAX_FPS:
                    continue
                last = now
                w = min(WIDTH, pic.width)
                h = round(pic.height * w / pic.width) // 2 * 2
                img = pic.to_image(width=w, height=h)
                buf = io.BytesIO()
                img.save(buf, "JPEG", quality=QUALITY)
                self.on_jpeg(f.t, buf.getvalue())
