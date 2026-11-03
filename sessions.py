"""TCP sessions with one foreground reader of terminal input."""
import io
import queue
import select
import socket
import sys
import threading


class Session:
    def __init__(self, ident, sock, peer, buffer_limit=1024 * 1024):
        self.id = ident
        self.sock = sock
        self.peer = peer
        self.buffer_limit = buffer_limit
        self._buffer = bytearray()
        self._dropped = 0
        self._lock = threading.Lock()
        self.closed = threading.Event()
        self.sock.settimeout(0.2)
        self._thread = threading.Thread(target=self._receive, daemon=True)
        self._thread.start()

    def _receive(self):
        try:
            while not self.closed.is_set():
                try:
                    data = self.sock.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                with self._lock:
                    self._buffer.extend(data)
                    excess = max(0, len(self._buffer) - self.buffer_limit)
                    if excess:
                        del self._buffer[:excess]
                        self._dropped += excess
        except OSError:
            pass
        finally:
            self.closed.set()
            self.sock.close()

    def read_pending(self):
        with self._lock:
            data, dropped = bytes(self._buffer), self._dropped
            self._buffer.clear()
            self._dropped = 0
        return data, dropped

    def _write_pending(self, output):
        data, dropped = self.read_pending()
        if dropped:
            output.write(f"\n[!] Buffer discarded {dropped} old bytes.\n")
        if data:
            output.flush()
            if hasattr(output, "buffer"):
                output.buffer.write(data)
                output.buffer.flush()
            else:
                output.write(data.decode("utf-8", errors="replace"))
        output.flush()

    def close(self):
        self.closed.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout=1)

    def interact(self, input_stream=None, output_stream=None):
        """Detach on background, EOF or Ctrl+C; only close() ends a session."""
        source = input_stream if input_stream is not None else sys.stdin
        output = output_stream if output_stream is not None else sys.stdout
        output.write(
            f"\n[+] Session {self.id} ({self.peer})\n"
            "Type 'background' or press Ctrl+C to detach.\n\n"
        )
        output.flush()
        try:
            while True:
                self._write_pending(output)
                if self.closed.is_set():
                    # EOF can arrive between draining the buffer and this check.
                    self._write_pending(output)
                    output.write("\n[*] Connection closed.\n")
                    break
                # StringIO is useful for embedded callers and local tests.
                if isinstance(source, io.StringIO):
                    ready = [source]
                else:
                    ready, _, _ = select.select([source], [], [], 0.1)
                if not ready:
                    continue
                line = source.readline()
                if not line or line.strip().lower() in ("background", "bg"):
                    break
                self.sock.sendall(line.encode("utf-8"))
        except KeyboardInterrupt:
            output.write("\n")
        except (OSError, ValueError) as exc:
            output.write(f"\n[!] Session I/O: {exc}\n")
        finally:
            output.write(f"\n[*] Back to console; session {self.id}: "
                         f"{'closed' if self.closed.is_set() else 'open'}.\n")
            output.flush()


class Listener:
    def __init__(self, host="0.0.0.0", port=4444, manager=None, ident=0):
        self.host, self.port = host, port
        self.manager = manager if manager is not None else SessionManager()
        self.id = ident
        self.stopped = threading.Event()
        self.accepted = queue.Queue()
        self.sock = None
        self._thread = None

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(8)
            sock.settimeout(0.2)
        except BaseException:
            sock.close()
            raise
        self.sock = sock
        self.port = sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self):
        try:
            while not self.stopped.is_set():
                try:
                    sock, address = self.sock.accept()
                except socket.timeout:
                    continue
                if self.stopped.is_set():
                    sock.close()
                    break
                session = self.manager.add(sock, f"{address[0]}:{address[1]}")
                self.accepted.put(session)
        except OSError as exc:
            if not self.stopped.is_set():
                self.manager.notices.put(f"Listener {self.id}: {exc}")
        finally:
            self.stopped.set()
            self.sock.close()

    def wait(self, timeout=None):
        return self.accepted.get(timeout=timeout)

    def close(self):
        self.stopped.set()
        if self.sock is not None:
            self.sock.close()
        if self._thread is not None:
            self._thread.join(timeout=1)


class SessionManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions = {}
        self._listeners = {}
        self._next_session = 1
        self._next_listener = 1
        self.notices = queue.Queue()

    def add(self, sock, peer="connected peer"):
        with self._lock:
            ident = self._next_session
            self._next_session += 1
            session = Session(ident, sock, peer)
            self._sessions[ident] = session
        self.notices.put(f"Session {ident} from {peer}; sessions -i {ident}")
        return session

    def get(self, ident):
        with self._lock:
            if ident not in self._sessions:
                raise ValueError(f"No session {ident}")
            return self._sessions[ident]

    def sessions(self):
        with self._lock:
            return list(self._sessions.values())

    def listeners(self):
        with self._lock:
            return list(self._listeners.values())

    def listen(self, host="0.0.0.0", port=4444):
        with self._lock:
            ident = self._next_listener
            self._next_listener += 1
            listener = Listener(host, port, self, ident).start()
            self._listeners[ident] = listener
        return listener

    def stop_listener(self, ident):
        with self._lock:
            if ident not in self._listeners:
                raise ValueError(f"No listener {ident}")
            listener = self._listeners.pop(ident)
        listener.close()

    def close(self):
        # Stop accepting before taking the final snapshot of sessions.
        for listener in self.listeners():
            listener.close()
        for session in self.sessions():
            session.close()
        with self._lock:
            self._listeners.clear()


def interactive_shell(sock, banner="[+] Shell opened", manager=None):
    """Pass the module's manager to keep detached sessions in the console."""
    manager = manager if manager is not None else SessionManager()
    session = manager.add(sock)
    print(banner)
    session.interact()
    return session
