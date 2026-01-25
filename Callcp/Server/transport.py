"""Transport layer for Secure TCP Server."""

import socket
from typing import Optional, Tuple, Callable

from Server.exceptions import TransportError


class TCPServerTransport:
    """TCP server transport layer."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8436,
        backlog: int = 1,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Initialize TCP server transport.

        Args:
            host: Server host address
            port: Server port
            backlog: Maximum number of queued connections
            logger: Optional logging function
        """
        self.host = host
        self.port = port
        self.backlog = backlog
        self._log = logger or (lambda msg: None)
        self._server_socket: Optional[socket.socket] = None
        self._running = False

    def bind(self) -> None:
        """
        Bind server socket to address.

        Raises:
            TransportError: If binding fails
        """
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.host, self.port))
            self._server_socket.listen(self.backlog)
            self._log(f"Server bound to {self.host}:{self.port}")
        except OSError as e:
            raise TransportError(f"Failed to bind server: {e}") from e

    def accept(self) -> Tuple[socket.socket, Tuple[str, int]]:
        """
        Accept a client connection.

        Returns:
            Tuple of (client_socket, client_address)

        Raises:
            TransportError: If accept fails
        """
        if self._server_socket is None:
            raise TransportError("Server socket not bound. Call bind() first.")

        try:
            conn, addr = self._server_socket.accept()
            self._log(f"Client connected: {addr}")
            return conn, addr
        except OSError as e:
            raise TransportError(f"Failed to accept connection: {e}") from e

    def close(self) -> None:
        """Close server socket."""
        if self._server_socket:
            try:
                self._server_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                self._server_socket.close()
                self._server_socket = None
                self._log("Server socket closed")

    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running

    def set_running(self, running: bool) -> None:
        """Set running state."""
        self._running = running



