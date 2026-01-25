"""Transport layer for Secure TCP Client."""

import socket
from typing import Optional, Tuple, Callable

from Client.exceptions import TransportError


class TCPClientTransport:
    """TCP client transport layer."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8436,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Initialize TCP client transport.

        Args:
            host: Server host address
            port: Server port
            logger: Optional logging function
        """
        self.host = host
        self.port = port
        self._log = logger or (lambda msg: None)
        self._socket: Optional[socket.socket] = None
        self._connected = False

    def connect(self) -> None:
        """
        Connect to server.

        Raises:
            TransportError: If connection fails
        """
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect((self.host, self.port))
            self._connected = True
            self._log(f"Connected to {self.host}:{self.port}")
        except OSError as e:
            self._connected = False
            raise TransportError(f"Failed to connect to server: {e}") from e

    def send(self, data: bytes) -> None:
        """
        Send data to server.

        Args:
            data: Data to send

        Raises:
            TransportError: If send fails
        """
        if not self._connected or self._socket is None:
            raise TransportError("Not connected to server")

        try:
            self._socket.sendall(data)
        except OSError as e:
            raise TransportError(f"Failed to send data: {e}") from e

    def receive(self, buffer_size: int = 4096) -> bytes:
        """
        Receive data from server.

        Args:
            buffer_size: Maximum bytes to receive

        Returns:
            Received data

        Raises:
            TransportError: If receive fails
        """
        if not self._connected or self._socket is None:
            raise TransportError("Not connected to server")

        try:
            data = self._socket.recv(buffer_size)
            if not data:
                raise TransportError("Connection closed by server")
            return data
        except OSError as e:
            raise TransportError(f"Failed to receive data: {e}") from e

    def close(self) -> None:
        """Close connection."""
        if self._socket:
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                self._socket.close()
                self._socket = None
                self._connected = False
                self._log("Connection closed")

    def is_connected(self) -> bool:
        """Check if connected to server."""
        return self._connected

    def get_socket(self) -> socket.socket:
        """
        Get underlying socket (for direct access if needed).

        Returns:
            Socket instance

        Raises:
            TransportError: If not connected
        """
        if not self._connected or self._socket is None:
            raise TransportError("Not connected to server")
        return self._socket
