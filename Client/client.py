"""Main Secure TCP Client implementation."""

import logging
from typing import Optional, Callable

from Client.crypto import AESGCMHandler
from Client.protocol import HandshakeHandler, MessageHandler
from Client.transport import TCPClientTransport
from Client.display import ClientDisplay
from Client.exceptions import (
    SecureTCPClientError,
    HandshakeError,
    TransportError,
)


class SecureTCPClient:
    """
    Secure TCP Client using:
    - RSA for key exchange
    - AES-GCM for encrypted communication

    Architecture:
    - Transport layer: Handles socket operations
    - Crypto layer: Manages encryption and key exchange
    - Protocol layer: Handles handshake and message exchange
    - Display layer: Optional UI display (can be replaced with logging)
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8436,
        logger: Optional[logging.Logger] = None,
        use_display: bool = True,
    ) -> None:
        """
        Initialize Secure TCP Client.

        Args:
            host: Server host address
            port: Server port
            logger: Optional logger instance (uses default if not provided)
            use_display: Whether to use Rich display (default: True)
        """
        # Initialize logger first
        self._logger = logger or self._get_default_logger()
        self._display = ClientDisplay() if use_display else None

        # Initialize components
        self._transport = TCPClientTransport(host=host, port=port, logger=self._log)
        self._aes_handler: Optional[AESGCMHandler] = None
        self._message_handler: Optional[MessageHandler] = None
        self._connected = False

    def _get_default_logger(self) -> logging.Logger:
        """Get default logger instance."""
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def _log(self, message: str, level: str = "info") -> None:
        """Internal logging helper."""
        log_method = getattr(self._logger, level.lower(), self._logger.info)
        log_method(message)

        # Also display if enabled
        if self._display:
            if level == "info":
                self._display.print_info(message)
            elif level == "warning":
                self._display.print_warning(message)
            elif level == "error":
                self._display.print_error(message)
            elif level == "success":
                self._display.print_success(message)

    def connect(self) -> None:
        """
        Connect to server and perform handshake.

        Raises:
            SecureTCPClientError: If connection or handshake fails
        """
        try:
            # Connect to server
            self._transport.connect()

            if self._display:
                self._display.print_connection_banner(
                    self._transport.host, self._transport.port
                )

            self._log(f"Connected to {self._transport.host}:{self._transport.port}")

            # Perform handshake
            handshake_handler = HandshakeHandler(
                self._transport,
                logger=self._log,
            )

            if self._display:
                self._display.print_panel("Starting secure handshake", title="Handshake")

            self._aes_handler = handshake_handler.perform_handshake()

            if self._display:
                self._display.print_panel(
                    "Encrypted channel active", title="AES-GCM", border_style="green"
                )

            # Initialize message handler
            self._message_handler = MessageHandler(
                self._aes_handler,
                self._transport,
                logger=self._log,
            )

            if self._display:
                def display_log(msg: str):
                    if "Sent:" in msg:
                        content = msg.replace("Sent: ", "")
                        self._display.print_text("Client → ", content)
                    elif "Received:" in msg:
                        content = msg.replace("Received: ", "")
                        self._display.print_text("Server → ", content, prefix_style="green")
                    else:
                        self._log(msg)

                self._message_handler._log = display_log

            self._connected = True
            self._log("Secure connection established", "success")

        except (HandshakeError, TransportError) as e:
            self._log(f"Connection failed: {e}", "error")
            self.disconnect()
            raise SecureTCPClientError(f"Failed to connect: {e}") from e
        except Exception as e:
            self.disconnect()
            raise SecureTCPClientError(f"Unexpected error: {e}") from e

    def send_message(self, message: bytes) -> bytes:
        """
        Send encrypted message and receive response.

        Args:
            message: Message to send

        Returns:
            Decrypted response from server

        Raises:
            SecureTCPClientError: If not connected or message exchange fails
        """
        if not self._connected or self._message_handler is None:
            raise SecureTCPClientError(
                "Not connected to server. Call connect() first."
            )

        try:
            return self._message_handler.send_message(message)
        except Exception as e:
            raise SecureTCPClientError(f"Message exchange failed: {e}") from e

    def disconnect(self) -> None:
        """Disconnect from server gracefully."""
        self._connected = False
        self._transport.close()

        if self._display:
            self._display.print_info("Disconnected from server")
        else:
            self._log("Disconnected from server", "info")

    def is_connected(self) -> bool:
        """Check if connected to server."""
        return self._connected and self._transport.is_connected()
