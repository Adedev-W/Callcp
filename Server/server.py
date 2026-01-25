"""Main Secure TCP Server implementation."""

import logging
from typing import Optional, Callable

from Server.crypto import KeyManager, AESGCMHandler
from Server.protocol import HandshakeHandler, MessageHandler
from Server.transport import TCPServerTransport
from Server.display import ServerDisplay
from Server.exceptions import (
    SecureTCPServerError,
    KeyManagementError,
    HandshakeError,
    TransportError,
)


class SecureTCPServer:
    """
    Secure TCP Server using:
    - RSA for key exchange
    - AES-GCM for encrypted communication

    Architecture:
    - Transport layer: Handles socket operations
    - Crypto layer: Manages keys and encryption
    - Protocol layer: Handles handshake and message exchange
    - Display layer: Optional UI display (can be replaced with logging)
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8436,
        private_key_path: str = "server_private.pem",
        public_key_path: str = "server_public.pem",
        message_callback: Optional[Callable[[bytes], bytes]] = None,
        logger: Optional[logging.Logger] = None,
        use_display: bool = True,
    ) -> None:
        """
        Initialize Secure TCP Server.

        Args:
            host: Server host address
            port: Server port
            private_key_path: Path to private key file
            public_key_path: Path to public key file
            message_callback: Optional callback for processing messages
            logger: Optional logger instance (uses default if not provided)
            use_display: Whether to use Rich display (default: True)
        """
        # Initialize logger first
        self._logger = logger or self._get_default_logger()
        self._display = ServerDisplay() if use_display else None

        # Initialize components
        self._transport = TCPServerTransport(host=host, port=port, logger=self._log)
        self._key_manager = KeyManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
        )

        # State
        self._private_key = None
        self._public_key_bytes = None
        self._message_callback = message_callback

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

    def initialize(self) -> None:
        """
        Initialize server (load/generate keys).

        This method must be called before start() to separate
        initialization from construction (no side effects in __init__).

        Raises:
            KeyManagementError: If key initialization fails
        """
        try:
            if self._display:
                with self._display.with_status("Loading RSA keys..."):
                    self._private_key, self._public_key_bytes = (
                        self._key_manager.load_or_generate_keys()
                    )
                self._display.print_success("RSA key pair loaded")
            else:
                self._log("Loading RSA keys...")
                self._private_key, self._public_key_bytes = (
                    self._key_manager.load_or_generate_keys()
                )
                self._log("RSA key pair loaded", "success")

        except KeyManagementError:
            raise
        except Exception as e:
            raise KeyManagementError(f"Initialization failed: {e}") from e

    def start(self) -> None:
        """
        Start the server.

        Raises:
            SecureTCPServerError: If server fails to start
        """
        if self._private_key is None or self._public_key_bytes is None:
            raise SecureTCPServerError(
                "Server not initialized. Call initialize() first."
            )

        try:
            self._transport.bind()
            self._transport.set_running(True)

            if self._display:
                self._display.print_startup_banner(
                    self._transport.host, self._transport.port
                )

            self._log(f"Server started on {self._transport.host}:{self._transport.port}")

            while self._transport.is_running():
                conn, addr = self._transport.accept()

                try:
                    with conn:
                        self._handle_client(conn, addr)
                except (HandshakeError, TransportError) as e:
                    self._log(f"Client connection error: {e}", "error")
                except Exception as e:
                    self._log(f"Unexpected error handling client: {e}", "error")

        except KeyboardInterrupt:
            self._log("Received shutdown signal", "warning")
            self.shutdown()
        except TransportError:
            raise
        except Exception as e:
            raise SecureTCPServerError(f"Server error: {e}") from e

    def _handle_client(self, conn, addr) -> None:
        """
        Handle a client connection.

        Args:
            conn: Client socket
            addr: Client address
        """
        # Perform handshake
        handshake_handler = HandshakeHandler(
            self._private_key,
            self._public_key_bytes,
            logger=self._log,
        )

        if self._display:
            self._display.print_panel("Starting secure handshake", title="Handshake")

        aes_handler = handshake_handler.perform_handshake(conn)

        if self._display:
            self._display.print_panel("Encrypted channel active", title="AES-GCM", border_style="green")

        # Handle encrypted messages
        message_handler = MessageHandler(
            aes_handler,
            message_callback=self._message_callback,
            logger=self._log,
        )

        if self._display:
            def display_log(msg: str):
                if "Received:" in msg:
                    content = msg.replace("Received: ", "")
                    self._display.print_text("Client → ", content)
                else:
                    self._log(msg)

            message_handler._log = display_log

        message_handler.handle_connection(conn)

    def shutdown(self) -> None:
        """Shutdown the server gracefully."""
        self._transport.set_running(False)
        self._transport.close()

        if self._display:
            self._display.print_error("Server shutting down gracefully")
        else:
            self._log("Server shutting down gracefully", "info")
