"""Reusable Rich console display utilities."""

from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.status import Status
from rich.text import Text
from rich.align import Align


class ServerDisplay:
    """Reusable display handler for server UI using Rich."""

    def __init__(self, console: Optional[Console] = None) -> None:
        """
        Initialize display handler.

        Args:
            console: Optional Rich Console instance. Creates new one if not provided.
        """
        self.console = console or Console()

    def print_startup_banner(
        self, host: str, port: int, author: str = "@Adedev-W (github)"
    ) -> None:
        """
        Print server startup banner.

        Args:
            host: Server host address
            port: Server port
            author: Author information
        """
        banner = Text()
        banner.append("Secure TCP Server\n", style="bold cyan")
        banner.append(f"Listening on {host}:{port}\n\n", style="white")
        banner.append("Created by ", style="dim")
        banner.append(author, style="bold magenta")

        self.console.print(
            Panel(
                Align.center(banner),
                border_style="blue",
                title="SERVER STARTED",
                expand=False,
            )
        )

    def print_status(self, message: str, style: str = "bold cyan") -> None:
        """
        Print status message.

        Args:
            message: Status message
            style: Rich style string
        """
        self.console.print(f"[{style}]{message}[/{style}]")

    def print_success(self, message: str) -> None:
        """
        Print success message.

        Args:
            message: Success message
        """
        self.console.print(f"[green]✔ {message}[/green]")

    def print_info(self, message: str) -> None:
        """
        Print info message.

        Args:
            message: Info message
        """
        self.console.print(f"[blue]→ {message}[/blue]")

    def print_warning(self, message: str) -> None:
        """
        Print warning message.

        Args:
            message: Warning message
        """
        self.console.print(f"[yellow]{message}[/yellow]")

    def print_error(self, message: str) -> None:
        """
        Print error message.

        Args:
            message: Error message
        """
        self.console.print(f"[bold red]✖ {message}[/bold red]")

    def print_panel(
        self, content: str, title: str = "", border_style: str = "cyan"
    ) -> None:
        """
        Print content in a panel.

        Args:
            content: Panel content
            title: Panel title
            border_style: Border style
        """
        self.console.print(
            Panel.fit(content, title=title, border_style=border_style)
        )

    def print_text(self, prefix: str, content: str, prefix_style: str = "cyan", content_style: str = "white") -> None:
        """
        Print formatted text with prefix.

        Args:
            prefix: Text prefix
            content: Text content
            prefix_style: Prefix style
            content_style: Content style
        """
        text = Text(prefix, style=prefix_style) + Text(content, style=content_style)
        self.console.print(text)

    def with_status(self, message: str):
        """
        Context manager for status spinner.

        Args:
            message: Status message

        Returns:
            Status context manager
        """
        return Status(f"[bold cyan]{message}[/bold cyan]", console=self.console)
