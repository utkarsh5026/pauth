"""
Interactive OAuth Playground for testing OAuth flows.

This module provides an interactive terminal UI for testing OAuth 2.0 flows
in real-time with beautiful visualizations.
"""

import json
import time
from datetime import datetime
from typing import Optional

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Confirm, Prompt
    from rich.syntax import Syntax
    from rich.table import Table
except ImportError:
    raise ImportError(
        "Rich is required for OAuth Playground. " "Install it with: pip install rich"
    )

try:
    import qrcode
except ImportError:
    qrcode = None

from src.client import OAuth2Client
from src.models import OAuthSession, Providers, TokenResponse


class OAuthPlayground:
    """
    Interactive OAuth 2.0 testing playground.

    Features:
    - Step-by-step flow visualization
    - Token inspection with countdown
    - QR code generation
    - Request/response viewing
    - Export flows
    """

    def __init__(self):
        """Initialize the playground."""
        self.console = Console()
        self.client: Optional[OAuth2Client] = None
        self.tokens: Optional[TokenResponse] = None
        self.session: Optional[OAuthSession] = None  # Store OAuth session
        self.flow_history: list = []

    def clear(self):
        """Clear the console."""
        self.console.clear()

    def show_welcome(self):
        """Display welcome screen."""
        self.clear()

        welcome_text = """
        [bold cyan]╔═══════════════════════════════════════════════════════╗[/]
        [bold cyan]║[/]  [bold magenta]🎨 OAuth 2.0 Interactive Playground[/]        [bold cyan]║[/]
        [bold cyan]╚═══════════════════════════════════════════════════════╝[/]

        [yellow]Test OAuth flows in real-time with beautiful visualizations[/]

        Features:
        • [green]✓[/] Step-by-step flow testing
        • [green]✓[/] Live token inspection
        • [green]✓[/] QR code generation
        • [green]✓[/] Request/response viewing
        • [green]✓[/] Export to cURL/Postman
        """

        self.console.print(Panel(welcome_text, border_style="cyan"))

    def select_provider(self) -> Providers:
        """Interactive provider selection."""
        self.console.print("\n[bold cyan]Available OAuth Providers:[/]\n")

        providers = list(Providers)
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("#", style="cyan", width=6)
        table.add_column("Provider", style="green")
        table.add_column("Status", style="yellow")

        for idx, provider in enumerate(providers, 1):
            status = "✅ Implemented" if idx <= 8 else "🚧 Coming Soon"
            table.add_row(str(idx), provider.display_name, status)

        self.console.print(table)

        while True:
            choice = Prompt.ask("\n[cyan]Select provider number[/]", default="1")
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(providers):
                    return providers[idx]
            except ValueError:
                pass
            self.console.print("[red]Invalid choice. Please try again.[/]")

    def configure_client(self) -> OAuth2Client:
        """Interactive client configuration."""
        self.console.print("\n[bold cyan]Configure OAuth Client:[/]\n")

        provider = self.select_provider()

        client_id = Prompt.ask("[cyan]Client ID[/]", default="demo_client_id")
        client_secret = Prompt.ask(
            "[cyan]Client Secret[/]", default="demo_secret", password=True
        )
        redirect_uri = Prompt.ask(
            "[cyan]Redirect URI[/]", default="http://localhost:8000/callback"
        )

        scopes_input = Prompt.ask(
            "[cyan]Scopes (comma-separated)[/]", default="openid,email,profile"
        )
        scopes = [s.strip() for s in scopes_input.split(",")]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            task = progress.add_task("Initializing OAuth client...", total=None)
            time.sleep(1)

            client = OAuth2Client(
                provider=provider,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                scopes=scopes,
            )

            progress.update(task, completed=True)

        self.console.print("\n[green]✓ Client configured successfully![/]\n")

        # Show provider capabilities
        capabilities = []
        if client.supports_pkce():
            capabilities.append("[green]✓ PKCE[/]")
        if client.supports_refresh():
            capabilities.append("[green]✓ Token Refresh[/]")
        if client.supports_revocation():
            capabilities.append("[green]✓ Token Revocation[/]")

        if capabilities:
            self.console.print(
                "[cyan]Provider capabilities:[/] " + " | ".join(capabilities) + "\n"
            )

        return client

    def show_authorization_url(self, auth_url: str):
        """Display authorization URL with QR code."""
        self.console.print("\n[bold cyan]Step 1: Authorization URL Generated[/]\n")

        # Show URL
        url_panel = Panel(
            f"[yellow]{auth_url}[/]", title="🔗 Authorization URL", border_style="green"
        )
        self.console.print(url_panel)

        # Show QR Code if available
        if qrcode:
            self.console.print("\n[cyan]Scan QR Code:[/]\n")
            qr = qrcode.QRCode(version=1, box_size=1, border=1)
            qr.add_data(auth_url)
            qr.make(fit=True)

            # Print ASCII QR code
            matrix = qr.get_matrix()
            for row in matrix:
                line = "".join("██" if cell else "  " for cell in row)
                self.console.print(line)

        # Parse URL components
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(auth_url)
        params = parse_qs(parsed.query)

        # Show parameters
        self.console.print("\n[bold cyan]URL Parameters:[/]\n")
        param_table = Table(show_header=True, box=box.SIMPLE)
        param_table.add_column("Parameter", style="cyan")
        param_table.add_column("Value", style="yellow")

        for key, values in params.items():
            value = values[0] if values else ""
            if len(value) > 50:
                value = value[:47] + "..."
            param_table.add_row(key, value)

        self.console.print(param_table)

    def show_token_details(self, tokens: TokenResponse):
        """Display token details with live countdown."""
        self.console.print("\n[bold green]✓ Tokens Received Successfully![/]\n")

        # Create token info table
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("Property", style="cyan", width=20)
        table.add_column("Value", style="yellow")

        # Access token (truncated)
        table.add_row(
            "Access Token",
            (
                f"{tokens.access_token[:30]}..."
                if len(tokens.access_token) > 30
                else tokens.access_token
            ),
        )

        # Token type
        table.add_row("Token Type", tokens.token_type)

        # Expires in
        if tokens.expires_in:
            table.add_row("Expires In", f"{tokens.expires_in} seconds")

            if tokens.expires_at:
                expires_str = tokens.expires_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                table.add_row("Expires At", expires_str)

        # Refresh token
        if tokens.refresh_token:
            table.add_row(
                "Refresh Token",
                (
                    f"{tokens.refresh_token[:30]}..."
                    if len(tokens.refresh_token) > 30
                    else tokens.refresh_token
                ),
            )

        # Scopes
        if tokens.scope:
            table.add_row("Scopes", ", ".join(tokens.scopes))

        # ID Token (if present)
        if tokens.id_token:
            table.add_row("ID Token", f"{tokens.id_token[:30]}...")

        self.console.print(table)

        # Show expiration countdown
        if tokens.expires_at and not tokens.is_expired:
            remaining = tokens.expires_at - datetime.utcnow()
            self.console.print(
                f"\n[yellow]⏱️  Token expires in: {remaining.seconds // 60} minutes, "
                f"{remaining.seconds % 60} seconds[/]"
            )

    def show_user_info(self, user_info):
        """Display user information."""
        self.console.print("\n[bold cyan]User Information:[/]\n")

        table = Table(show_header=False, box=box.ROUNDED)
        table.add_column("Field", style="cyan", width=20)
        table.add_column("Value", style="green")

        if user_info.id:
            table.add_row("User ID", user_info.id)
        if user_info.email:
            table.add_row("Email", user_info.email)
        if user_info.name:
            table.add_row("Name", user_info.name)
        if user_info.given_name:
            table.add_row("First Name", user_info.given_name)
        if user_info.family_name:
            table.add_row("Last Name", user_info.family_name)
        if user_info.picture:
            table.add_row("Picture URL", user_info.picture)
        if user_info.locale:
            table.add_row("Locale", user_info.locale)
        if user_info.verified_email is not None:
            verified = "✅ Yes" if user_info.verified_email else "❌ No"
            table.add_row("Email Verified", verified)

        self.console.print(table)

    def export_flow(self, format: str = "curl"):
        """Export the OAuth flow."""
        if not self.flow_history or not self.client:
            self.console.print("[red]No flow history to export[/]")
            return

        self.console.print(f"\n[bold cyan]Exporting as {format.upper()}...[/]\n")

        if format == "curl":
            # Generate cURL command
            curl_cmd = f"""# OAuth 2.0 Flow - cURL Commands

# Step 1: Get Authorization URL
curl -X GET '{self.flow_history[0].get('auth_url', '')}' \\
  -H 'Accept: application/json'

# Step 2: Exchange Code for Token
curl -X POST '{self.flow_history[0].get('token_endpoint', '')}' \\
  -H 'Content-Type: application/x-www-form-urlencoded' \\
  -d 'client_id={self.client.client_id}' \\
  -d 'client_secret={self.client.client_secret}' \\
  -d 'code=AUTHORIZATION_CODE' \\
  -d 'redirect_uri={self.client.redirect_uri}' \\
  -d 'grant_type=authorization_code'
"""

            syntax = Syntax(curl_cmd, "bash", theme="monokai", line_numbers=True)
            self.console.print(Panel(syntax, title="cURL Export", border_style="green"))

        elif format == "json":
            # Generate JSON export
            export_data = {
                "provider": self.client.provider.__class__.__name__,
                "configuration": {
                    "client_id": self.client.client_id,
                    "redirect_uri": self.client.redirect_uri,
                    "scopes": self.client.scopes,
                    "supports_pkce": self.client.supports_pkce(),
                    "supports_refresh": self.client.supports_refresh(),
                    "supports_revocation": self.client.supports_revocation(),
                },
                "flow_history": self.flow_history,
            }

            json_str = json.dumps(export_data, indent=2)
            syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
            self.console.print(Panel(syntax, title="JSON Export", border_style="green"))

    def test_flow(self, provider: Optional[str] = None):
        """
        Run interactive OAuth flow test.

        Args:
            provider: Optional provider name (if not provided, will prompt)
        """
        self.show_welcome()
        time.sleep(1)

        # Configure client
        self.client = self.configure_client()

        # Step 1: Generate Authorization URL
        self.console.print(
            "\n[bold cyan]═══ Step 1: Generate Authorization Session ═══[/]\n"
        )
        self.session = self.client.get_authorization_session()
        auth_url = self.session.url

        self.flow_history.append(
            {
                "step": "authorization_url",
                "auth_url": auth_url,
                "state": self.session.state,
                "has_pkce": self.session.code_verifier is not None,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

        self.show_authorization_url(auth_url)

        # Prompt for code
        self.console.print(
            "\n[yellow]👉 Open the URL in your browser and authorize the application[/]"
        )

        if not Confirm.ask("\n[cyan]Ready to continue with callback?[/]", default=True):
            self.console.print("[yellow]Flow cancelled[/]")
            return

        # Step 2: Exchange Code
        self.console.print(
            "\n[bold cyan]═══ Step 2: Exchange Authorization Code ═══[/]\n"
        )

        code = Prompt.ask("[cyan]Enter the authorization code from callback[/]")
        state = Prompt.ask(
            "[cyan]Enter the state parameter from callback (optional)[/]", default=""
        )

        # Validate state if provided
        if state and self.session:
            try:
                self.session.validate_state(state)
                self.console.print("[green]✓ State validation successful[/]\n")
            except ValueError as e:
                self.console.print(f"[red]✗ State validation failed: {e}[/]\n")
                return

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Exchanging code for tokens...", total=None)

                # Use session for PKCE flow
                self.tokens = self.client.exchange_code(code=code, session=self.session)

                progress.update(task, completed=True)

            self.flow_history.append(
                {
                    "step": "token_exchange",
                    "tokens_received": True,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

            self.show_token_details(self.tokens)

            # Step 3: Get User Info
            if Confirm.ask("\n[cyan]Fetch user information?[/]", default=True):
                self.console.print(
                    "\n[bold cyan]═══ Step 3: Fetch User Information ═══[/]\n"
                )

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=self.console,
                ) as progress:
                    task = progress.add_task("Fetching user info...", total=None)

                    user_info = self.client.get_user_info(self.tokens.access_token)

                    progress.update(task, completed=True)

                self.show_user_info(user_info)

            # Export options
            self.console.print("\n[bold cyan]═══ Export Flow ═══[/]\n")

            if Confirm.ask("[cyan]Export flow as cURL?[/]", default=False):
                self.export_flow("curl")

            if Confirm.ask("[cyan]Export flow as JSON?[/]", default=False):
                self.export_flow("json")

            self.console.print(
                "\n[bold green]✓ OAuth flow completed successfully![/]\n"
            )

        except Exception as e:
            self.console.print(f"\n[bold red]❌ Error: {str(e)}[/]\n")
            self.flow_history.append(
                {
                    "step": "error",
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )


def main():
    """Run the playground."""
    playground = OAuthPlayground()
    playground.test_flow()


if __name__ == "__main__":
    main()
