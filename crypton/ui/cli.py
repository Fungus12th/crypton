import os
import sys
import datetime
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from crypton.core.vault import VaultManager, VaultError, InvalidPasswordError
from crypton.core.header import VaultHeader

app = typer.Typer(
    name="crypton",
    help="Crypton - Cross-Platform Secure USB Vault and Cloud Sync Tool",
    add_completion=False,
)
console = Console()


@app.command()
def init(
    drive_path: str = typer.Argument(".", help="Path to USB drive or directory to encrypt"),
    time_cost: int = typer.Option(3, help="Argon2id time cost (iterations)"),
    memory_cost: int = typer.Option(65536, help="Argon2id memory cost in KB (default: 64MB)"),
    parallelism: int = typer.Option(4, help="Argon2id parallelism lanes"),
):
    """Initialize a new Crypton secure vault on a pendrive or directory."""
    abs_path = os.path.abspath(drive_path)
    if not os.path.exists(abs_path):
        console.print(f"[red]Error: Target directory '{abs_path}' does not exist.[/red]")
        raise typer.Exit(code=1)

    if VaultManager.is_vault(abs_path):
        console.print(f"[yellow]Vault already exists at '{abs_path}'.[/yellow]")
        raise typer.Exit(code=1)

    console.print(f"[bold cyan]Initializing Crypton Vault on:[/bold cyan] [green]{abs_path}[/green]")
    
    password = typer.prompt("Enter master vault password", hide_input=True)
    confirm = typer.prompt("Confirm master vault password", hide_input=True)

    if password != confirm:
        console.print("[red]Error: Passwords do not match.[/red]")
        raise typer.Exit(code=1)

    if len(password) < 6:
        console.print("[red]Error: Password must be at least 6 characters long.[/red]")
        raise typer.Exit(code=1)

    with console.status("[bold green]Deriving Argon2id keys and creating vault structure..."):
        try:
            header = VaultManager.init_vault(
                abs_path,
                password,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
            )
        except Exception as e:
            console.print(f"[red]Failed to initialize vault: {e}[/red]")
            raise typer.Exit(code=1)

    console.print(
        Panel(
            f"[bold green]✔ Vault successfully initialized![/bold green]\n"
            f"Location: [cyan]{abs_path}[/cyan]\n"
            f"Argon2id params: memory={header.memory_cost}KB, time={header.time_cost}, lanes={header.parallelism}\n"
            f"Cipher: AES-256-GCM chunked streaming\n\n"
            f"[bold yellow]Remember: If you lose your password, data cannot be recovered![/bold yellow]",
            title="Crypton Lock Initialized",
            border_style="green",
        )
    )


@app.command()
def info(
    drive_path: str = typer.Argument(".", help="Path to USB drive or vault directory"),
):
    """Display public vault header metadata (salt, creation date, cipher info)."""
    abs_path = os.path.abspath(drive_path)
    header_path = VaultManager.get_header_path(abs_path)

    if not os.path.isfile(header_path):
        console.print(f"[red]Error: No Crypton vault found at '{abs_path}'.[/red]")
        raise typer.Exit(code=1)

    with open(header_path, "rb") as f:
        header = VaultHeader.deserialize(f.read())

    created_dt = datetime.datetime.fromtimestamp(header.created_at).strftime("%Y-%m-%d %H:%M:%S")

    table = Table(title="Crypton Vault Metadata", border_style="cyan")
    table.add_column("Property", style="bold yellow")
    table.add_column("Value", style="white")

    table.add_row("Vault Location", abs_path)
    table.add_row("Created Date", created_dt)
    table.add_row("KDF Algorithm", "Argon2id")
    table.add_row("Memory Cost", f"{header.memory_cost} KB ({header.memory_cost // 1024} MB)")
    table.add_row("Time Cost (Iterations)", str(header.time_cost))
    table.add_row("Parallelism Lanes", str(header.parallelism))
    table.add_row("Argon2id Salt", header.salt.hex())
    table.add_row("MVK Nonce", header.mvk_nonce.hex())
    table.add_row("Cloud Token Attached", "Yes" if header.wrapped_cloud_token else "No")

    console.print(table)


@app.command()
def unlock(
    drive_path: str = typer.Argument(".", help="Path to USB drive or vault directory"),
):
    """Test unlocking the vault by verifying your password."""
    abs_path = os.path.abspath(drive_path)
    if not VaultManager.is_vault(abs_path):
        console.print(f"[red]Error: No Crypton vault found at '{abs_path}'.[/red]")
        raise typer.Exit(code=1)

    password = typer.prompt("Enter master vault password", hide_input=True)

    with console.status("[bold green]Verifying password with Argon2id..."):
        try:
            mvk = VaultManager.unlock_vault(abs_path, password)
            console.print(f"[bold green]✔ Password verified! Master Vault Key successfully unwrapped in RAM.[/bold green]")
        except InvalidPasswordError:
            console.print("[bold red]✖ Access Denied: Incorrect password or corrupted vault header.[/bold red]")
            raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"[bold red]✖ Error: {e}[/bold red]")
            raise typer.Exit(code=1)


@app.command()
def add(
    src_file: str = typer.Argument(..., help="Path to local file to encrypt and import"),
    drive_path: str = typer.Option(".", "--drive", "-d", help="Path to Crypton vault directory"),
    as_path: Optional[str] = typer.Option(None, "--as", "-a", help="Relative destination path inside vault"),
):
    """Encrypt and add a file into the Crypton vault."""
    abs_drive = os.path.abspath(drive_path)
    if not VaultManager.is_vault(abs_drive):
        console.print(f"[red]Error: No Crypton vault found at '{abs_drive}'.[/red]")
        raise typer.Exit(code=1)

    if not os.path.isfile(src_file):
        console.print(f"[red]Error: Source file '{src_file}' does not exist.[/red]")
        raise typer.Exit(code=1)

    password = typer.prompt("Enter master vault password", hide_input=True)

    try:
        mvk = VaultManager.unlock_vault(abs_drive, password)
    except InvalidPasswordError:
        console.print("[bold red]✖ Access Denied: Incorrect password.[/bold red]")
        raise typer.Exit(code=1)

    with console.status(f"[bold green]Encrypting '{src_file}' into vault data blocks..."):
        record = VaultManager.add_file(abs_drive, mvk, src_file, as_path)

    console.print(
        f"[green]✔ Added [bold]{record['rel_path']}[/bold] ({record['size']} bytes) -> Block ID: [cyan]{record['file_id']}[/cyan][/green]"
    )


@app.command()
def list(
    drive_path: str = typer.Argument(".", help="Path to USB drive or vault directory"),
):
    """List all encrypted files currently stored inside the vault."""
    abs_drive = os.path.abspath(drive_path)
    if not VaultManager.is_vault(abs_drive):
        console.print(f"[red]Error: No Crypton vault found at '{abs_drive}'.[/red]")
        raise typer.Exit(code=1)

    password = typer.prompt("Enter master vault password", hide_input=True)

    try:
        mvk = VaultManager.unlock_vault(abs_drive, password)
    except InvalidPasswordError:
        console.print("[bold red]✖ Access Denied: Incorrect password.[/bold red]")
        raise typer.Exit(code=1)

    files = VaultManager.list_files(abs_drive, mvk)

    if not files:
        console.print("[yellow]The vault is currently empty.[/yellow]")
        return

    table = Table(title="Encrypted Files in Vault", border_style="green")
    table.add_column("Vault Path", style="bold white")
    table.add_column("Original Size", justify="right", style="cyan")
    table.add_column("Block ID", style="dim")
    table.add_column("SHA-256 Digest", style="dim yellow")

    for f in files:
        table.add_row(
            f["rel_path"],
            f"{f['size']:,} bytes",
            f["file_id"][:12] + "...",
            f["sha256"][:16] + "...",
        )

    console.print(table)


@app.command()
def extract(
    vault_file: str = typer.Argument(..., help="Relative path of file inside the vault"),
    dest_path: str = typer.Argument(..., help="Destination path to decrypt the file into"),
    drive_path: str = typer.Option(".", "--drive", "-d", help="Path to Crypton vault directory"),
):
    """Decrypt and extract a file from the vault to your filesystem."""
    abs_drive = os.path.abspath(drive_path)
    if not VaultManager.is_vault(abs_drive):
        console.print(f"[red]Error: No Crypton vault found at '{abs_drive}'.[/red]")
        raise typer.Exit(code=1)

    password = typer.prompt("Enter master vault password", hide_input=True)

    try:
        mvk = VaultManager.unlock_vault(abs_drive, password)
    except InvalidPasswordError:
        console.print("[bold red]✖ Access Denied: Incorrect password.[/bold red]")
        raise typer.Exit(code=1)

    with console.status(f"[bold green]Decrypting '{vault_file}' to '{dest_path}'..."):
        try:
            VaultManager.extract_file(abs_drive, mvk, vault_file, dest_path)
            console.print(f"[bold green]✔ Successfully decrypted '{vault_file}' -> '{dest_path}'[/bold green]")
        except Exception as e:
            console.print(f"[bold red]✖ Extraction failed: {e}[/bold red]")
            raise typer.Exit(code=1)


@app.command(name="change-password")
def change_password(
    drive_path: str = typer.Argument(".", help="Path to USB drive or vault directory"),
):
    """Instantly change the vault password without re-encrypting any files."""
    abs_drive = os.path.abspath(drive_path)
    if not VaultManager.is_vault(abs_drive):
        console.print(f"[red]Error: No Crypton vault found at '{abs_drive}'.[/red]")
        raise typer.Exit(code=1)

    old_password = typer.prompt("Enter CURRENT master vault password", hide_input=True)
    new_password = typer.prompt("Enter NEW master vault password", hide_input=True)
    confirm = typer.prompt("Confirm NEW master vault password", hide_input=True)

    if new_password != confirm:
        console.print("[red]Error: New passwords do not match.[/red]")
        raise typer.Exit(code=1)

    if len(new_password) < 6:
        console.print("[red]Error: New password must be at least 6 characters.[/red]")
        raise typer.Exit(code=1)

    with console.status("[bold green]Re-wrapping Master Vault Key with fresh Argon2id salt..."):
        try:
            VaultManager.change_password(abs_drive, old_password, new_password)
            console.print("[bold green]✔ Password changed successfully in <100ms![/bold green]")
        except InvalidPasswordError:
            console.print("[bold red]✖ Access Denied: Current password is incorrect.[/bold red]")
            raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"[bold red]✖ Error: {e}[/bold red]")
            raise typer.Exit(code=1)


@app.command(name="config")
def config_cmd(
    drive_path: str = typer.Argument(".", help="Path to USB drive or vault directory"),
    ram_limit: Optional[int] = typer.Option(None, "--ram-limit", "-r", help="RAM staging limit in MB (e.g. 16, 32, 64, 128)"),
):
    """View or configure developer performance settings (e.g., RAM staging limit)."""
    abs_drive = os.path.abspath(drive_path)
    settings = VaultManager.get_settings(abs_drive)
    if ram_limit is not None:
        settings["ram_limit_mb"] = ram_limit
        VaultManager.save_settings(abs_drive, settings)
        console.print(f"[bold green]✔ RAM staging buffer limit set to {ram_limit} MB.[/bold green]")
    else:
        console.print(f"[bold cyan]Crypton Performance Settings for {abs_drive}:[/bold cyan]")
        console.print(f"  • RAM Staging Limit: [bold green]{settings.get('ram_limit_mb', 32)} MB[/bold green]")
