#!/usr/bin/env python3
"""
OFXpwn CLI - Main command-line interface

This is the entry point for the OFXpwn security testing framework.
"""

import click
import sys
from pathlib import Path
from typing import Optional

from ofxpwn import __version__
from ofxpwn.core.config import Config
from ofxpwn.core.logger import Logger
from ofxpwn.core.module_loader import ModuleLoader


# Context settings to enable -h for help
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


# ASCII banner
BANNER = r"""   ____  ________  __
  / __ \/ ____/ |/ /____  _      ______
 / / / / /_   |   / __ \ | | /| / / __ \
/ /_/ / __/  /   / /_/ / | |/ |/ / / / /
\____/_/    /_/|_/ .___/  |__/|__/_/ /_/
                /_/

OFX Penetration Testing Framework v{version}
By Mike Piekarski | https://github.com/pect0ral
"""


class Context:
    """Global context for CLI commands"""

    def __init__(self):
        self.config: Optional[Config] = None
        self.logger: Optional[Logger] = None
        self.verbose: bool = False
        self.module_loader: Optional[ModuleLoader] = None


pass_context = click.make_pass_decorator(Context, ensure=True)


@click.group(invoke_without_command=True, context_settings=CONTEXT_SETTINGS)
@click.option("--version", is_flag=True, help="Show version and exit")
@click.option("--banner/--no-banner", default=True, help="Show banner")
@click.pass_context
def cli(ctx, version, banner):
    """OFXpwn - Open Financial Exchange Security Testing Framework

    A modular penetration testing toolkit for OFX servers.
    """
    # Initialize context
    ctx.obj = Context()

    if version:
        click.echo(f"OFXpwn version {__version__}")
        sys.exit(0)

    if banner and ctx.invoked_subcommand is not None:
        click.echo(BANNER.format(version=__version__))


@cli.command(context_settings=CONTEXT_SETTINGS)
@click.argument("what", required=False, default="modules",
                type=click.Choice(["modules", "categories", "all"], case_sensitive=False))
@click.option("--category", "-c", help="Filter by category")
@pass_context
def list(ctx, what, category):
    """List modules, categories, or everything

    Examples:
        ofxpwn list                      # List all modules (default)
        ofxpwn list modules              # List all modules
        ofxpwn list categories           # List all categories
        ofxpwn list all                  # List everything
        ofxpwn list --category auth      # List auth modules only
    """
    loader = ModuleLoader()

    if what == "categories" or what == "all":
        click.echo("\nAvailable Categories:\n")
        categories = ["auth", "recon", "exploit", "fuzz", "infra"]
        for cat in categories:
            mods = loader.list_modules(category=cat)
            click.echo(f"  {cat:<15} - {len(mods)} modules")
        click.echo()

    if what == "modules" or what == "all" or category:
        all_modules = loader.list_modules(category=category)

        if category:
            click.echo(f"\nModules in category '{category.upper()}':\n")
        else:
            click.echo("\nAvailable Modules:\n")

        categories_dict = {}
        for module in all_modules:
            cat = module["category"]
            if cat not in categories_dict:
                categories_dict[cat] = []
            categories_dict[cat].append(module)

        for cat, mods in sorted(categories_dict.items()):
            click.echo(f"\n{cat.upper()}:")
            for mod in sorted(mods, key=lambda x: x["name"]):
                click.echo(f"  {mod['path']:<30} - {mod['description']}")

        click.echo(f"\nTotal modules: {len(all_modules)}\n")


@cli.command(context_settings=CONTEXT_SETTINGS)
@click.option("--config", "-c", type=click.Path(exists=True), help="Config file path")
@pass_context
def modules(ctx, config):
    """List all available modules (deprecated: use 'list' instead)"""
    loader = ModuleLoader()
    all_modules = loader.list_modules()

    click.echo("\nAvailable Modules:\n")

    categories = {}
    for module in all_modules:
        category = module["category"]
        if category not in categories:
            categories[category] = []
        categories[category].append(module)

    for category, mods in sorted(categories.items()):
        click.echo(f"\n{category.upper()}:")
        for mod in sorted(mods, key=lambda x: x["name"]):
            click.echo(f"  {mod['path']:<30} - {mod['description']}")

    click.echo(f"\nTotal modules: {len(all_modules)}\n")


@cli.command(context_settings=CONTEXT_SETTINGS)
@click.argument("module_path")
@click.option("--config", "-c", type=click.Path(exists=True), required=True, help="Config file path")
@click.option("--target", "-t", help="Override target URL")
@click.option("--proxy", "-p", help="Override proxy URL")
@click.option("--org", help="Override organization name")
@click.option("--fid", help="Override FID")
@click.option("--username", "-u", help="Override username")
@click.option("--password", help="Override password")
@click.option("--clientuid", help="Override client UID")
@click.option("--output", "-o", type=click.Path(), help="Override output directory")
@click.option("--threads", type=int, help="Override max threads")
@click.option("--timeout", type=int, help="Override timeout")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@pass_context
def run(ctx, module_path, config, target, proxy, org, fid, username, password, clientuid, output, threads, timeout, verbose):
    """Run a specific module

    Examples:
        ofxpwn run auth/default_creds --config myconfig.yaml
        ofxpwn run recon/fingerprint --config myconfig.yaml --verbose
        ofxpwn run exploit/xxe --config myconfig.yaml --target https://example.com
    """
    ctx.verbose = verbose

    # Load configuration
    try:
        ctx.config = Config(config)
    except Exception as e:
        click.echo(f"Error loading config: {e}", err=True)
        sys.exit(1)

    # Apply runtime overrides
    if target:
        ctx.config.set("target.url", target)
    if proxy:
        ctx.config.set("proxy.url", proxy)
        ctx.config.set("proxy.enabled", True)
    if org:
        ctx.config.set("target.org", org)
    if fid:
        ctx.config.set("target.fid", fid)
    if username:
        ctx.config.set("credentials.username", username)
    if password:
        ctx.config.set("credentials.password", password)
    if clientuid:
        ctx.config.set("credentials.clientuid", clientuid)
    if output:
        ctx.config.set("output.directory", output)
    if threads:
        ctx.config.set("testing.max_threads", threads)
    if timeout:
        ctx.config.set("testing.timeout", timeout)

    # Initialize logger
    ctx.logger = Logger(ctx.config, verbose=verbose)
    ctx.logger.info(f"Running module: {module_path}")

    # Load and execute module
    loader = ModuleLoader()
    try:
        module = loader.load_module(module_path)
        module.run(ctx.config, ctx.logger)
    except Exception as e:
        ctx.logger.error(f"Module execution failed: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command(context_settings=CONTEXT_SETTINGS)
@click.option("--config", "-c", type=click.Path(exists=True), required=True, help="Config file path")
@click.option("--category", type=click.Choice(["auth", "recon", "exploit", "fuzz", "infra"]),
              help="Run all modules in category")
@click.option("--target", "-t", help="Override target URL")
@click.option("--proxy", "-p", help="Override proxy URL")
@click.option("--output", "-o", type=click.Path(), help="Override output directory")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@pass_context
def scan(ctx, config, category, target, proxy, output, verbose):
    """Run multiple modules by category

    Examples:
        ofxpwn scan --category auth --config myconfig.yaml
        ofxpwn scan --category recon --config myconfig.yaml --verbose
    """
    ctx.verbose = verbose

    # Load configuration
    try:
        ctx.config = Config(config)
    except Exception as e:
        click.echo(f"Error loading config: {e}", err=True)
        sys.exit(1)

    # Apply runtime overrides
    if target:
        ctx.config.set("target.url", target)
    if proxy:
        ctx.config.set("proxy.url", proxy)
        ctx.config.set("proxy.enabled", True)
    if output:
        ctx.config.set("output.directory", output)

    # Initialize logger
    ctx.logger = Logger(ctx.config, verbose=verbose)

    # Load modules in category
    loader = ModuleLoader()
    modules = loader.list_modules(category=category)

    ctx.logger.info(f"Running {len(modules)} modules in category: {category}")

    success_count = 0
    fail_count = 0

    for mod_info in modules:
        try:
            ctx.logger.info(f"\n{'='*60}")
            ctx.logger.info(f"Running: {mod_info['path']}")
            ctx.logger.info(f"{'='*60}\n")

            module = loader.load_module(mod_info["path"])
            module.run(ctx.config, ctx.logger)
            success_count += 1

        except Exception as e:
            ctx.logger.error(f"Module {mod_info['path']} failed: {e}")
            fail_count += 1
            if verbose:
                import traceback
                traceback.print_exc()

    ctx.logger.info(f"\n{'='*60}")
    ctx.logger.info(f"Scan complete: {success_count} succeeded, {fail_count} failed")
    ctx.logger.info(f"{'='*60}\n")


@cli.command(context_settings=CONTEXT_SETTINGS)
@click.option("--config", "-c", type=click.Path(exists=True), required=True, help="Config file path")
@click.option("--target", "-t", help="Override target URL")
@click.option("--proxy", "-p", help="Override proxy URL")
@click.option("--output", "-o", type=click.Path(), help="Override output directory")
@click.option("--aggressive", is_flag=True, help="Aggressive mode (faster, noisier)")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@pass_context
def all(ctx, config, target, proxy, output, aggressive, verbose):
    """Run ALL modules (YOLO mode)

    Runs a comprehensive security assessment with all available modules.

    Examples:
        ofxpwn all --config myconfig.yaml
        ofxpwn all --config myconfig.yaml --aggressive
        ofxpwn all --config myconfig.yaml --output /tmp/scan-results
    """
    ctx.verbose = verbose

    # Load configuration
    try:
        ctx.config = Config(config)
    except Exception as e:
        click.echo(f"Error loading config: {e}", err=True)
        sys.exit(1)

    # Apply runtime overrides
    if target:
        ctx.config.set("target.url", target)
    if proxy:
        ctx.config.set("proxy.url", proxy)
        ctx.config.set("proxy.enabled", True)
    if output:
        ctx.config.set("output.directory", output)
    if aggressive:
        ctx.config.set("testing.max_threads", 100)
        ctx.config.set("testing.rate_limit", 0)

    # Initialize logger
    ctx.logger = Logger(ctx.config, verbose=verbose)

    click.echo("\n" + "="*60)
    click.echo("YOLO MODE: Running ALL modules")
    click.echo("="*60 + "\n")

    ctx.logger.warning("Running comprehensive security assessment...")
    ctx.logger.warning("This may generate significant traffic and logs.")

    if not click.confirm("\nProceed with full scan?"):
        click.echo("Scan cancelled.")
        sys.exit(0)

    # Load all modules
    loader = ModuleLoader()
    all_modules = loader.list_modules()

    ctx.logger.info(f"\nRunning {len(all_modules)} modules...\n")

    # Group by category for better organization
    categories = ["recon", "auth", "exploit", "fuzz", "infra"]
    success_count = 0
    fail_count = 0

    for category in categories:
        category_modules = [m for m in all_modules if m["category"] == category]

        if not category_modules:
            continue

        ctx.logger.info(f"\n{'='*60}")
        ctx.logger.info(f"Category: {category.upper()} ({len(category_modules)} modules)")
        ctx.logger.info(f"{'='*60}\n")

        for mod_info in category_modules:
            try:
                ctx.logger.info(f"Running: {mod_info['path']}")
                module = loader.load_module(mod_info["path"])
                module.run(ctx.config, ctx.logger)
                success_count += 1
            except Exception as e:
                ctx.logger.error(f"Module {mod_info['path']} failed: {e}")
                fail_count += 1
                if verbose:
                    import traceback
                    traceback.print_exc()

    ctx.logger.info(f"\n{'='*60}")
    ctx.logger.info(f"Full scan complete!")
    ctx.logger.info(f"Modules run: {success_count + fail_count}")
    ctx.logger.info(f"Succeeded: {success_count}")
    ctx.logger.info(f"Failed: {fail_count}")
    ctx.logger.info(f"{'='*60}\n")


def main():
    """Main entry point"""
    cli()


if __name__ == "__main__":
    main()
