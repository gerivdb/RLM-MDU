#!/usr/bin/env python3
"""
RLM-MDU CLI — Interface en ligne de commande pour le runner cognitif MDU
Commandes: detect, fix, dry-run, health
"""

import sys
import json
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from rlm_mdu import detect, fix, health, MDU_CONFIG


def main():
    parser = argparse.ArgumentParser(
        description="RLM-MDU — Runner Cognitif pour le Design MDU",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python cli.py --detect --workspace D:/DO/WEB/TOOLS/L0-CANON/unified-design
  python cli.py --fix --dry-run --workspace D:/DO/WEB/TOOLS/L0-CANON/unified-design
  python cli.py --health
  python cli.py --fix --workspace D:/DO/WEB/TOOLS/L0-CANON/unified-design
        """
    )
    
    parser.add_argument(
        "--detect", "-d",
        action="store_true",
        help="Detect all frictions (ERR-001 to ERR-014) in workspace"
    )
    parser.add_argument(
        "--fix", "-f",
        action="store_true",
        help="Apply corrections using ATOMs"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview corrections without applying (use with --fix)"
    )
    parser.add_argument(
        "--workspace", "-w",
        default="D:/DO/WEB/TOOLS/L0-CANON/unified-design",
        help="Workspace path to scan (default: unified-design)"
    )
    parser.add_argument(
        "--health", "-h",
        action="store_true",
        help="Check runner health"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Health check
    if args.health:
        result = health()
        print(json.dumps(result, indent=2))
        return 0
    
    # Detect
    if args.detect:
        if args.verbose:
            print(f"[RLM-MDU] Scanning workspace: {args.workspace}")
        result = detect(args.workspace)
        print(json.dumps(result, indent=2))
        return 0
    
    # Fix
    if args.fix:
        if args.verbose:
            mode = "DRY-RUN" if args.dry_run else "APPLY"
            print(f"[RLM-MDU] {mode} corrections in: {args.workspace}")
        result = fix(args.workspace, args.dry_run)
        print(json.dumps(result, indent=2))
        return 0
    
    # No action specified
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())