"""CLI and local MCP entry point."""
import argparse
import json
import sys
from .app import App
from .safety import Failure
from .server import Server

def main():
    parser = argparse.ArgumentParser(description="Authorized static Android analysis")
    parser.add_argument("--workspace")
    parser.add_argument("--home")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("serve", "doctor", "capabilities"):
        commands.add_parser(name)
    setup = commands.add_parser("setup")
    setup.add_argument("--yes", action="store_true")
    for name in ("inspect", "headers"):
        commands.add_parser(name).add_argument("path")
    analyze = commands.add_parser("analyze")
    analyze.add_argument("path")
    analyze.add_argument("--mode", choices=["both", "code", "resources"], default="both")
    compare = commands.add_parser("compare")
    compare.add_argument("before")
    compare.add_argument("after")
    for name in ("manifest", "summary", "artifacts", "search", "read"):
        command = commands.add_parser(name)
        command.add_argument("job_id")
        if name == "search":
            command.add_argument("query")
        if name == "read":
            command.add_argument("path")
    args = parser.parse_args()
    try:
        app = App(args.workspace, args.home)
        if args.command == "serve":
            Server(app).serve()
            return
        if args.command == "setup":
            if not args.yes:
                raise Failure("CONSENT_REQUIRED", "Pass --yes to approve official downloads")
            data = app.installer.setup()
        elif args.command == "inspect":
            data = app.inspect_apk(args.path)
        elif args.command == "headers":
            data = app.inspect_headers(args.path)
        elif args.command == "analyze":
            data = app.analyze_apk(args.path, args.mode)
        elif args.command == "compare":
            data = app.compare_apks(args.before, args.after)
        elif args.command == "manifest":
            data = app.review_manifest(args.job_id)
        elif args.command == "summary":
            data = app.summarize_job(args.job_id)
        elif args.command == "artifacts":
            data = app.list_artifacts(args.job_id)
        elif args.command == "search":
            data = app.search_artifacts(args.job_id, args.query)
        elif args.command == "read":
            data = app.read_artifact(args.job_id, args.path)
        else:
            data = getattr(app, args.command)()
        print(json.dumps(data, indent=2, ensure_ascii=False))
    except (Failure, OSError, ValueError) as exc:
        error = exc.as_dict() if isinstance(exc, Failure) else {"code": "HOST_ERROR", "message": str(exc)}
        print(json.dumps({"error": error}), file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
