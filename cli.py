import argparse
import os

def main():
    parser = argparse.ArgumentParser(
        prog="UnpackFW",
        description="UnpackFW - IoT firmware unpacking and analysis tool",
        epilog="Example usage:\n  python cli.py --input firmware.bin --extract-only",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('--input', type=str, help='Path to the firmware file (.bin, .img, etc.)')
    parser.add_argument('--extract-only', action='store_true', help='Only extract firmware')
    parser.add_argument('--analyze', action='store_true', help='Perform static analysis')
    parser.add_argument('--output', type=str, default="./output", help='Output directory')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose/debug output')

    args = parser.parse_args()

    if not (args.extract_only or args.analyze):
        print("[!] No action specified. Use one of: --extract-only, or --analyze.")
        parser.print_help()
        return

    if not args.input:
        print("[!] --input is required for the selected action.")
        parser.print_help()
        return

    if not os.path.isfile(args.input):
        print(f"[!] Input file not found: {args.input}")
        return

    # Dispatch logic
    if args.extract_only:
        from scanner.unpacker import run_extract
        run_extract(args.input, args.output, args.verbose)

    elif args.analyze:
        from scanner.analyzer import run_analysis
        run_analysis(args.input, args.output, args.verbose)


if __name__ == "__main__":
    main()
