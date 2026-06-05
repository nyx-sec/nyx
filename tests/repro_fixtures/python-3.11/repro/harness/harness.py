import os
import sys


def main() -> int:
    payload = os.environ.get('NYX_PAYLOAD', '')
    if not payload:
        sys.stderr.write('error: NYX_PAYLOAD missing\n')
        return 2
    try:
        result = eval(payload)  # noqa: S307 sink under sandbox
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f'__NYX_SINK_ERROR__ {type(exc).__name__}: {exc}\n')
        return 1
    sys.stdout.write('__NYX_SINK_HIT__\n')
    sys.stdout.write(f'eval-result={result}\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
