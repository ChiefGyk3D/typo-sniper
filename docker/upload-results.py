#!/usr/bin/env python3
"""
Ship a completed scan's reports to S3.

A separate script rather than an inline ``python -c`` in the task definition:
that would be a Python string inside a shell string inside a JSON string inside
HCL, and every layer of escaping there is somewhere a bug can hide silently.

Reads RESULTS_BUCKET and RESULTS_PREFIX from the environment. Uploading is
best-effort per file: one unreadable report should not discard the rest of a
scan's output.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

import os
import pathlib
import sys


def main() -> int:
    bucket = os.environ.get('RESULTS_BUCKET')
    if not bucket:
        print('RESULTS_BUCKET is not set; nothing to upload', file=sys.stderr)
        return 0

    prefix = os.environ.get('RESULTS_PREFIX', '').strip('/')
    source = pathlib.Path(os.environ.get('RESULTS_DIR', '/app/results'))

    if not source.is_dir():
        print(f'{source} does not exist; nothing to upload', file=sys.stderr)
        return 0

    import boto3

    client = boto3.client('s3')
    uploaded = failed = 0

    for path in sorted(source.rglob('*')):
        if not path.is_file():
            continue

        relative = path.relative_to(source).as_posix()
        key = f'{prefix}/{relative}' if prefix else relative

        try:
            client.upload_file(str(path), bucket, key)
            uploaded += 1
        except Exception as e:
            # Only the exception type: a client error message can echo the
            # request, and these run in a log an operator may ship elsewhere.
            print(f'Failed to upload {relative} ({type(e).__name__})', file=sys.stderr)
            failed += 1

    print(f'Uploaded {uploaded} report file(s) to s3://{bucket}/{prefix}')

    # A scan whose reports did not reach S3 has not really finished, so a
    # complete failure is an error the scheduler should surface.
    return 1 if failed and not uploaded else 0


if __name__ == '__main__':
    sys.exit(main())
