"""Normalize source-distribution archive metadata for reproducible releases."""

from __future__ import annotations

import argparse
import copy
import gzip
import io
import os
import tarfile
from pathlib import Path


def normalize_sdist(path: Path, source_date_epoch: int) -> None:
    """Rewrite one ``.tar.gz`` with stable ordering, ownership, modes and timestamps."""

    if source_date_epoch < 0:
        raise ValueError("source_date_epoch must not be negative.")
    path = path.resolve()
    temporary = path.with_name(path.name + ".normalized")
    tar_buffer = io.BytesIO()
    with tarfile.open(path, mode="r:gz") as source, tarfile.open(
        fileobj=tar_buffer,
        mode="w",
        format=tarfile.PAX_FORMAT,
    ) as target:
        for original in sorted(source.getmembers(), key=lambda member: member.name):
            member = copy.copy(original)
            member.mtime = source_date_epoch
            # The builder's umask must not leak into release bytes.
            member.mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.pax_headers = {}
            file_data = source.extractfile(original) if original.isfile() else None
            target.addfile(member, file_data)
    with temporary.open("wb") as raw_output, gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=raw_output,
        mtime=source_date_epoch,
    ) as compressed:
        compressed.write(tar_buffer.getvalue())
    os.replace(temporary, path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
    )
    args = parser.parse_args()
    for path in args.paths:
        normalize_sdist(path, args.source_date_epoch)
        print(path)


if __name__ == "__main__":
    main()
