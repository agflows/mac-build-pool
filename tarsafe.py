"""Extract a source snapshot without following links or escaping the revision directory."""

from __future__ import annotations

import tarfile
from pathlib import Path

from policy import PolicyError


def extract_source(archive: Path, destination: Path, max_bytes: int) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    total = 0
    try:
        tar = tarfile.open(archive, "r:*")
    except tarfile.TarError as exc:
        raise PolicyError("invalid_archive", "Source snapshot is not a tar archive.") from exc
    with tar:
        for member in tar.getmembers():
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise PolicyError("invalid_archive", "Links and special files are not accepted.")
            if not (member.isdir() or member.isfile()):
                raise PolicyError("invalid_archive", "Archive members must be files or directories.")
            relative = Path(member.name)
            if ".worker" in relative.parts:
                raise PolicyError("invalid_archive", "The .worker directory is reserved for job runtime state.")
            if relative.is_absolute() or ".." in relative.parts:
                raise PolicyError("invalid_archive", "Archive paths must stay inside the snapshot.")
            target = (root / relative).resolve()
            if target != root and root not in target.parents:
                raise PolicyError("invalid_archive", "Archive path escapes the snapshot.")
            if member.isfile():
                total += member.size
                if total > max_bytes:
                    raise PolicyError("invalid_archive", "Uncompressed snapshot is too large.")
            tar.extract(member, path=root, set_attrs=False)
