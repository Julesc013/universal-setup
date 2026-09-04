<!-- SPDX-FileCopyrightText: 2026 Jules C -->
<!-- SPDX-License-Identifier: MIT -->

# Private zlib inflate subset

`upstream/` contains an unmodified, hash-locked subset of zlib 1.3.2 used only
by Universal Setup's private ZIP Deflate reader. The subset is compiled into
the provider libraries with zlib's supported `Z_PREFIX` namespace so static
consumers do not collide with an ordinary zlib linkage. Its headers and CMake
targets are not installed or exported.

`provenance.v1.toml` binds the official archive, tag, source commit, licence,
and every admitted file. Run `py -3 tools/zlib_dependency_check.py` after any
dependency change.
