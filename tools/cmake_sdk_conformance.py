# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONSUMER = ROOT / "tests" / "sdk" / "consumer"
EMBEDDED = ROOT / "tests" / "sdk" / "embedded"
PACKAGE_FIXTURE = ROOT / "tests" / "fixtures" / "product-package" / "neutral-product.v1.json"
RECIPE_FIXTURE = ROOT / "tests" / "fixtures" / "product-package" / "neutral-recipe.v1.json"
EXPECTED = {
    "abi": "1.0",
    "local_source": "valid",
    "no_mutation": "validated",
    "package": "valid",
    "recipe": "valid",
}


class ConformanceError(RuntimeError):
    pass


def run(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    expect_failure: bool = False,
    timeout_seconds: int | None = None,
) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    try:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        if expect_failure:
            return subprocess.CompletedProcess(
                command,
                124,
                stdout=f"negative control timed out after {timeout_seconds} seconds",
            )
        raise ConformanceError(
            f"command timed out after {timeout_seconds} seconds: {' '.join(command)}"
        ) from error
    if expect_failure:
        if result.returncode == 0:
            raise ConformanceError(
                f"negative control unexpectedly succeeded: {' '.join(command)}"
            )
    elif result.returncode != 0:
        raise ConformanceError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}"
        )
    return result


def cmake_configure(
    source: Path,
    build: Path,
    definitions: dict[str, str],
    platform: str | None,
    expect_failure: bool = False,
) -> subprocess.CompletedProcess[str]:
    command = ["cmake", "-S", str(source), "-B", str(build)]
    if platform:
        command.extend(["-A", platform])
    command.extend(f"-D{key}={value}" for key, value in definitions.items())
    return run(command, expect_failure=expect_failure)


def build(build_dir: Path, config: str) -> None:
    run(["cmake", "--build", str(build_dir), "--config", config, "--parallel"])


def executable(build_dir: Path, name: str, config: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    candidates = [build_dir / config / f"{name}{suffix}", build_dir / f"{name}{suffix}"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ConformanceError(f"cannot locate executable {name} in {build_dir}")


def runtime_environment(prefix: Path) -> dict[str, str]:
    env = os.environ.copy()
    paths = [str(prefix / "bin"), str(prefix / "lib"), str(prefix / "lib64")]
    if os.name == "nt":
        variable = "PATH"
    elif sys.platform == "darwin":
        variable = "DYLD_LIBRARY_PATH"
    else:
        variable = "LD_LIBRARY_PATH"
    env[variable] = os.pathsep.join(paths + ([env[variable]] if env.get(variable) else []))
    return env


def execute_consumer(
    build_dir: Path,
    config: str,
    prefix: Path | None = None,
    expect_failure: bool = False,
    timeout_seconds: int | None = None,
) -> dict[str, str] | None:
    program = executable(build_dir, "usk_sdk_external_consumer", config)
    result = run(
        [str(program), str(PACKAGE_FIXTURE), str(RECIPE_FIXTURE)],
        env=runtime_environment(prefix) if prefix else None,
        expect_failure=expect_failure,
        timeout_seconds=timeout_seconds,
    )
    if expect_failure:
        return None
    output = json.loads(result.stdout.strip().splitlines()[-1])
    if output != EXPECTED:
        raise ConformanceError(f"unexpected normalized consumer result: {output!r}")
    return output


def install_provider(
    build_dir: Path,
    prefix: Path,
    config: str,
    static: bool,
    shared: bool,
    platform: str | None,
) -> None:
    cmake_configure(
        ROOT,
        build_dir,
        {
            "CMAKE_BUILD_TYPE": config,
            "USK_BUILD_APPS": "OFF",
            "USK_BUILD_FUZZERS": "OFF",
            "USK_BUILD_TESTS": "OFF",
            "USK_BUILD_STATIC": "ON" if static else "OFF",
            "USK_BUILD_SHARED": "ON" if shared else "OFF",
        },
        platform,
    )
    build(build_dir, config)
    run(["cmake", "--install", str(build_dir), "--config", config, "--prefix", str(prefix)])


def configure_consumer(
    build_dir: Path,
    mode: str,
    linkage: str,
    config: str,
    platform: str | None,
    prefix: Path | None = None,
    extra: dict[str, str] | None = None,
    expect_failure: bool = False,
) -> subprocess.CompletedProcess[str]:
    definitions = {
        "CMAKE_BUILD_TYPE": config,
        "USK_CONSUMPTION_MODE": mode,
        "USK_LINKAGE": linkage,
        "USK_PACKAGE_FIXTURE": str(PACKAGE_FIXTURE),
        "USK_RECIPE_FIXTURE": str(RECIPE_FIXTURE),
    }
    if mode == "SOURCE":
        definitions["USK_SOURCE_DIR"] = str(ROOT)
    if prefix:
        definitions["CMAKE_PREFIX_PATH"] = str(prefix)
    if extra:
        definitions.update(extra)
    return cmake_configure(CONSUMER, build_dir, definitions, platform, expect_failure)


def scan_relocation_metadata(prefix: Path, forbidden_paths: list[Path]) -> None:
    suffixes = {".cmake", ".h", ".json", ".md", ".toml", ".txt"}
    forbidden = [str(path.resolve()).replace("\\", "/").lower() for path in forbidden_paths]
    for path in prefix.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        content = path.read_text(encoding="utf-8", errors="replace").replace("\\", "/").lower()
        for value in forbidden:
            if value in content:
                raise ConformanceError(f"stale absolute path {value!r} found in {path}")


def dynamic_runtime_files(prefix: Path) -> list[Path]:
    candidates: list[Path] = []
    for directory in (prefix / "bin", prefix / "lib", prefix / "lib64"):
        if not directory.is_dir():
            continue
        for path in directory.iterdir():
            name = path.name.lower()
            if path.is_file() and (
                name.endswith(".dll") or ".so" in name or name.endswith(".dylib")
            ):
                candidates.append(path)
    return candidates


def prove_install_mode(
    work: Path,
    linkage: str,
    config: str,
    platform: str | None,
) -> tuple[dict[str, str], dict[str, str]]:
    lower = linkage.lower()
    provider_build = work / f"provider-{lower}"
    prefix_a = work / f"prefix-a-{lower}"
    prefix_b = work / "unrelated" / f"prefix-b-{lower}"
    install_provider(
        provider_build,
        prefix_a,
        config,
        linkage == "STATIC",
        linkage == "SHARED",
        platform,
    )

    installed_build = work / f"consumer-installed-{lower}"
    configure_consumer(installed_build, "INSTALLED", linkage, config, platform, prefix_a)
    build(installed_build, config)
    installed = execute_consumer(installed_build, config, prefix_a)

    prefix_b.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(prefix_a), str(prefix_b))
    if prefix_a.exists():
        raise ConformanceError(f"original install prefix remains available: {prefix_a}")
    relocated_build = work / f"consumer-relocated-{lower}"
    configure_consumer(relocated_build, "INSTALLED", linkage, config, platform, prefix_b)
    build(relocated_build, config)
    relocated = execute_consumer(relocated_build, config, prefix_b)
    scan_relocation_metadata(prefix_b, [ROOT, provider_build, prefix_a])

    if linkage == "SHARED":
        runtimes = dynamic_runtime_files(prefix_b)
        if not runtimes:
            raise ConformanceError("shared SDK did not install a runtime library")
        runtime = runtimes[0]
        unavailable = runtime.with_name(runtime.name + ".unavailable")
        runtime.rename(unavailable)
        try:
            execute_consumer(
                relocated_build,
                config,
                prefix_b,
                expect_failure=True,
                timeout_seconds=30,
            )
        finally:
            unavailable.rename(runtime)
    assert installed is not None and relocated is not None
    return installed, relocated


def negative_controls(work: Path, prefix: Path, config: str, platform: str | None) -> None:
    configure_consumer(
        work / "negative-version",
        "INSTALLED",
        "STATIC",
        config,
        platform,
        prefix,
        {"USK_FIND_VERSION": "1.0.1", "USK_FIND_EXACT": "ON"},
        expect_failure=True,
    )
    configure_consumer(
        work / "negative-unexported",
        "INSTALLED",
        "STATIC",
        config,
        platform,
        prefix,
        {"USK_REQUIRE_UNEXPORTED_TARGET": "ON"},
        expect_failure=True,
    )
    empty = work / "empty-prefix"
    empty.mkdir()
    configure_consumer(
        work / "negative-missing-config",
        "INSTALLED",
        "STATIC",
        config,
        platform,
        empty,
        expect_failure=True,
    )

    corrupt_abi = work / "corrupt-abi-prefix"
    shutil.copytree(prefix, corrupt_abi)
    manifests = list(corrupt_abi.rglob("usk_c_abi.v1.toml"))
    if len(manifests) != 1:
        raise ConformanceError("installed ABI manifest closure is ambiguous")
    manifests[0].unlink()
    configure_consumer(
        work / "negative-missing-abi",
        "INSTALLED",
        "STATIC",
        config,
        platform,
        corrupt_abi,
        expect_failure=True,
    )

    corrupt_schema = work / "corrupt-schema-prefix"
    shutil.copytree(prefix, corrupt_schema)
    schemas = list(corrupt_schema.rglob("product_package.v1.schema.json"))
    if len(schemas) != 1:
        raise ConformanceError("installed product-package schema closure is ambiguous")
    schemas[0].unlink()
    configure_consumer(
        work / "negative-missing-schema",
        "INSTALLED",
        "STATIC",
        config,
        platform,
        corrupt_schema,
        expect_failure=True,
    )

    unknown = work / "unknown-product.v1.json"
    fixture = json.loads(PACKAGE_FIXTURE.read_text(encoding="utf-8"))
    fixture["schema"] = "usk.product_package.v999"
    unknown.write_text(json.dumps(fixture, sort_keys=True), encoding="utf-8")
    configure_consumer(
        work / "negative-unknown-schema",
        "INSTALLED",
        "STATIC",
        config,
        platform,
        prefix,
        {"USK_PACKAGE_FIXTURE": str(unknown)},
        expect_failure=True,
    )


def combined_install(work: Path, config: str, platform: str | None) -> None:
    provider_build = work / "provider-combined"
    prefix = work / "prefix-combined"
    install_provider(provider_build, prefix, config, True, True, platform)
    for linkage in ("STATIC", "SHARED"):
        consumer_build = work / f"consumer-combined-{linkage.lower()}"
        configure_consumer(consumer_build, "INSTALLED", linkage, config, platform, prefix)
        build(consumer_build, config)
        execute_consumer(consumer_build, config, prefix)


def source_mode(work: Path, config: str, platform: str | None) -> dict[str, str]:
    cmake_configure(EMBEDDED, work / "embedded", {"USK_SOURCE_DIR": str(ROOT)}, platform)
    source_build = work / "consumer-workspace"
    configure_consumer(source_build, "SOURCE", "STATIC", config, platform)
    build(source_build, config)
    result = execute_consumer(source_build, config)
    assert result is not None
    return result


def main() -> int:
    if os.name == "nt":
        ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--config", default="Release")
    parser.add_argument("--platform")
    parser.add_argument(
        "--phase",
        choices=("full", "workspace", "static", "shared", "combined"),
        default="full",
    )
    args = parser.parse_args()
    work = Path(os.path.abspath(args.work_dir))
    if work == ROOT or ROOT in work.parents:
        allowed_build_root = ROOT / "build"
        if work != allowed_build_root and allowed_build_root not in work.parents:
            raise ConformanceError("work directory inside the repository must be under build/")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    results: list[dict[str, str]] = []
    if args.phase in {"full", "workspace"}:
        results.append(source_mode(work, args.config, args.platform))
    if args.phase in {"full", "static"}:
        installed_static, relocated_static = prove_install_mode(
            work, "STATIC", args.config, args.platform
        )
        results.extend((installed_static, relocated_static))
        negative_controls(
            work,
            work / "unrelated" / "prefix-b-static",
            args.config,
            args.platform,
        )
    if args.phase in {"full", "shared"}:
        installed_shared, relocated_shared = prove_install_mode(
            work, "SHARED", args.config, args.platform
        )
        results.extend((installed_shared, relocated_shared))
    if args.phase in {"full", "combined"}:
        combined_install(work, args.config, args.platform)
    if not results and args.phase != "combined":
        raise ConformanceError(f"phase {args.phase} produced no normalized result")
    if any(result != EXPECTED for result in results):
        raise ConformanceError("source, installed, and relocated normalized results differ")
    print(json.dumps({
        "combined_install": args.phase in {"full", "combined"},
        "normalized_result": EXPECTED,
        "phase": args.phase,
        "relocatable": args.phase in {"full", "static", "shared"},
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConformanceError as error:
        print(f"cmake-sdk-conformance: {error}", file=sys.stderr)
        raise SystemExit(1)
