import collections
import enum
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import typing
import zipfile

import attrs
import cattrs
import cattrs.preconf.json
import rich.progress
import typer

converter = cattrs.preconf.json.make_converter()

app = typer.Typer(
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

testcases_path = pathlib.Path("testcases").absolute()
testcasesupport_path = pathlib.Path("testcasesupport").absolute()
doc_path = pathlib.Path("doc").absolute()
juliet_path = doc_path / "2022-08-11-juliet-c-cplusplus-v1-3-1-with-extra-support.zip"
sarifs_path = pathlib.Path("sarifs.json").absolute()
manifest_path = pathlib.Path("manifest.json").absolute()


def get_testcase_name(
    artifacts: list[pathlib.Path],
    pattern: re.Pattern[str] = re.compile(r"(?P<name>.*_\d+).*$"),
) -> pathlib.Path:
    """
    Get testcase name from list of artifacts.
    """
    s = set[str]()
    for artifact in artifacts:
        assert (m := pattern.match(artifact.stem)) is not None, artifact.stem
        s.add(m.group("name"))
    (e,) = s
    return artifact.parent / e


def copy_testcases(juliet: zipfile.ZipFile, uri: str) -> typing.Optional[pathlib.Path]:
    """
    Extract the testcase file and modify bind() to ::bind() for C++ source.
    """
    uri: pathlib.Path = pathlib.Path(uri)
    parts = uri.parts
    try:
        idx = parts.index("testcases")
        path = pathlib.Path(*parts[idx:])
        path.parent.mkdir(parents=True, exist_ok=True)
        with juliet.open(str(uri), "r") as input:
            with open(path, "wb") as output:
                data = input.read()
                if uri.suffix == ".cpp":
                    data = data.replace(b"bind", b"::bind")
                output.write(data)
        return path
    except ValueError:
        return None


class Target(str, enum.Enum):
    HOST = "host"
    AARCH64 = "aarch64"
    MORELLO_HYBRID = "morello-hybrid"
    MORELLO_PURECAP = "morello-purecap"
    RISCV64 = "riscv64"
    RISCV64_HYBRID = "riscv64-hybrid"
    RISCV64_PURECAP = "riscv64-purecap"


@attrs.define(frozen=True)
class Result:
    uri: str
    startLine: int


@attrs.define(frozen=True, order=True)
class TestCase:
    id: int
    version: str = attrs.field(eq=False, order=False)
    language: str = attrs.field(eq=False, order=False)
    path: pathlib.Path = attrs.field(eq=False, order=False)
    separate: bool = attrs.field(eq=False, order=False)
    artifacts: list[pathlib.Path] = attrs.field(eq=False, order=False)
    results: dict[str, list[Result]] = attrs.field(eq=False, order=False)


@attrs.define
class Manifest:
    testcases: dict[int, TestCase]
    cwes: dict[str, set[int]]


@app.command()
def populate():
    """
    Populate the testcases directory and generate manifest.json.
    """
    testcases = dict[int, TestCase]()
    cwes = collections.defaultdict[str, set[int]](set)
    with zipfile.ZipFile(juliet_path) as juliet:
        if sarifs_path.exists():
            with open(sarifs_path) as sarifs_file:
                sarifs = json.load(sarifs_file)
        else:
            with juliet.open("sarifs.json") as sarifs_file:
                sarifs = json.load(sarifs_file)
            with open(sarifs_path, "w") as sarifs_file:
                json.dump(sarifs, sarifs_file, indent=2)
        for testcase in rich.progress.track(
            sarifs["testCases"],
            "populating testcases",
        ):
            # identifier = testcase["identifier"]
            sarif = testcase["sarif"]
            runs = sarif["runs"]
            (run,) = runs
            properties = run["properties"]
            artifacts = run["artifacts"]
            results = run["results"]
            artifacts_path: list[pathlib.Path] = [
                path
                for artifact in artifacts
                if (uri := artifact["location"]["uri"])
                if (path := copy_testcases(juliet, uri))
            ]
            tc = TestCase(
                id=properties["id"],
                version=properties["version"],
                language=properties["language"],
                path=get_testcase_name(artifacts_path),
                separate=any(map(lambda p: p.stem.endswith("_good1"), artifacts_path)),
                artifacts=artifacts_path,
                results={
                    result["ruleId"]: [
                        Result(
                            uri=physicalLocation["artifactLocation"]["uri"],
                            startLine=physicalLocation["region"]["startLine"],
                        )
                        for location in result["locations"]
                        if (physicalLocation := location["physicalLocation"])
                    ]
                    for result in results
                },
            )
            testcases[properties["id"]] = tc
            for k in tc.results.keys():
                cwes[k].add(properties["id"])
    manifest = Manifest(testcases=testcases, cwes=cwes)
    with open(manifest_path, "w") as sarifs_file:
        sarifs_file.write(converter.dumps(manifest, indent=2))


@app.command()
def generate(
    cwes: typing.Annotated[
        typing.Optional[list[int]],
        typer.Argument(
            help="CWE numbers. Default all CWEs.",
            callback=lambda cwes: cwes or [],
        ),
    ] = None,
    ignore_windows: typing.Annotated[
        bool,
        typer.Option("--ignore-windows", "-w", help="Ignore window files."),
    ] = True,
    ignore_wchar: typing.Annotated[
        bool,
        typer.Option("--ignore-wchar", "-c", help="Ignore wchat_t files."),
    ] = True,
    baseline: typing.Annotated[
        bool,
        typer.Option("--baseline", "-b", help="Build baseline version."),
    ] = False,
    exclude: typing.Annotated[
        typing.Optional[list[int]],
        typer.Option(
            "--exclude",
            "-x",
            help="Exclude CWE numbers. Default none.",
            callback=lambda cwes: cwes or [],
        ),
    ] = None,
):
    """
    Generate CMakeLists.txt for given CWEs.
    """
    with open("manifest.json") as file:
        manifest = converter.loads(file.read(), Manifest)
    if cwes:
        cwes: set[str] = set(map(lambda cwe: f"CWE-{cwe}", cwes))
    else:
        cwes: set[str] = set(manifest.cwes.keys())
    if exclude:
        exclude: set[str] = set(map(lambda cwe: f"CWE-{cwe}", exclude))
    else:
        exclude: set[str] = set()
    cm: list[str] = [
        """\
cmake_minimum_required(VERSION 3.15...4.1)
project(juliet
    VERSION 1.3.1
    DESCRIPTION "Juliet C/C++"
    LANGUAGES C CXX
)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_COLOR_DIAGNOSTICS ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED On)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED On)
set(CMAKE_CXX_EXTENSIONS ON)
add_compile_options(-g -O0 -fno-omit-frame-pointer)
add_link_options(-fuse-ld=lld)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
""",
        f"add_library(support STATIC {' '.join(map(str, testcasesupport_path.glob('*')))})",
    ]
    cwe_tc: collections.defaultdict[str, set[TestCase]] = collections.defaultdict(set)
    for tc in rich.progress.track(
        manifest.testcases.values(),
        "generating targets for testcases",
    ):
        if tc.results.keys().isdisjoint(cwes) or not tc.results.keys().isdisjoint(
            exclude
        ):
            continue
        if ignore_windows and any("w32" in artifact.name for artifact in tc.artifacts):
            continue
        if ignore_wchar and any(
            "wchar_t" in artifact.name or "wchar_t" in data
            for artifact in tc.artifacts
            if (file := open(artifact))
            if (data := file.read())
            if (file.close() or True)
        ):
            continue
        if baseline and not tc.path.name.endswith("_01"):
            continue
        for cwe in tc.results.keys():
            cwe_tc[cwe].add(tc)
        if tc.separate:
            cm.append(f"add_executable({tc.path.name}-bad {str(tc.path)}_bad.cpp)")
            cm.append(f"add_executable({tc.path.name}-good {str(tc.path)}_good1.cpp)")
        else:
            cm.append(
                f"add_executable({tc.path.name}-bad {' '.join(map(str, tc.artifacts))})"
            )
            cm.append(
                f"add_executable({tc.path.name}-good {' '.join(map(str, tc.artifacts))})"
            )
        cm.append(f"""\
target_compile_definitions({tc.path.name}-bad PUBLIC INCLUDEMAIN OMITGOOD)
target_include_directories({tc.path.name}-bad PUBLIC {str(testcasesupport_path)})
target_link_libraries({tc.path.name}-bad PUBLIC support pthread m)
set_target_properties({tc.path.name}-bad
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${{CMAKE_BINARY_DIR}}/bin/{str(pathlib.Path(*tc.path.parts[1:-1]))}"
)
target_compile_definitions({tc.path.name}-good PUBLIC INCLUDEMAIN OMITBAD)
target_include_directories({tc.path.name}-good PUBLIC {str(testcasesupport_path)})
target_link_libraries({tc.path.name}-good PUBLIC support pthread m)
set_target_properties({tc.path.name}-good
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${{CMAKE_BINARY_DIR}}/bin/{str(pathlib.Path(*tc.path.parts[1:-1]))}"
)
""")
    for cwe, testcases in rich.progress.track(
        cwe_tc.items(),
        "generating targets for CWEs",
    ):
        if cwe not in cwes:
            continue
        cm.append(f"""\
add_custom_target({cwe}-bad
    DEPENDS {" ".join([f"{tc.path.name}-bad" for tc in testcases])}
)
add_custom_target({cwe}-good
    DEPENDS {" ".join([f"{tc.path.name}-good" for tc in testcases])}
)
add_custom_target({cwe}
    DEPENDS {cwe}-bad {cwe}-good
)
""")
    with open("CMakeLists.txt", "w") as file:
        file.write("\n".join(cm))
    cwe_tc: dict[str, list[TestCase]] = {
        cwe: sorted(list(cwe_tc[cwe]))
        for cwe in sorted(cwe_tc.keys(), key=lambda cwe: int(cwe[4:]))
    }
    with open("testcases.json", "w") as file:
        file.write(converter.dumps(cwe_tc, indent=2))


@app.command()
def config(
    target: typing.Annotated[
        Target,
        typer.Option("--target", "-t"),
    ] = Target.HOST,
    cc: typing.Annotated[
        typing.Optional[str],
        typer.Option(
            envvar="CC",
            callback=lambda value: value or shutil.which("cc"),
        ),
    ] = None,
    cxx: typing.Annotated[
        typing.Optional[str],
        typer.Option(
            envvar="CXX",
            callback=lambda value: value or shutil.which("c++"),
        ),
    ] = None,
    sysroot: typing.Annotated[
        typing.Optional[pathlib.Path],
        typer.Option(envvar="SYSROOT"),
    ] = None,
    build_path: typing.Annotated[
        pathlib.Path,
        typer.Option("--build-dir", "-b"),
    ] = pathlib.Path("build"),
):
    if cc is None:
        typer.echo("cc not found")
        raise typer.Exit(code=1)
    if cxx is None:
        typer.echo("c++ not found")
        raise typer.Exit(code=1)
    if (cmake := shutil.which("cmake")) is None:
        typer.echo("cmake not found")
        raise typer.Exit(code=1)
    flags: list[str] = []
    if target == Target.HOST:
        pass
    elif target == Target.AARCH64:
        flags.append("-target aarch64-unknown-freebsd")
        flags.append("-march=morello+noa64c -mabi=aapcs")
    elif target == Target.MORELLO_HYBRID:
        flags.append("-target aarch64-unknown-freebsd")
        flags.append("-march=morello -mabi=aapcs -Xclang -morello-vararg=new")
    elif target == Target.MORELLO_PURECAP:
        flags.append("-target aarch64-unknown-freebsd")
        flags.append("-march=morello -mabi=purecap -Xclang -morello-vararg=new")
    elif target == Target.RISCV64:
        flags.append("-target riscv64-unknown-freebsd")
        flags.append("-march=rv64gc -mabi=lp64d -mno-relax")
    elif target == Target.RISCV64:
        flags.append("-target riscv64-unknown-freebsd")
        flags.append("-march=rv64gcxcheri -mabi=lp64d -mno-relax")
    elif target == Target.RISCV64:
        flags.append("-target riscv64-unknown-freebsd")
        flags.append("-march=rv64gcxcheri -mabi=l64pc128d -mno-relax")
    else:
        raise RuntimeError("unreachable path")
    if sysroot is not None:
        flags.append(f"--sysroot {str(pathlib.Path(sysroot).expanduser())}")
    cmake_args = shlex.split(
        " ".join(
            [
                f"{cmake}",
                f"-B {pathlib.Path(build_path).expanduser()}",
                f"-S {pathlib.Path.cwd()}",
            ]
        )
    )
    shutil.rmtree(pathlib.Path(build_path).expanduser(), ignore_errors=True)
    os.environ["CC"] = str(pathlib.Path(cc).expanduser())
    os.environ["CXX"] = str(pathlib.Path(cxx).expanduser())
    os.environ["CFLAGS"] = f"{os.environ.get('CFLAGS', '')} {' '.join(flags)}"
    os.environ["CXXFLAGS"] = f"{os.environ.get('CXXFLAGS', '')} {' '.join(flags)}"
    typer.echo(f">>> {' '.join(cmake_args)}")
    proc = subprocess.Popen(args=cmake_args, env=os.environ)
    assert proc.wait() == 0, proc


if __name__ == "__main__":
    app()
