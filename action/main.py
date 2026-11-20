"""The GitHub Action: inputs in, a contract out, and a summary somebody reads.

This is a wrapper and nothing more. Every decision about what the data becomes
belongs to `opteryx-upload push`, which the SDK, the terminal and this share -
a difference between them is a place where the thing you tested by hand is not
the thing CI does, and that is the whole reason the contract flow exists.

What a wrapper is for is the three things a workflow should not have to write
again in every repository:

* the arguments, built from named inputs rather than a shell string, so a glob
  with a space in it and a type correction with an `=` in it both survive;
* a snapshot message that says which workflow published it, because six months
  later "which run wrote these rows" is the only question anybody asks;
* the step summary, because a plan that is only in the log is a plan nobody
  reads, and the whole point of negotiating first is that somebody looks.

Standard library only, and no import of the package it drives except for one
lookup table of wording. It runs on whatever `python3` the runner has, before
anything has been installed into the job.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

#: Inputs arrive as environment variables set by `action.yml`, not as argv.
#: Credentials are deliberately not among them - those go straight into the
#: environment the CLI reads, so a token never appears in a process list.
PREFIX = "INPUT_"

#: What each plan action does to the data, in the words an operator needs. The
#: same table the terminal output uses; duplicated rather than imported so this
#: file keeps working if it is ever run against a package that predates it.
ACTIONS = {
    "keep": "",
    "retag": "relabelled, no values change",
    "widen": "widened, nothing is lost",
    "cast": "**converted**",
    "unsupported": "stored as read",
    "undeclared": "",
    "ignored": "read and not written",
}

#: The CLI's exit codes, in the words that tell a reader what to do next. The
#: numbers are `opteryx_upload.cli.config`; the advice is the reason they are
#: separate numbers at all, so it belongs next to them.
EXIT_MEANINGS = {
    0: "committed",
    2: "the action was configured wrong, or a file was not found",
    3: "the service refused this upload on its merits - retrying will not help",
    4: "the destination changed after the contract was agreed - re-run to "
    "negotiate against the new definition",
    5: "not signed in, or signed in as somebody who may not write here",
    6: "the upload service could not be reached",
    130: "interrupted; nothing was published",
}


class InputError(Exception):
    """Something the caller fixes in the workflow file."""


# ---------------------------------------------------------------------------
# Reading inputs
# ---------------------------------------------------------------------------


def _raw(name: str, env: Dict[str, str]) -> str:
    return env.get(PREFIX + name.upper().replace("-", "_"), "").strip()


def _lines(name: str, env: Dict[str, str]) -> List[str]:
    """A multi-valued input, one value per line.

    Newlines and not spaces, because every value here can legitimately contain
    a space - a path, and a column name that came out of a spreadsheet.
    """
    return [line.strip() for line in _raw(name, env).splitlines() if line.strip()]


def _flag(name: str, env: Dict[str, str]) -> bool:
    return _raw(name, env).lower() in ("true", "1", "yes", "on")


def _choice(name: str, env: Dict[str, str], allowed: Dict[str, Any], default: str):
    value = _raw(name, env) or default
    if value not in allowed:
        raise InputError(
            f"{name}: expected one of {', '.join(sorted(allowed))}, got {value!r}"
        )
    return allowed[value]


# ---------------------------------------------------------------------------
# The snapshot message
# ---------------------------------------------------------------------------


def default_message(env: Dict[str, str]) -> str:
    """Who published this, said once so nobody has to go looking.

    A snapshot with no message is a row in a history that answers nothing. The
    run URL is the useful half - it survives a deleted branch and leads to the
    log - and the short sha is there for the case where the run has aged out.
    """
    workflow = env.get("GITHUB_WORKFLOW") or "workflow"
    sha = (env.get("GITHUB_SHA") or "")[:7]
    repository = env.get("GITHUB_REPOSITORY")
    run_id = env.get("GITHUB_RUN_ID")
    where = f"{repository}@{sha}" if repository and sha else repository or sha
    message = f"{workflow}" + (f" ({where})" if where else "")
    if repository and run_id:
        server = env.get("GITHUB_SERVER_URL", "https://github.com")
        message += f" {server}/{repository}/actions/runs/{run_id}"
    return message


# ---------------------------------------------------------------------------
# Building the command
# ---------------------------------------------------------------------------

SCHEMA_FLAGS = {"auto": None, "infer": "--infer", "dataset": "--use-dataset"}
MODE_FLAGS = {"append": "--append", "overwrite": "--overwrite"}
AUTH_MODES = {"auto": False, "oidc": True}


def build_argv(env: Dict[str, str], executable: str, result_path: str) -> List[str]:
    """The exact command to run, or an `InputError` naming the input to fix.

    Checked here rather than left to argparse so the message says `mode:` and
    not `--overwrite`: somebody reading it is looking at a YAML file, and the
    flags are an implementation detail of this wrapper.
    """
    files = _lines("files", env)
    if not files:
        raise InputError("files: nothing to upload (one path or glob per line)")
    target = _raw("to", env)
    if not target:
        raise InputError("to: required, as workspace.collection.dataset")

    plan_only = _flag("plan-only", env)
    argv = [executable, "plan" if plan_only else "push", *files, "--to", target]

    declare = _lines("declare", env)
    schema = _choice("schema", env, SCHEMA_FLAGS, "auto")
    if declare:
        if schema is not None:
            raise InputError(
                "declare and schema cannot both be set; declaring the columns IS "
                "the schema source"
            )
        for pair in declare:
            argv += ["--declare", pair]
    elif schema is not None:
        argv.append(schema)

    # The disposition is only sent when it was asked for. An existing dataset
    # appends by default, and saying so explicitly would mean this action could
    # never be told "whatever the dataset already implies".
    mode = _raw("mode", env)
    if mode:
        argv.append(_choice("mode", env, MODE_FLAGS, "append"))

    for pair in _lines("types", env):
        argv += ["--type", pair]
    for column in _lines("ignore", env):
        argv += ["--ignore", column]

    if _choice("auth", env, AUTH_MODES, "auto"):
        argv.append("--oidc")

    url = _raw("url", env)
    if url:
        argv += ["--url", url]

    if not plan_only:
        # An inferred type is never accepted without somebody saying so, and in
        # a workflow there is nobody to ask. `accept-inferred-types` is that
        # somebody, deciding in advance; without it a new dataset is refused
        # rather than catalogued on a guess.
        if _flag("accept-inferred-types", env):
            argv.append("--yes")
        argv += ["-m", _raw("message", env) or default_message(env)]

    argv += ["--output-json", result_path, "--no-color"]
    return argv


def credential_env(env: Dict[str, str]) -> Dict[str, str]:
    """Credentials, moved from inputs to where the CLI looks for them.

    Through the environment and never through argv: a process list is readable
    by anything else in the job, and a masked log does not mask that.
    """
    passed = {}
    for name, variable in (
        ("client-id", "OPTERYX_CLIENT_ID"),
        ("client-secret", "OPTERYX_CLIENT_SECRET"),
        ("token", "OPTERYX_TOKEN"),
        ("auth-url", "OPTERYX_AUTH_URL"),
        ("audience", "OPTERYX_OIDC_AUDIENCE"),
    ):
        value = _raw(name, env)
        if value:
            passed[variable] = value
    return passed


# ---------------------------------------------------------------------------
# The summary
# ---------------------------------------------------------------------------


def _target_of(payload: Dict[str, Any]) -> str:
    target = payload.get("target") or {}
    parts = (target.get("workspace"), target.get("collection"), target.get("dataset"))
    return ".".join(part for part in parts if part)


def _rows(count: Optional[int]) -> str:
    return f"{count:,}" if isinstance(count, int) else "?"


def summary_markdown(
    payload: Optional[Dict[str, Any]], *, plan_only: bool, exit_code: int
) -> str:
    """What happened, as the job summary renders it.

    The sampled value next to each column is the point of the table, the same
    as at a terminal: `published` sitting next to `2026-08-02T04:22:07Z` reads
    as wrong at a glance in a way that `published: VARCHAR` does not. A summary
    without it is a list of type names nobody checks.
    """
    heading = "Opteryx upload plan" if plan_only else "Opteryx upload"
    if payload is None:
        meaning = EXIT_MEANINGS.get(exit_code, f"exit code {exit_code}")
        return f"### {heading}\n\nNothing was negotiated: {meaning}.\n"

    table = _target_of(payload) or "unknown"
    out = [f"### {heading} — `{table}`", ""]

    blocking = any(
        issue.get("severity", "blocking") == "blocking"
        for issue in payload.get("issues") or []
    )
    if plan_only:
        verdict = "would be refused" if blocking else "would be accepted"
        out.append(f"Nothing was uploaded. This plan **{verdict}**.")
    elif exit_code == 0:
        created = len(payload.get("writes") or [])
        out.append(
            f"**Committed** · {_rows(payload.get('rows_written'))} rows · "
            f"{created} file{'' if created == 1 else 's'}"
            + (f" · snapshot `{payload['snapshot']}`" if payload.get("snapshot") else "")
        )
    else:
        out.append(
            f"**Not published** — {EXIT_MEANINGS.get(exit_code, f'exit code {exit_code}')}."
        )
    out.append("")

    values = payload.get("values") or {}
    plan = payload.get("plan") or []
    if plan:
        out += [
            "| column | sample | type | what happens |",
            "| --- | --- | --- | --- |",
        ]
        for entry in plan:
            column = entry.get("column", "")
            sample = str(values.get(column, "")).replace("|", "\\|")[:48]
            arrived = entry.get("to", "")
            note = ACTIONS.get(entry.get("action", ""), entry.get("action", ""))
            out.append(f"| `{column}` | {sample} | {arrived} | {note} |")
        out.append("")

    issues = payload.get("issues") or []
    if issues:
        out.append("**Issues**")
        out.append("")
        for issue in issues:
            mark = "❌" if issue.get("severity", "blocking") == "blocking" else "⚠️"
            column = issue.get("column")
            where = f"`{column}` — " if column else ""
            out.append(f"- {mark} {where}{issue.get('detail') or issue.get('code', '')}")
        out.append("")

    if payload.get("contract_id"):
        out.append(f"<sub>contract `{payload['contract_id']}`</sub>")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Talking to the runner
# ---------------------------------------------------------------------------


def _append(path: Optional[str], text: str) -> None:
    """Add to one of the runner's files, and never fail the job over it.

    A summary that cannot be written is cosmetic. The upload has already
    happened by the time we get here, and turning a committed snapshot into a
    failed job because a file handle was unavailable would be a lie about what
    is in the catalog.
    """
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)
    except OSError as error:
        print(f"::warning::could not write {path}: {error}")


def outputs_for(payload: Optional[Dict[str, Any]], exit_code: int) -> Dict[str, str]:
    """The step outputs, so the next step can act without re-reading anything."""
    blocking = any(
        issue.get("severity", "blocking") == "blocking"
        for issue in (payload or {}).get("issues") or []
    )
    return {
        "exit-code": str(exit_code),
        "table": _target_of(payload or {}),
        "state": str((payload or {}).get("state") or ""),
        "contract-id": str((payload or {}).get("contract_id") or ""),
        "snapshot": str((payload or {}).get("snapshot") or ""),
        "rows": str((payload or {}).get("rows_written") or 0),
        "files": str(len((payload or {}).get("writes") or [])),
        "blocking": "true" if blocking else "false",
        "result": "" if payload is None else json.dumps(payload, separators=(",", ":")),
    }


def write_outputs(values: Dict[str, str], path: Optional[str]) -> None:
    # The heredoc form, because `result` is JSON and a value with a newline in
    # it silently truncates in `name=value`.
    lines = []
    for name, value in values.items():
        lines.append(f"{name}<<__OPTERYX_EOF__\n{value}\n__OPTERYX_EOF__\n")
    _append(path, "".join(lines))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    env = dict(os.environ)
    executable = env.get("OPTERYX_UPLOAD_EXECUTABLE") or "opteryx-upload"
    result_path = os.path.join(env.get("RUNNER_TEMP") or ".", "opteryx-contract.json")
    plan_only = _flag("plan-only", env)

    try:
        command = build_argv(env, executable, result_path)
    except InputError as error:
        print(f"::error::{error}")
        # Outputs are written here too, so a caller with continue-on-error can see the 2.
        write_outputs(outputs_for(None, 2), env.get("GITHUB_OUTPUT"))
        return 2

    child_env = dict(env)
    child_env.update(credential_env(env))
    # Unbuffered, so the per-file lines appear in the log as the upload happens
    # rather than all at once when the step ends.
    child_env["PYTHONUNBUFFERED"] = "1"

    if os.path.exists(result_path):
        os.remove(result_path)

    # Quoted, so the line in the log is the command somebody can paste at a
    # terminal to reproduce it - a snapshot message with spaces in it otherwise
    # reads as four more arguments.
    print(f"::group::opteryx-upload {shlex.join(command[1:])}")
    # Flushed, or the group marker lands in the log after the output it is
    # supposed to be wrapping - the child writes to the same descriptor and
    # does not wait for us.
    sys.stdout.flush()
    exit_code = subprocess.call(command, env=child_env)
    sys.stdout.flush()
    print("::endgroup::")

    payload: Optional[Dict[str, Any]] = None
    if os.path.exists(result_path):
        try:
            with open(result_path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError) as error:
            print(f"::warning::could not read the contract back: {error}")

    write_outputs(outputs_for(payload, exit_code), env.get("GITHUB_OUTPUT"))
    if _flag("summary", env):
        _append(env.get("GITHUB_STEP_SUMMARY"), summary_markdown(
            payload, plan_only=plan_only, exit_code=exit_code
        ))

    if exit_code != 0:
        meaning = EXIT_MEANINGS.get(exit_code, f"exit code {exit_code}")
        print(f"::error::opteryx-upload: {meaning}")
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
