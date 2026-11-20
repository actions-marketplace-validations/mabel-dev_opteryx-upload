"""The GitHub Action wrapper: inputs in, a command and a summary out.

Two things are worth testing here. The command, because a wrong flag in a
workflow is discovered by a nightly job writing the wrong thing to a catalog,
and because the arguments it builds are the whole reason the wrapper exists -
a glob with a space in it and a type correction with an `=` in it have to
survive the trip.

And the refusal to accept inferred types without being told to. That rule is
enforced by the client, not here, but here is where a wrapper would be tempted
to be helpful and pass `--yes` for everybody, so it gets a test that says the
flag is only ever sent when somebody asked for it.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import stat
import sys

import pytest

ACTION = pathlib.Path(__file__).resolve().parent.parent / "action" / "main.py"


def _load():
    spec = importlib.util.spec_from_file_location("opteryx_upload_action", ACTION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


action = _load()


def inputs(**values):
    """Inputs as `action.yml` passes them: `INPUT_` + the name, underscored."""
    return {f"INPUT_{name.upper().replace('-', '_')}": value for name, value in values.items()}


def argv(**values):
    env = {"INPUT_FILES": "f.csv", "INPUT_TO": "acme.security.findings"}
    env.update(inputs(**values))
    return action.build_argv(env, "opteryx-upload", "/tmp/result.json")


# ---------------------------------------------------------------------------


class TestTheCommand:
    def test_the_minimum_is_a_push_to_a_target(self):
        assert argv()[:5] == ["opteryx-upload", "push", "f.csv", "--to", "acme.security.findings"]

    def test_both_required_inputs_name_themselves_when_missing(self):
        with pytest.raises(action.InputError) as raised:
            action.build_argv({"INPUT_TO": "a.b.c"}, "x", "r")
        assert "files" in str(raised.value)
        with pytest.raises(action.InputError) as raised:
            action.build_argv({"INPUT_FILES": "f.csv"}, "x", "r")
        assert "to" in str(raised.value)

    def test_files_are_split_on_newlines_so_a_path_may_contain_a_space(self):
        command = argv(files="my data/a.parquet\nother/b.csv\n\n")
        assert command[2:4] == ["my data/a.parquet", "other/b.csv"]

    def test_a_glob_is_passed_through_rather_than_expanded_here(self):
        # The client expands it, which is the only place that knows a pattern
        # matching nothing is an error worth stopping for.
        assert "data/**/*.parquet" in argv(files="data/**/*.parquet")

    def test_plan_only_negotiates_and_abandons(self):
        command = argv(**{"plan-only": "true"})
        assert command[1] == "plan"
        # `plan` has neither of these, and sending them would be a usage error
        assert "-m" not in command and "--yes" not in command

    def test_the_result_is_always_written_somewhere_machine_readable(self):
        command = argv()
        assert command[command.index("--output-json") + 1] == "/tmp/result.json"


class TestInferredTypes:
    """The one rule the whole design exists for, from a workflow's side."""

    def test_nothing_is_accepted_unasked(self):
        assert "--yes" not in argv()

    def test_it_is_sent_only_when_somebody_decided_in_advance(self):
        assert "--yes" in argv(**{"accept-inferred-types": "true"})

    @pytest.mark.parametrize("value", ["false", "", "no", "False"])
    def test_anything_short_of_yes_is_no(self, value):
        assert "--yes" not in argv(**{"accept-inferred-types": value})


class TestSchemaSource:
    def test_auto_says_nothing_and_lets_the_destination_answer(self):
        command = argv()
        assert "--infer" not in command and "--use-dataset" not in command

    def test_each_source_maps_to_the_flag_that_means_it(self):
        assert "--infer" in argv(schema="infer")
        assert "--use-dataset" in argv(schema="dataset")

    def test_declaring_the_columns_is_one_flag_per_column(self):
        command = argv(declare="cve_id:VARCHAR\nsource_ip:IPV4")
        assert command.count("--declare") == 2
        assert "source_ip:IPV4" in command

    def test_declaring_and_naming_a_schema_source_is_refused_not_guessed(self):
        # They are mutually exclusive at the client too; caught here so the
        # message talks about the inputs rather than about argparse.
        with pytest.raises(action.InputError) as raised:
            argv(schema="infer", declare="a:VARCHAR")
        assert "declare" in str(raised.value)

    def test_an_unknown_value_lists_what_it_wanted(self):
        with pytest.raises(action.InputError) as raised:
            argv(schema="guess")
        assert "auto" in str(raised.value)

    def test_corrections_and_drops_are_one_flag_each(self):
        command = argv(types="published=TIMESTAMP\nsource_ip=IPV4", ignore="internal_id")
        assert command.count("--type") == 2
        assert command.count("--ignore") == 1
        assert "published=TIMESTAMP" in command


class TestDisposition:
    def test_saying_nothing_lets_the_destination_imply_it(self):
        command = argv()
        assert "--append" not in command and "--overwrite" not in command

    def test_overwrite_has_to_be_asked_for_by_name(self):
        assert "--overwrite" in argv(mode="overwrite")
        assert "--append" in argv(mode="append")

    def test_a_typo_does_not_silently_append(self):
        with pytest.raises(action.InputError):
            argv(mode="replace")


class TestCredentials:
    def test_oidc_is_the_default_path_and_needs_no_input(self):
        # Nothing is passed; the client authenticates as the workflow because
        # there is no other credential to find.
        assert action.credential_env(inputs()) == {}

    def test_demanding_oidc_is_a_flag_rather_than_a_hope(self):
        assert "--oidc" in argv(auth="oidc")
        assert "--oidc" not in argv(auth="auto")

    def test_an_access_token_travels_in_the_environment_never_in_argv(self):
        env = inputs(**{"client-id": "id", "client-secret": "shhh"})
        assert action.credential_env(env) == {
            "OPTERYX_CLIENT_ID": "id",
            "OPTERYX_CLIENT_SECRET": "shhh",
        }
        assert "shhh" not in " ".join(argv(**{"client-secret": "shhh"}))

    def test_the_service_urls_are_environment_too(self):
        env = inputs(**{"auth-url": "https://auth.test", "audience": "https://aud.test"})
        assert action.credential_env(env) == {
            "OPTERYX_AUTH_URL": "https://auth.test",
            "OPTERYX_OIDC_AUDIENCE": "https://aud.test",
        }


class TestTheSnapshotMessage:
    def test_it_says_which_run_published_the_rows(self):
        message = action.default_message(
            {
                "GITHUB_WORKFLOW": "nightly",
                "GITHUB_REPOSITORY": "acme/data",
                "GITHUB_SHA": "0123456789abcdef",
                "GITHUB_RUN_ID": "42",
                "GITHUB_SERVER_URL": "https://github.com",
            }
        )
        assert "nightly" in message
        assert "acme/data@0123456" in message
        assert "https://github.com/acme/data/actions/runs/42" in message

    def test_one_given_on_purpose_is_used_as_written(self):
        command = argv(message="Q3 reload")
        assert command[command.index("-m") + 1] == "Q3 reload"

    def test_there_is_always_one(self):
        # A snapshot with no message is a row in a history that answers nothing.
        assert action.default_message({}).strip()
        assert argv()[argv().index("-m") + 1]


# ---------------------------------------------------------------------------
# The summary and the outputs
# ---------------------------------------------------------------------------

COMMITTED = {
    "contract_id": "ct_1",
    "state": "committed",
    "target": {"workspace": "acme", "collection": "security", "dataset": "findings"},
    "plan": [
        {"column": "cve_id", "from": "VARCHAR", "to": "VARCHAR", "action": "keep"},
        {"column": "source_ip", "from": "VARCHAR", "to": "IPV4", "action": "cast"},
    ],
    "values": {"cve_id": "CVE-1", "source_ip": "10.4.19.7"},
    "issues": [],
    "writes": [{"source": "findings.csv", "rows": 2}],
    "rows_written": 1234567,
    "snapshot": "snap_1",
}

REFUSED = dict(
    COMMITTED,
    state="proposed",
    snapshot=None,
    rows_written=0,
    writes=[],
    issues=[{"code": "value_not_castable", "column": "source_ip", "detail": "not an IPV4",
             "severity": "blocking"}],
)


class TestSummary:
    def test_the_sampled_value_is_in_the_table(self):
        # The point of the table, the same as at a terminal: `source_ip` next to
        # a dotted quad reads as wrong at a glance in a way that a type name
        # alone does not.
        text = action.summary_markdown(COMMITTED, plan_only=False, exit_code=0)
        assert "10.4.19.7" in text
        assert "`source_ip`" in text

    def test_a_commit_reports_what_landed(self):
        text = action.summary_markdown(COMMITTED, plan_only=False, exit_code=0)
        assert "1,234,567 rows" in text
        assert "snap_1" in text
        assert "Committed" in text

    def test_a_conversion_is_the_line_worth_noticing(self):
        text = action.summary_markdown(COMMITTED, plan_only=False, exit_code=0)
        assert "**converted**" in text
        assert "relabelled" not in text

    def test_a_blocking_issue_is_marked_as_one(self):
        text = action.summary_markdown(REFUSED, plan_only=False, exit_code=3)
        assert "not an IPV4" in text
        assert "Not published" in text
        assert "retrying will not help" in text

    def test_a_plan_says_it_uploaded_nothing(self):
        text = action.summary_markdown(COMMITTED, plan_only=True, exit_code=0)
        assert "Nothing was uploaded" in text
        assert "would be accepted" in text
        assert action.summary_markdown(REFUSED, plan_only=True, exit_code=3).count(
            "would be refused"
        )

    def test_a_pipe_in_a_sampled_value_does_not_break_the_table(self):
        payload = dict(COMMITTED, values={"cve_id": "a|b", "source_ip": ""})
        assert "a\\|b" in action.summary_markdown(payload, plan_only=False, exit_code=0)

    def test_nothing_negotiated_still_says_why(self):
        text = action.summary_markdown(None, plan_only=False, exit_code=5)
        assert "may not write here" in text


class TestOutputs:
    def test_the_next_step_gets_what_it_needs_without_re_reading_anything(self):
        values = action.outputs_for(COMMITTED, 0)
        assert values["table"] == "acme.security.findings"
        assert values["snapshot"] == "snap_1"
        assert values["rows"] == "1234567"
        assert values["files"] == "1"
        assert values["contract-id"] == "ct_1"
        assert values["blocking"] == "false"
        assert values["exit-code"] == "0"

    def test_blocking_is_the_services_decision_carried_through(self):
        assert action.outputs_for(REFUSED, 3)["blocking"] == "true"

    def test_a_failure_before_any_contract_still_sets_every_output(self):
        values = action.outputs_for(None, 6)
        assert set(values) == set(action.outputs_for(COMMITTED, 0))
        assert values["exit-code"] == "6"
        assert values["rows"] == "0"

    def test_json_is_written_in_the_form_a_newline_survives(self, tmp_path):
        # `name=value` silently truncates at the first newline, and `result` is
        # a whole contract.
        path = tmp_path / "out"
        action.write_outputs({"result": '{"a":\n1}'}, str(path))
        written = path.read_text()
        assert "result<<__OPTERYX_EOF__" in written
        assert written.rstrip().endswith("__OPTERYX_EOF__")

    def test_an_unwritable_file_warns_and_does_not_raise(self, capsys, tmp_path):
        # The upload has already happened; losing the summary must not turn a
        # committed snapshot into a failed job.
        action._append(str(tmp_path / "nope" / "deeper" / "x"), "text")
        assert "::warning::" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# End to end, with the client stood in for
# ---------------------------------------------------------------------------


FAKE = """#!{python}
import json, os, sys
args = sys.argv[1:]
open(os.environ["FAKE_ARGV"], "w").write(json.dumps(args))
if "--output-json" in args and os.environ.get("FAKE_PAYLOAD"):
    with open(args[args.index("--output-json") + 1], "w") as handle:
        handle.write(os.environ["FAKE_PAYLOAD"])
sys.exit(int(os.environ.get("FAKE_EXIT", "0")))
"""


@pytest.fixture
def runner(tmp_path, monkeypatch):
    """A stand-in for the client that records its arguments and exits as told."""
    if sys.platform.startswith("win"):  # pragma: no cover
        pytest.skip("the stand-in relies on a shebang")
    fake = tmp_path / "fake-opteryx-upload"
    fake.write_text(FAKE.format(python=sys.executable))
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)

    recorded = tmp_path / "argv.json"
    monkeypatch.setenv("FAKE_ARGV", str(recorded))
    monkeypatch.setenv("OPTERYX_UPLOAD_EXECUTABLE", str(fake))
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "github-output"))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "github-summary"))
    monkeypatch.setenv("INPUT_FILES", "f.csv")
    monkeypatch.setenv("INPUT_TO", "acme.security.findings")
    monkeypatch.setenv("INPUT_SUMMARY", "true")

    class Runner:
        output = tmp_path / "github-output"
        summary = tmp_path / "github-summary"

        def __call__(self, payload=COMMITTED, exit_code=0, **env):
            monkeypatch.setenv("FAKE_EXIT", str(exit_code))
            if payload is None:
                monkeypatch.delenv("FAKE_PAYLOAD", raising=False)
            else:
                monkeypatch.setenv("FAKE_PAYLOAD", json.dumps(payload))
            for name, value in inputs(**env).items():
                monkeypatch.setenv(name, value)
            return action.main()

        @property
        def argv(self):
            return json.loads(recorded.read_text())

    return Runner()


class TestEndToEnd:
    def test_a_commit_sets_the_outputs_and_the_summary(self, runner):
        assert runner() == 0
        assert "snapshot<<" in runner.output.read_text()
        assert "snap_1" in runner.output.read_text()
        assert "acme.security.findings" in runner.summary.read_text()

    def test_the_clients_exit_code_is_the_steps_exit_code(self, runner):
        # A pipeline branches on these, so the wrapper must not flatten them.
        assert runner(payload=REFUSED, exit_code=3) == 3
        assert "exit-code<<__OPTERYX_EOF__\n3" in runner.output.read_text()

    def test_a_failure_is_annotated_so_it_shows_without_opening_the_log(
        self, runner, capsys
    ):
        runner(payload=None, exit_code=5)
        assert "::error::" in capsys.readouterr().out

    def test_a_stale_contract_tells_the_reader_to_re_run(self, runner, capsys):
        runner(payload=None, exit_code=4)
        assert "re-run" in capsys.readouterr().out

    def test_a_result_from_a_previous_step_is_not_reported_as_this_ones(
        self, runner, tmp_path
    ):
        # Two uploads in one job share `RUNNER_TEMP`. Reading a stale file back
        # would report the first commit's snapshot as the second's.
        runner()
        assert runner(payload=None, exit_code=6) == 6
        assert "snap_1" not in runner.output.read_text().split("exit-code")[-1]

    def test_misconfiguration_fails_before_the_client_is_run(self, runner, monkeypatch):
        monkeypatch.setenv("INPUT_SCHEMA", "guess")
        assert runner() == 2
        assert not os.path.exists(os.environ["FAKE_ARGV"])

    def test_the_summary_can_be_turned_off(self, runner):
        runner(summary="false")
        assert not runner.summary.exists()
