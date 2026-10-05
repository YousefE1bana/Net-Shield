import pytest
from types import SimpleNamespace
from netshield.helper import NftBoundary, MARKER


def test_nonzero_nft_exit_is_not_success(monkeypatch):
    from netshield.helper import execute

    monkeypatch.setattr(
        "netshield.helper.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="", stderr="denied"),
    )
    with pytest.raises(OSError, match="failed"):
        execute(["-f", "-"], "fixed owned operation")


def owned_table():
    objects = [{"table": {"family": "inet", "name": "netshield_v2", "comment": MARKER}}]
    for name, datatype in (("blocked4", "ipv4_addr"), ("blocked6", "ipv6_addr")):
        objects.append({"set": {"name": name, "type": datatype, "flags": ["timeout"], "elem": []}})
    for hook in ("input", "forward"):
        objects.append(
            {"chain": {"name": hook, "hook": hook, "type": "filter", "policy": "accept", "prio": -10}}
        )
        for family, name in (("ip", "blocked4"), ("ip6", "blocked6")):
            objects.append(
                {
                    "rule": {
                        "chain": hook,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"payload": {"protocol": family, "field": "saddr"}},
                                    "right": "@" + name,
                                }
                            },
                            {"counter": {"packets": 0, "bytes": 0}},
                            {"drop": None},
                        ],
                    }
                }
            )
    return {"nftables": objects}


def test_changed_or_foreign_resources_are_never_adopted():
    data = owned_table()
    boundary = NftBoundary(["10.77.0.0/24"], ["10.77.0.1/32"], lambda *_: data)
    assert boundary.inspect()["targets"] == []
    data["nftables"][0]["table"]["comment"] = "Foreign administrator table"
    with pytest.raises(OSError):
        boundary.request("add", "10.77.0.2", 60)
    data = owned_table()
    data["nftables"][-1]["rule"]["expr"] = [{"accept": None}]
    with pytest.raises(OSError):
        boundary.inspect()


@pytest.mark.parametrize("target", ["10.77.0.1", "10.78.0.2", "127.0.0.1", "10.77.0.2; flush ruleset", 123])
def test_helper_independently_rejects_unsafe_targets(target):
    calls = []

    def runner(arguments, input=None):
        calls.append((arguments, input))
        return owned_table()

    boundary = NftBoundary(["10.77.0.0/24"], ["10.77.0.1/32"], runner)
    with pytest.raises(ValueError):
        boundary.request("add", target, 60)
    assert all(input is None for _, input in calls)


def test_removal_keeps_working_when_policy_scope_changes():
    data = owned_table()
    data["nftables"][1]["set"]["elem"] = [{"elem": {"val": "10.78.0.2", "expires": 5000}}]
    calls = []

    def runner(arguments, input=None):
        calls.append(input)
        if input:
            data["nftables"][1]["set"]["elem"] = []
        return data

    boundary = NftBoundary(["10.77.0.0/24"], ["10.77.0.1/32"], runner)
    assert boundary.request("remove", "10.78.0.2")["targets"] == []
    assert "delete element inet netshield_v2 blocked4" in calls[1]


def test_old_nft_json_without_comment_uses_exact_table_level_text_marker():
    data = owned_table()
    del data["nftables"][0]["table"]["comment"]
    calls = []

    def runner(arguments, input=None):
        calls.append(arguments)
        return data if "-j" in arguments else f'table inet netshield_v2 {{\n comment "{MARKER}"\n}}\n'

    boundary = NftBoundary(["10.77.0.0/24"], ["10.77.0.1/32"], runner)
    assert boundary.inspect()["targets"] == []
    assert calls[-1] == ["list", "table", "inet", "netshield_v2"]


@pytest.mark.parametrize(
    "text",
    [
        'table inet netshield_v2 { comment "wrong" }',
        f'table inet netshield_v2 {{ set blocked4 {{ comment "{MARKER}" }} }}',
        f'table inet foreign {{ comment "{MARKER}" }}',
        f'table inet netshield_v2 {{ comment "{MARKER} extra" }}',
        f'table inet netshield_v2 {{ comment "{MARKER}" }} table inet other {{}}',
    ],
)
def test_old_nft_foreign_or_nested_marker_is_refused(text):
    data = owned_table()
    del data["nftables"][0]["table"]["comment"]
    boundary = NftBoundary(
        ["10.77.0.0/24"], ["10.77.0.1/32"], lambda args, *_: data if "-j" in args else text
    )
    with pytest.raises(OSError, match="Foreign"):
        boundary.inspect()


def test_wrong_json_comment_never_falls_back_to_correct_text():
    data = owned_table()
    data["nftables"][0]["table"]["comment"] = "foreign"
    calls = []

    def runner(arguments, input=None):
        calls.append(arguments)
        return data if "-j" in arguments else f'table inet netshield_v2 {{ comment "{MARKER}" }}'

    with pytest.raises(OSError):
        NftBoundary(["10.77.0.0/24"], ["10.77.0.1/32"], runner).inspect()
    assert len(calls) == 1


def test_non_json_nft_stdout_is_preserved(monkeypatch):
    from netshield.helper import execute

    monkeypatch.setattr(
        "netshield.helper.subprocess.run",
        lambda *_a, **_k: SimpleNamespace(returncode=0, stdout="table text", stderr=""),
    )
    assert execute(["list", "table", "inet", "netshield_v2"]) == "table text"
