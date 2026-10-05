import json

import pytest

from bastionfuse.policy import PolicyError, load_policy, policy_from_dict
from conftest import TOKEN, pol


def test_minimal_policy_defaults(fuse_home):
    p = policy_from_dict(pol())
    assert p.mode == "kill"
    assert p.kill_file == fuse_home / "KILL"
    assert p.state_dir == fuse_home
    assert "Read" in p.labels["read_only"]
    # built-in budgets log only until the operator writes them
    assert p.budgets["calls"].action == "shadow"
    assert p.repeat.action == "shadow"


def test_operator_budget_enforces():
    p = policy_from_dict(pol(budgets={"egress": {"max": 3, "window_s": 60},
                                      "tools": {"send_email": {"max": 1, "window_s": 3600}}}))
    assert p.budgets["egress"].action == "enforce"
    assert p.budgets["calls"].action == "shadow"
    assert p.tool_budgets["send_email"].max == 1


@pytest.mark.parametrize("obj, msg", [
    ([], "mapping"),
    ({"fuse": {}}, "policy_version"),
    ({"policy_version": True, "fuse": {}}, "policy_version"),
    ({"policy_version": 2}, "fuse:` block is required"),
    ({"policy_version": 2, "fuse": []}, "must be a mapping"),
    ({"policy_version": 2, "mode": "kill"}, "move ['mode']"),
    ({"policy_version": 2, "fuse": {}, "zzz": 1}, "unknown top-level"),
    (pol(nope=1), "unknown key(s) in `fuse:`"),
    (pol(mode="explode"), "mode"),
    (pol(honeytokens=["short"]), "12-256"),
    (pol(honeytokens=["has space in it ok"]), "whitespace"),
    (pol(honeytokens="notalist"), "list of non-empty strings"),
    (pol(budgets={"egress": {"max": 0, "window_s": 60}}), "egress.max"),
    (pol(budgets={"egress": {"max": True, "window_s": 60}}), "egress.max"),
    (pol(budgets={"egress": {"max": 1, "window_s": 999999}}), "window_s"),
    (pol(budgets={"egress": {"max": 1}}), "max: N, window_s"),
    (pol(budgets={"bogus": {"max": 1, "window_s": 1}}), "budgets` keys"),
    (pol(budgets={"tools": []}), "budgets.tools"),
    (pol(labels={"read_only": ["X"], "egress": ["X"]}), "both read_only and egress"),
    (pol(labels={"weird": []}), "fuse.labels"),
    (pol(canary_tools=["Read"]), "cannot also be read_only"),
    (pol(repeat={"max": 5, "window_s": 10, "action": "maybe"}), "repeat.action"),
    (pol(repeat={"max": 1, "window_s": 10}), "repeat.max"),
    (pol(heartbeat={"file": "x"}), "heartbeat"),
    (pol(self_protect="yes"), "true or false"),
    (pol(commands={"egress": [""]}), "commands.egress"),
    (pol(kill_env=""), "kill_env"),
], ids=lambda x: str(x)[:20] if not isinstance(x, (dict, list)) else None)
def test_rejects(obj, msg):
    with pytest.raises(PolicyError) as e:
        policy_from_dict(obj)
    assert msg in str(e.value)


def test_other_blocks_ignored():
    p = policy_from_dict({"policy_version": 2, "gate": {"anything": 1}, "default": "allow", "fuse": {}})
    assert p.mode == "kill"


def test_tokens_from_env_and_planted(fuse_home, monkeypatch):
    monkeypatch.setenv("MY_TOKENS", "ghp_FUSEdecoy1234567890, sk-fuse-decoy-abcdefgh")
    fuse_home.mkdir()
    (fuse_home / "honeytokens.txt").write_text(f"# planted\n{TOKEN}\n", encoding="utf-8")
    (fuse_home / "decoys.txt").write_text("/tmp/.env.backup\n", encoding="utf-8")
    p = policy_from_dict(pol(honeytokens_env="MY_TOKENS", honeytokens=[TOKEN]))
    assert p.honeytokens == (TOKEN, "ghp_FUSEdecoy1234567890", "sk-fuse-decoy-abcdefgh")
    assert p.decoy_paths == ("/tmp/.env.backup",)


def test_bad_env_token_rejected(monkeypatch):
    monkeypatch.setenv("BASTIONFUSE_HONEYTOKENS", "tiny")
    with pytest.raises(PolicyError, match="BASTIONFUSE_HONEYTOKENS"):
        policy_from_dict(pol())


def test_too_many_tokens(monkeypatch):
    listed = [f"tok-{i:012d}" for i in range(256)]
    assert len(policy_from_dict(pol(honeytokens=listed)).honeytokens) == 256
    monkeypatch.setenv("BASTIONFUSE_HONEYTOKENS", "tok-extra-000000001")
    with pytest.raises(PolicyError, match="at most 256"):
        policy_from_dict(pol(honeytokens=listed))


def test_load_json_and_cache(tmp_path, fuse_home):
    f = tmp_path / "fuse.json"
    f.write_text(json.dumps(pol(mode="degrade")), encoding="utf-8")
    assert load_policy(f).mode == "degrade"
    cache = json.loads((fuse_home / "policy-cache.json").read_text(encoding="utf-8"))
    assert cache["raw"]["fuse"]["mode"] == "degrade"
    # an edit changes the hash: the cache never serves stale policy
    f.write_text(json.dumps(pol(mode="pause")), encoding="utf-8")
    assert load_policy(f).mode == "pause"
    assert load_policy(f).source == f.resolve()


def test_load_yaml(tmp_path):
    f = tmp_path / "fuse.yaml"
    f.write_text("policy_version: 2\nfuse:\n  mode: pause\n", encoding="utf-8")
    assert load_policy(f, cache=False).mode == "pause"


def test_load_errors(tmp_path):
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid JSON"):
        load_policy(bad)
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("a: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid YAML"):
        load_policy(bad_yaml)


def test_yaml_without_pyyaml(tmp_path, monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "yaml":
            raise ImportError("no yaml")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    f = tmp_path / "fuse.yaml"
    f.write_text("policy_version: 2\nfuse: {}\n", encoding="utf-8")
    with pytest.raises(PolicyError, match=r"bastionfuse\[yaml\]"):
        load_policy(f, cache=False)
