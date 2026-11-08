from app.github_app import event_from_payload, is_analyzable_path


def test_push_event_is_routable() -> None:
    event = event_from_payload("push", {
        "installation": {"id": 42},
        "repository": {"full_name": "safetyguard-labs/demo"},
        "before": "a" * 40,
        "after": "b" * 40,
    })
    assert event is not None
    assert event.installation_id == 42
    assert event.repository == "safetyguard-labs/demo"
    assert event.sha == "b" * 40


def test_pull_request_event_is_routable() -> None:
    event = event_from_payload("pull_request", {
        "action": "synchronize",
        "number": 7,
        "installation": {"id": 42},
        "repository": {"full_name": "safetyguard-labs/demo"},
        "pull_request": {"head": {"sha": "c" * 40}},
    })
    assert event is not None
    assert event.pull_number == 7


def test_irrelevant_event_is_ignored() -> None:
    assert event_from_payload("issues", {
        "installation": {"id": 42},
        "repository": {"full_name": "safetyguard-labs/demo"},
    }) is None


def test_analysis_path_filter_skips_non_runtime_files() -> None:
    assert not is_analyzable_path(".github/workflows/test.yml")
    assert not is_analyzable_path("tests/test_strategy.py")
    assert not is_analyzable_path("docs/example.env")
    assert is_analyzable_path("app/strategy.py")
    assert is_analyzable_path("config/risk.yaml")
