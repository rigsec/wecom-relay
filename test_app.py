import os
import time
from unittest.mock import AsyncMock, patch

import pytest
import respx
import httpx
from fastapi.testclient import TestClient

os.environ.setdefault("WECOM_TOKEN", "test_token")
os.environ.setdefault("WECOM_ENCODING_AES_KEY", "A" * 43)  # decodes to 32 zero-bytes
os.environ.setdefault("WECOM_CORP_ID", "test_corp")

from app import _responses, app  # noqa: E402
import app as app_module

client = TestClient(app)

CALLBACK_QS = "?msg_signature=sig&timestamp=1&nonce=abc"


def _event_xml(event, card_type, event_key, task_id, user_id="user1", response_code=""):
    return (
        f"<xml>"
        f"<Event><![CDATA[{event}]]></Event>"
        f"<EventKey><![CDATA[{event_key}]]></EventKey>"
        f"<CardType><![CDATA[{card_type}]]></CardType>"
        f"<TaskId><![CDATA[{task_id}]]></TaskId>"
        f"<FromUserName><![CDATA[{user_id}]]></FromUserName>"
        f"<ResponseCode><![CDATA[{response_code}]]></ResponseCode>"
        f"<SelectedItems></SelectedItems>"
        f"</xml>"
    )


def _post_callback(xml):
    with patch("app.crypt.decrypt_message", return_value=xml):
        return client.post(f"/wechat/callback{CALLBACK_QS}", content="<xml/>")


@pytest.fixture(autouse=True)
def clear_responses():
    _responses.clear()
    yield
    _responses.clear()


# ── Health ────────────────────────────────────────────────────────────────────

def test_health_ok():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "pending": 0}


def test_health_pending_count():
    _responses["x"] = {"task_id": "x", "response": "Yes", "user_id": "u", "received_at": time.time()}
    assert client.get("/health").json()["pending"] == 1


# ── POST /wechat/callback ─────────────────────────────────────────────────────

def test_callback_stores_button_interaction():
    r = _post_callback(_event_xml("template_card_event", "button_interaction", "Yes1", "task1", response_code="abc123"))
    assert r.status_code == 200
    assert "task1" in _responses
    assert _responses["task1"]["response"] == "Yes"
    assert _responses["task1"]["user_id"] == "user1"
    assert _responses["task1"]["code"] == "abc123"


def test_callback_stores_empty_response_code_when_absent():
    _post_callback(_event_xml("template_card_event", "button_interaction", "Yes1", "task1"))
    assert _responses["task1"]["code"] == ""


def test_callback_strips_multi_digit_suffix():
    _post_callback(_event_xml("template_card_event", "button_interaction", "Approve12", "task2"))
    assert _responses["task2"]["response"] == "Approve"


def test_callback_no_digit_suffix_unchanged():
    _post_callback(_event_xml("template_card_event", "button_interaction", "Yes", "task3"))
    assert _responses["task3"]["response"] == "Yes"


def test_callback_unhandled_event_not_stored():
    _post_callback(_event_xml("subscribe", "button_interaction", "Yes1", "task4"))
    assert "task4" not in _responses


def test_callback_wrong_card_type_not_stored():
    _post_callback(_event_xml("template_card_event", "vote_interaction", "Yes1", "task5"))
    assert "task5" not in _responses


def test_callback_empty_task_id_not_stored():
    _post_callback(_event_xml("template_card_event", "button_interaction", "Yes1", ""))
    assert len(_responses) == 0


# ── GET /relay/response/{task_id} ────────────────────────────────────────────

def test_get_response_404_when_missing():
    assert client.get("/relay/response/nonexistent").status_code == 404


def test_get_response_200_when_present():
    _responses["t1"] = {"task_id": "t1", "response": "Yes", "user_id": "u", "received_at": time.time()}
    r = client.get("/relay/response/t1")
    assert r.status_code == 200
    assert r.json()["response"] == "Yes"


# ── DELETE /relay/response/{task_id} ─────────────────────────────────────────

def test_delete_removes_entry():
    _responses["t2"] = {"task_id": "t2", "response": "No", "user_id": "u", "received_at": time.time()}
    assert client.delete("/relay/response/t2").status_code == 204
    assert "t2" not in _responses


def test_delete_missing_is_idempotent():
    assert client.delete("/relay/response/nonexistent").status_code == 204


# ── Auth (RELAY_API_SECRET) ───────────────────────────────────────────────────

def test_no_secret_configured_allows_access():
    _responses["t"] = {"task_id": "t", "response": "Yes", "user_id": "u", "received_at": time.time()}
    with patch("app.RELAY_API_SECRET", ""):
        assert client.get("/relay/response/t").status_code == 200


def test_correct_secret_allows_access():
    _responses["t"] = {"task_id": "t", "response": "Yes", "user_id": "u", "received_at": time.time()}
    with patch("app.RELAY_API_SECRET", "mysecret"):
        assert client.get("/relay/response/t", headers={"x-relay-secret": "mysecret"}).status_code == 200


def test_wrong_secret_returns_401():
    _responses["t"] = {"task_id": "t", "response": "Yes", "user_id": "u", "received_at": time.time()}
    with patch("app.RELAY_API_SECRET", "mysecret"):
        assert client.get("/relay/response/t", headers={"x-relay-secret": "wrong"}).status_code == 401


def test_missing_secret_returns_401():
    _responses["t"] = {"task_id": "t", "response": "Yes", "user_id": "u", "received_at": time.time()}
    with patch("app.RELAY_API_SECRET", "mysecret"):
        assert client.get("/relay/response/t").status_code == 401


# ── _disable_card ─────────────────────────────────────────────────────────────

def test_callback_calls_disable_card_when_credentials_configured():
    with (
        patch("app.WECOM_CORP_SECRET", "secret"),
        patch("app.WECOM_AGENT_ID", 42),
        patch("app._disable_card", new_callable=AsyncMock) as mock_disable,
    ):
        _post_callback(_event_xml("template_card_event", "button_interaction", "Yes1", "t", response_code="rc1"))
        mock_disable.assert_awaited_once_with("rc1", "Yes")



@respx.mock
@pytest.mark.anyio
async def test_disable_card_calls_wecom_apis():
    respx.get("https://qyapi.weixin.qq.com/cgi-bin/gettoken").mock(
        return_value=httpx.Response(200, json={"errcode": 0, "access_token": "tok", "expires_in": 7200})
    )
    respx.post("https://qyapi.weixin.qq.com/cgi-bin/message/interactive/taskcard/update").mock(
        return_value=httpx.Response(200, json={"errcode": 0, "errmsg": "ok"})
    )
    app_module._token_cache = None
    with patch("app.WECOM_CORP_SECRET", "secret"), patch("app.WECOM_AGENT_ID", 42):
        from app import _disable_card
        await _disable_card("rc1", "Yes")

    assert respx.calls.call_count == 2


@respx.mock
@pytest.mark.anyio
async def test_disable_card_uses_token_cache():
    app_module._token_cache = ("cached_tok", time.time() + 3600)
    respx.post("https://qyapi.weixin.qq.com/cgi-bin/message/interactive/taskcard/update").mock(
        return_value=httpx.Response(200, json={"errcode": 0, "errmsg": "ok"})
    )
    with patch("app.WECOM_CORP_SECRET", "secret"), patch("app.WECOM_AGENT_ID", 42):
        from app import _disable_card
        await _disable_card("rc2", "No")

    # gettoken should NOT have been called
    assert respx.calls.call_count == 1
    app_module._token_cache = None


@pytest.mark.anyio
async def test_disable_card_noop_without_credentials():
    with patch("app.WECOM_CORP_SECRET", ""), patch("app.WECOM_AGENT_ID", 0):
        from app import _disable_card
        await _disable_card("rc1", "Yes")  # must not raise or make HTTP calls


@pytest.mark.anyio
async def test_disable_card_noop_without_response_code():
    with patch("app.WECOM_CORP_SECRET", "secret"), patch("app.WECOM_AGENT_ID", 42):
        from app import _disable_card
        await _disable_card("", "Yes")  # empty response_code → noop
