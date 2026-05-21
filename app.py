"""WeCom Relay — public-facing callback receiver for SOARAI's wecom-ask feature.

Receives WeCom button_interaction template_card_event callbacks, stores the
response keyed by task_id, and exposes a polling endpoint so the internal
SOARAI service can retrieve results without needing a public IP.

Environment variables (required):
  WECOM_TOKEN             — callback token from WeCom admin console
  WECOM_ENCODING_AES_KEY  — 43-char AES key from WeCom admin console
  WECOM_CORP_ID           — enterprise corp ID

Environment variables (optional):
  RELAY_API_SECRET        — shared secret for the /relay/* endpoints (recommended)
  RESPONSE_TTL_SECONDS    — how long to keep responses in memory (default: 86400)
  WECOM_CORP_SECRET       — corp secret; enables immediate card-disable on button click
  WECOM_AGENT_ID          — app agent ID; required together with WECOM_CORP_SECRET
"""

import base64
import hashlib
import logging
import os
import re
import struct
import time
import xml.etree.ElementTree as ET
from typing import Any

import httpx

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import PlainTextResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WeCom Relay")

TOKEN = os.environ["WECOM_TOKEN"]
ENCODING_AES_KEY = os.environ["WECOM_ENCODING_AES_KEY"]
CORP_ID = os.environ["WECOM_CORP_ID"]
RELAY_API_SECRET = os.environ.get("RELAY_API_SECRET", "")
TTL_SECONDS = int(os.environ.get("RESPONSE_TTL_SECONDS", 86400))
WECOM_CORP_SECRET = os.environ.get("WECOM_CORP_SECRET", "")
WECOM_AGENT_ID = int(os.environ.get("WECOM_AGENT_ID", "0") or "0")

# task_id -> {"task_id", "response", "user_id", "code", "received_at"}
_responses: dict[str, dict[str, Any]] = {}
_token_cache: tuple[str, float] | None = None  # (access_token, expires_at)


def _cleanup() -> None:
    now = time.time()
    expired = [k for k, v in _responses.items() if now - v["received_at"] > TTL_SECONDS]
    for k in expired:
        del _responses[k]


async def _get_access_token() -> str:
    global _token_cache
    now = time.time()
    if _token_cache and now < _token_cache[1] - 60:
        return _token_cache[0]
    async with httpx.AsyncClient() as client:
        r = await client.get(
            "https://qyapi.weixin.qq.com/cgi-bin/gettoken",
            params={"corpid": CORP_ID, "corpsecret": WECOM_CORP_SECRET},
        )
        data = r.json()
    if data.get("errcode", 0) != 0:
        raise RuntimeError(f"WeCom gettoken error: {data}")
    token = data["access_token"]
    _token_cache = (token, now + data.get("expires_in", 7200))
    return token


async def _disable_card(response_code: str, replace_name: str) -> None:
    """Call WeCom taskcard/update to replace the button area immediately after a click."""
    if not WECOM_CORP_SECRET or not WECOM_AGENT_ID or not response_code:
        return
    try:
        token = await _get_access_token()
        async with httpx.AsyncClient() as client:
            r = await client.post(
                "https://qyapi.weixin.qq.com/cgi-bin/message/interactive/taskcard/update",
                params={"access_token": token},
                json={"agentid": WECOM_AGENT_ID, "response_code": response_code, "replace_name": replace_name},
            )
            data = r.json()
        if data.get("errcode", 0) != 0:
            logger.warning("WeCom taskcard/update failed: %s", data)
        else:
            logger.info("Card disabled: response_code=%r replace_name=%r", response_code, replace_name)
    except Exception as e:
        logger.warning("WeCom taskcard/update error: %s", e)


def _require_secret(x_relay_secret: str) -> None:
    if RELAY_API_SECRET and x_relay_secret != RELAY_API_SECRET:
        raise HTTPException(status_code=401, detail="Invalid relay secret")


class WXBizMsgCrypt:
    def __init__(self, token: str, aes_key_b64: str, corpid: str) -> None:
        self.token = token
        self.aes_key = base64.b64decode(aes_key_b64 + "=")
        if len(self.aes_key) != 32:
            raise ValueError("AES key must be 32 bytes after base64 decode")
        self.corpid = corpid

    def _sha1(self, timestamp: str, nonce: str, encrypt: str) -> str:
        sha1 = hashlib.sha1()
        sha1.update("".join(sorted([self.token, timestamp, nonce, encrypt])).encode())
        return sha1.hexdigest()

    def _aes_decrypt(self, encrypt_str: str) -> str:
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.aes_key[:16]))
        decryptor = cipher.decryptor()
        data = decryptor.update(base64.b64decode(encrypt_str)) + decryptor.finalize()
        # PKCS7 unpad
        data = data[: -data[-1]]
        # random(16) + msg_len(4BE) + msg + corpid
        msg_len = struct.unpack(">I", data[16:20])[0]
        msg = data[20 : 20 + msg_len].decode("utf-8")
        received_id = data[20 + msg_len :].decode("utf-8")
        if received_id != self.corpid:
            raise ValueError(f"CorpID mismatch: got {received_id!r}")
        return msg

    def verify_url(
        self, msg_signature: str, timestamp: str, nonce: str, echostr: str
    ) -> str:
        if self._sha1(timestamp, nonce, echostr) != msg_signature:
            raise HTTPException(status_code=403, detail="Signature mismatch")
        return self._aes_decrypt(echostr)

    def decrypt_message(
        self, msg_signature: str, timestamp: str, nonce: str, xml_body: str
    ) -> str:
        tree = ET.fromstring(xml_body)
        encrypt = (tree.findtext("Encrypt") or "").strip()
        if not encrypt:
            raise HTTPException(status_code=400, detail="Missing Encrypt element")
        if self._sha1(timestamp, nonce, encrypt) != msg_signature:
            raise HTTPException(status_code=403, detail="Signature mismatch")
        return self._aes_decrypt(encrypt)


crypt = WXBizMsgCrypt(TOKEN, ENCODING_AES_KEY, CORP_ID)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "pending": len(_responses)}


@app.get("/wechat/callback", response_class=PlainTextResponse)
def wecom_verify(
    msg_signature: str = Query(...),
    timestamp: str = Query(...),
    nonce: str = Query(...),
    echostr: str = Query(...),
) -> str:
    return crypt.verify_url(msg_signature, timestamp, nonce, echostr)


@app.post("/wechat/callback")
async def wecom_event(
    request: Request,
    msg_signature: str = Query(...),
    timestamp: str = Query(...),
    nonce: str = Query(...),
) -> Response:
    _cleanup()
    body = (await request.body()).decode("utf-8")
    try:
        msg_xml = crypt.decrypt_message(msg_signature, timestamp, nonce, body)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decrypt error: {e}")

    tree = ET.fromstring(msg_xml)
    event = (tree.findtext("Event") or "").lower()
    card_type = (tree.findtext("CardType") or "").lower()
    event_key_raw = (tree.findtext("EventKey") or "").strip()
    task_id = (tree.findtext("TaskId") or "").strip()
    user_id = (tree.findtext("FromUserName") or "").strip()
    response_code = (tree.findtext("ResponseCode") or "").strip()

    logger.info(
        "WeCom event received: Event=%r EventKey=%r CardType=%r TaskId=%r FromUser=%r ResponseCode=%r XML=%s",
        event, event_key_raw, card_type, task_id, user_id, response_code, msg_xml,
    )

    if event == "template_card_event" and card_type == "button_interaction":
        # WeCom appends a 1-based index to the button key (e.g. "Yes" -> "Yes1"); strip it.
        button_key = re.sub(r"\d+$", "", event_key_raw)
        if task_id:
            _responses[task_id] = {
                "task_id": task_id,
                "response": button_key,
                "user_id": user_id,
                "code": response_code,
                "received_at": time.time(),
            }
            logger.info("Stored response: task_id=%r response=%r user_id=%r", task_id, button_key, user_id)
            await _disable_card(response_code, button_key)
        else:
            logger.warning("template_card_event received but TaskId is empty")
    else:
        logger.info("Unhandled event (not stored): Event=%r CardType=%r", event, card_type)

    return Response(content="success", media_type="text/plain")


@app.get("/relay/response/{task_id}")
def get_response(task_id: str, x_relay_secret: str = Header(default="")) -> dict:
    _require_secret(x_relay_secret)
    entry = _responses.get(task_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No response yet")
    return entry


@app.delete("/relay/response/{task_id}", status_code=204)
def delete_response(task_id: str, x_relay_secret: str = Header(default="")) -> Response:
    _require_secret(x_relay_secret)
    _responses.pop(task_id, None)
    return Response(status_code=204)
