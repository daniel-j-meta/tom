import json
from urllib.parse import urlsplit

from .proxy import resolve_public


async def navigate(cdp, url):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.port not in {None, 443}
    ):
        raise ValueError("Enter an HTTPS URL without credentials or a custom port")
    await resolve_public(parsed.hostname)
    # The mandatory CONNECT proxy independently checks every actual request and redirect.
    await cdp.call("Page.navigate", {"url": url})


async def input_action(cdp, action):
    kind = action.get("type")
    if kind == "click":
        x, y = float(action["x"]), float(action["y"])
        if not (0 <= x <= 1280 and 0 <= y <= 800):
            raise ValueError("Click is outside the browser viewport")
        for phase in ["mousePressed", "mouseReleased"]:
            await cdp.call(
                "Input.dispatchMouseEvent",
                {"type": phase, "x": x, "y": y, "button": "left", "clickCount": 1},
            )
    elif kind == "text":
        text = action.get("text", "")
        if not isinstance(text, str) or len(text) > 4096:
            raise ValueError("Text is too long")
        await cdp.call("Input.insertText", {"text": text})
    elif kind == "key":
        keys = {
            "Enter": 13,
            "Tab": 9,
            "Backspace": 8,
            "Escape": 27,
            "ArrowLeft": 37,
            "ArrowUp": 38,
            "ArrowRight": 39,
            "ArrowDown": 40,
        }
        key = action.get("key")
        if key not in keys:
            raise ValueError("Unsupported key")
        for phase in ["keyDown", "keyUp"]:
            await cdp.call(
                "Input.dispatchKeyEvent",
                {"type": phase, "key": key, "windowsVirtualKeyCode": keys[key]},
            )
    elif kind == "scroll":
        await cdp.call(
            "Input.dispatchMouseEvent",
            {
                "type": "mouseWheel",
                "x": max(0, min(1280, float(action.get("x", 640)))),
                "y": max(0, min(800, float(action.get("y", 400)))),
                "deltaX": max(-800, min(800, float(action.get("dx", 0)))),
                "deltaY": max(-800, min(800, float(action.get("dy", 0)))),
            },
        )
    else:
        raise ValueError("Unsupported browser input")


async def fill_credential(cdp, credential, username_selector, password_selector):
    if (
        not username_selector
        or not password_selector
        or max(len(username_selector), len(password_selector)) > 256
    ):
        raise ValueError("Two short input selectors are required")
    # Origin check and fill occur together in one page evaluation to avoid a navigation race.
    expression = """(() => {
      const c = CREDENTIAL;
      if (location.protocol !== 'https:' || location.hostname !== c.host) return false;
      const u = document.querySelector(c.usernameSelector);
      const p = document.querySelector(c.passwordSelector);
      if (!(u instanceof HTMLInputElement) || !(p instanceof HTMLInputElement) || p.type !== 'password') return false;
      const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      set.call(u,c.username); set.call(p,c.password);
      for (const el of [u,p]) { el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true})); }
      return true;
    })()""".replace(
        "CREDENTIAL",
        json.dumps(
            {
                **credential,
                "usernameSelector": username_selector,
                "passwordSelector": password_selector,
            }
        ),
    )
    result = await cdp.call("Runtime.evaluate", {"expression": expression, "returnByValue": True})
    if result.get("result", {}).get("value") is not True:
        raise ValueError("Page origin or login inputs do not match the saved credential")
