"""Screenshots of the dashboard, taken from a real run of scripts/demo_dashboard.py.

Starts the demo gateway (dashboard on, scripted calls already made), opens it
in headless Chromium, signs in with the demo admin key, and writes

    assets/dashboard.png          feed, approval queue and audit chain, after
                                  "Verify the real log" was clicked
    assets/dashboard_tamper.png   after "Change this entry (demo copy)" on the
                                  entry the admin approved, field `decision`:
                                  the real log still verifies, the copy breaks

Both at a 1400 x 900 viewport with deviceScaleFactor 2. The run fails if the
browser reports any console error (a Content-Security-Policy violation would
show up there).

Browser driver: the Python package `playwright` if it is installed, otherwise
Node.js Playwright (found as in scripts/design/render.py, `node_path`) driven
with the same steps. Both use an installed Chromium; nothing new is installed.

Run from the repo root: .venv/bin/python scripts/fig_dashboard.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import demo_dashboard
import style
from design.render import node_path

FIELD = "decision"
APPROVER = "ana"
VIEWPORT = {"width": 1400, "height": 900}
SCALE = 2
SETTLE_MS = 2500  # a little over one poll interval


def target_entry(log: Path) -> int:
    """The seq of the entry the admin approved: the one an attacker would want to flip.

    The story approves it mid-run, so later entries show where checking stops."""
    for line in log.read_text().splitlines():
        entry = json.loads(line)
        if entry["decision"] == "approved":
            return entry["seq"]
    raise RuntimeError("the demo log has no approved entry")


def shoot_python(url: str, key: str, seq: int, out: dict[str, str]) -> list[str]:
    from playwright.sync_api import sync_playwright

    errors: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport=VIEWPORT, device_scale_factor=SCALE)
        page = context.new_page()
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.goto(url + "/dashboard")
        page.fill("#key", key)
        page.fill("#approver", APPROVER)
        page.click("#login button[type=submit]")
        page.wait_for_selector("table.feed")
        page.wait_for_selector(".approval")
        page.wait_for_selector(".chain .block")
        page.click("#verify")
        page.wait_for_selector("#verify-result .verdict")
        page.wait_for_timeout(SETTLE_MS)
        page.screenshot(path=out["main"])
        page.fill("#tamper-seq", str(seq))
        page.select_option("#tamper-field", FIELD)
        page.click("#tamper button[type=submit]")
        page.wait_for_selector(".side.copy .verdict")
        page.eval_on_selector(".chain-panel", "e => e.scrollIntoView({block: 'start'})")
        page.wait_for_timeout(300)
        page.screenshot(path=out["tamper"])
        browser.close()
    return errors


NODE_DRIVER = r"""
const { chromium } = require("playwright");
const a = JSON.parse(process.env.FIG_ARGS);
(async () => {
  const errors = [];
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: a.viewport, deviceScaleFactor: a.scale });
  const page = await context.newPage();
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  await page.goto(a.url + "/dashboard");
  await page.fill("#key", a.key);
  await page.fill("#approver", a.approver);
  await page.click("#login button[type=submit]");
  await page.waitForSelector("table.feed");
  await page.waitForSelector(".approval");
  await page.waitForSelector(".chain .block");
  await page.click("#verify");
  await page.waitForSelector("#verify-result .verdict");
  await page.waitForTimeout(a.settle);
  await page.screenshot({ path: a.out.main });
  await page.fill("#tamper-seq", String(a.seq));
  await page.selectOption("#tamper-field", a.field);
  await page.click("#tamper button[type=submit]");
  await page.waitForSelector(".side.copy .verdict");
  await page.$eval(".chain-panel", (e) => e.scrollIntoView({ block: "start" }));
  await page.waitForTimeout(300);
  await page.screenshot({ path: a.out.tamper });
  await browser.close();
  process.stdout.write(JSON.stringify(errors));
})().catch((e) => { console.error(e); process.exit(1); });
"""


def shoot_node(url: str, key: str, seq: int, out: dict[str, str]) -> list[str]:
    args = {
        "url": url,
        "key": key,
        "approver": APPROVER,
        "seq": seq,
        "field": FIELD,
        "viewport": VIEWPORT,
        "scale": SCALE,
        "settle": SETTLE_MS,
        "out": out,
    }
    env = {
        **os.environ,
        "FIG_ARGS": json.dumps(args),
        "NODE_PATH": node_path(),
    }
    with tempfile.TemporaryDirectory() as folder:
        script = Path(folder) / "driver.js"
        script.write_text(NODE_DRIVER)
        done = subprocess.run(
            ["node", str(script)], env=env, capture_output=True, text=True, timeout=120
        )
    if done.returncode != 0:
        raise RuntimeError(f"node playwright failed: {done.stderr[-2000:]}")
    return json.loads(done.stdout or "[]")


def main() -> int:
    style.ASSETS.mkdir(exist_ok=True)
    out = {
        "main": str(style.ASSETS / "dashboard.png"),
        "tamper": str(style.ASSETS / "dashboard_tamper.png"),
    }
    demo = demo_dashboard.start()
    try:
        before = demo.gateway.audit.path.read_bytes()
        seq = target_entry(demo.gateway.audit.path)
        try:
            import playwright.sync_api  # noqa: F401

            shoot = shoot_python
        except ImportError:
            shoot = shoot_node
        errors = shoot(demo.url, demo.admin_key, seq, out)
        after = demo.gateway.audit.path.read_bytes()
    finally:
        demo.stop()
    if errors:
        print("browser console errors:", *errors, sep="\n  ", file=sys.stderr)
        return 1
    # Nothing in the run writes to the log after the story, and the demo must not.
    if before != after:
        print("the real audit log changed during the screenshots", file=sys.stderr)
        return 1
    print(f"wrote {out['main']} and {out['tamper']} (tamper demo on entry {seq}, {FIELD})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
