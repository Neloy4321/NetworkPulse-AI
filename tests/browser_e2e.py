"""Run a real Chromium smoke test against a bootstrapped local API.

CI owns a disposable SQLite database and model. This is not an external IDS
benchmark or an internet-exposed deployment.
"""

import os
import subprocess
import sys
import time

import httpx
from playwright.sync_api import sync_playwright


URL = "http://127.0.0.1:8957"


def main():
    env = os.environ.copy()
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "networkpulse.api:create_app",
         "--factory", "--host", "127.0.0.1", "--port", "8957"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        for _ in range(80):
            if server.poll() is not None:
                raise RuntimeError(server.stderr.read().decode(errors="replace")[-3000:])
            try:
                if httpx.get(URL + "/health/ready", timeout=1).status_code == 200:
                    break
            except httpx.RequestError:
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError("Dashboard API did not become ready")

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 900})
                errors = []
                alert_responses = []
                page.on("pageerror", lambda err: errors.append(str(err)))
                page.on("response", lambda resp: alert_responses.append(
                    (resp.status, resp.url)
                ) if "/api/v1/alerts?" in resp.url else None)

                page.goto(URL + "/", wait_until="domcontentloaded")
                page.wait_for_function(
                    "() => document.querySelector('#system-state').textContent === 'OPERATIONAL'",
                    timeout=20000,
                )
                assert page.locator("#metric-flows").inner_text() == "325"
                assert page.locator("#metric-anomalies").inner_text() == "66"
                assert page.locator("#status-filter").input_value() == ""
                assert page.locator("#severity-filter").input_value() == ""
                assert page.locator("#alerts-body tr").count() > 0
                assert any(
                    code == 200 and "status=" not in url and "severity=" not in url
                    for code, url in alert_responses
                ), alert_responses

                page.locator("#status-filter").select_option("investigating")
                page.wait_for_function(
                    "() => document.querySelector('#alerts-body').textContent.includes('No alerts match')",
                    timeout=10000,
                )
                page.locator("#status-filter").select_option("")
                page.wait_for_function(
                    "() => document.querySelector('#system-state').textContent === 'OPERATIONAL' && document.querySelector('#alerts-body button[data-alert]') !== null",
                    timeout=10000,
                )
                page.set_viewport_size({"width": 390, "height": 844})
                assert page.locator("#system-state").inner_text() == "OPERATIONAL"
                assert not errors, errors
                assert all(code == 200 for code, _ in alert_responses), alert_responses
            finally:
                browser.close()
        print("Browser E2E PASS: default all-filters, data, interactions and mobile viewport")
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


if __name__ == "__main__":
    main()
