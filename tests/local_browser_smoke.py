"""Local optional browser integration smoke test using installed Chromium."""
import os
import sys
import time
import subprocess
from pathlib import Path

import httpx
from playwright.sync_api import sync_playwright

BASE=Path(__file__).resolve().parents[1]
env=os.environ.copy()
env['NETWORKPULSE_API_KEY']='integration-tests-use-random-env-key'
env['PYTHONPATH']=str(BASE)
server=subprocess.Popen([sys.executable,'-m','uvicorn','networkpulse.api:create_app','--factory', '--host','127.0.0.1','--port','8957'],cwd=BASE,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
try:
    for _ in range(40):
        if server.poll() is not None:
            raise RuntimeError(server.stderr.read().decode()[-2000:])
        try:
            if httpx.get('http://127.0.0.1:8957/health/ready', timeout=1).status_code == 200:
                break
        except httpx.RequestError:
            pass
        time.sleep(.2)
    else:
        raise RuntimeError('Server failed to start')
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
        page=browser.new_page(viewport={'width':1512,'height':900},device_scale_factor=1)
        errors=[]
        page.on('pageerror',lambda x:errors.append(str(x)))
        page.goto('http://127.0.0.1:8957/',wait_until='domcontentloaded')
        page.wait_for_function("document.getElementById('metric-flows').textContent === '325'",timeout=12000)
        assert page.locator('#metric-anomalies').inner_text()=='66'
        assert page.locator('#severity-filter').count()==1
        page.locator('#severity-filter').select_option('high')
        page.wait_for_timeout(1100)
        assert page.locator('#alerts-body tr').count()>=1
        assert not errors,errors
        Path('/mnt/data/networkpulse-advanced-ui.png').parent.mkdir(exist_ok=True)
        page.screenshot(path='/mnt/data/networkpulse-advanced-ui.png',full_page=True)
        browser.close()
    print('Browser smoke succeeded. Screenshot saved. Dashboard flows=325, alerts=66, filters operational.')
finally:
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
