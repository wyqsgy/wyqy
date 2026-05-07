from playwright.sync_api import sync_playwright
import time

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False, args=['--no-sandbox'])
    page = browser.new_page(viewport={"width": 1920, "height": 1080})

    print("正在打开 http://localhost:3000/ ...")
    page.goto('http://localhost:3000/', timeout=30000)
    page.wait_for_load_state('networkidle', timeout=15000)
    time.sleep(2)

    print("页面标题:", page.title())
    print("页面 URL:", page.url)

    page.screenshot(path='/workspace/wyqyan_preview.png', full_page=True)
    print("截图已保存到 /workspace/wyqyan_preview.png")

    content = page.content()
    if 'WyqYan' in content or 'SECURITY' in content or 'Dashboard' in content:
        print("✅ 页面加载成功！找到项目相关内容")
    else:
        print("⚠️ 页面可能未正确加载")

    page.wait_for_timeout(2000)
    browser.close()
    print("浏览器已关闭")
