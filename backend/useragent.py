"""
User-Agent parsing — automatic OS + browser detection (server side).

Given the User-Agent string the browser sends with every request, work out which
operating system and browser the client is on. Used to enrich the Site Access
log, device-trust labels and behaviour context, so the admin can see whether a
user is on Windows, Linux, macOS, Android, iOS, etc. — no extra input needed.
"""


def detect_os(ua: str) -> str:
    ua = ua or ""
    # Order matters: Android/iOS carry "Linux"/"Mac" substrings, so check first.
    if "Windows NT" in ua or "Windows" in ua:
        return "Windows"
    if "Android" in ua:
        return "Android"
    if "iPhone" in ua or "iPad" in ua or "iPod" in ua:
        return "iOS"
    if "CrOS" in ua:
        return "Chrome OS"
    if "Mac OS X" in ua or "Macintosh" in ua:
        return "macOS"
    if "Linux" in ua:
        return "Linux"
    return "Unknown OS"


def detect_browser(ua: str) -> str:
    ua = ua or ""
    if "Edg" in ua:
        return "Edge"
    if "OPR" in ua or "Opera" in ua:
        return "Opera"
    if "Chrome" in ua and "Chromium" not in ua:
        return "Chrome"
    if "Chromium" in ua:
        return "Chromium"
    if "Firefox" in ua:
        return "Firefox"
    if "Safari" in ua:
        return "Safari"
    return "Unknown browser"


def device_label(ua: str) -> str:
    """A short 'Browser on OS' label, e.g. 'Chrome on Windows'."""
    os_name = detect_os(ua)
    browser = detect_browser(ua)
    if os_name == "Unknown OS":
        return browser
    return f"{browser} on {os_name}"
