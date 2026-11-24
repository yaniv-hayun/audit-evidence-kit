"""Find a company's logo and brand colors from its website, and save branding.

Security: the URL comes from the user and the website is untrusted.
  - Only http/https. Every host (including redirects and asset URLs) must
    resolve to public IP addresses: no localhost, private networks or cloud
    metadata (169.254.169.254). This blocks SSRF.
  - Size and time limits on every download; nothing is executed.
  - Only images and color codes are returned. The site's text never reaches
    Claude, so a page can't inject instructions.
"""

import io
import ipaddress
import json
import re
import shutil
import socket
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

from PIL import Image

MAX_HTML = 2 * 1024 * 1024
MAX_IMAGE = 5 * 1024 * 1024
TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (compatible; audit-evidence-kit branding detector)"
HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")


class BrandingError(Exception):
    """An expected problem (bad URL, blocked host, unreadable site)."""


# ---------------------------------------------------------------- safe fetching

def check_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise BrandingError(f"Only http(s) URLs are allowed: {url}")
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise BrandingError(f"Can't resolve {parsed.hostname}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise BrandingError(f"Blocked: {parsed.hostname} resolves to a non-public address ({ip})")
    return url


class SafeRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)  # every hop must be public too
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(SafeRedirects)


def fetch(url: str, limit: int, truncate: bool = False) -> tuple[bytes, str, str]:
    """Returns (body, content_type, final_url). With truncate, oversized
    bodies are cut at the limit instead of rejected (fine for HTML: the logo
    is near the top)."""
    check_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with OPENER.open(req, timeout=TIMEOUT) as resp:
            body = resp.read(limit + 1)
            ctype = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
            final = resp.geturl()
    except urllib.error.HTTPError as exc:
        raise BrandingError(f"{url} returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise BrandingError(f"Couldn't read {url}: {getattr(exc, 'reason', exc)}") from exc
    if len(body) > limit and truncate:
        body = body[:limit]
    elif len(body) > limit:
        raise BrandingError(f"{url} is larger than {limit // 1024 // 1024} MB")
    return body, ctype, final


# ---------------------------------------------------------------- HTML parsing

class BrandParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.candidates: list[tuple[str, str]] = []   # (source, url)
        self.theme_color: str | None = None
        self.styles: list[str] = []
        self.stylesheets: list[str] = []
        self._in_style = False
        self._in_jsonld = False
        self._jsonld: list[str] = []
        self._chrome = 0  # depth inside <header>/<nav>, where the company's own logo lives

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()  # e.g. <meta charset> has neither
            if name == "theme-color" and HEX.match(a.get("content", "").strip()):
                self.theme_color = a["content"].strip()
            if name in ("og:image", "twitter:image") and a.get("content"):
                self.candidates.append(("social image (og:image)", a["content"]))
        elif tag == "link":
            rel = a.get("rel", "").lower()
            href = a.get("href")
            if not href:
                return
            if "apple-touch-icon" in rel:
                self.candidates.append(("apple-touch-icon", href))
            elif "icon" in rel:
                self.candidates.append(("favicon", href))
            elif "stylesheet" in rel:
                self.stylesheets.append(href)
        elif tag in ("header", "nav"):
            self._chrome += 1
        elif tag == "img":
            hint = " ".join(a.get(k, "") for k in ("src", "alt", "class", "id")).lower()
            if "logo" in hint and a.get("src"):
                # Outside header/nav, "logo" images are usually customer or partner logos.
                source = "header logo image" if self._chrome else "other logo image on page"
                self.candidates.append((source, a["src"]))
        elif tag == "style":
            self._in_style = True
        elif tag == "script" and a.get("type", "").lower() == "application/ld+json":
            self._in_jsonld = True

    def handle_endtag(self, tag):
        if tag in ("header", "nav") and self._chrome:
            self._chrome -= 1
        elif tag == "style":
            self._in_style = False
        elif tag == "script":
            self._in_jsonld = False

    def handle_data(self, data):
        if self._in_style:
            self.styles.append(data)
        elif self._in_jsonld:
            self._jsonld.append(data)

    def jsonld_logos(self) -> list[str]:
        logos = []
        for block in self._jsonld:
            for m in re.finditer(r'"logo"\s*:\s*(?:"([^"]+)"|\{[^}]*"url"\s*:\s*"([^"]+)")', block):
                logos.append(m.group(1) or m.group(2))
        return logos


CSS_VAR = re.compile(r"--([\w-]*(?:primary|brand|accent|main)[\w-]*)\s*:\s*(#[0-9a-fA-F]{6}|#[0-9a-fA-F]{3})\b")
PRIORITY = {"header logo image": 0, "organization logo (structured data)": 1, "apple-touch-icon": 2,
            "other logo image on page": 3, "social image (og:image)": 4, "favicon": 5}


# ---------------------------------------------------------------- colors

def normalize_hex(value: str) -> str:
    value = value.strip().lower()
    if len(value) == 4:
        value = "#" + "".join(c * 2 for c in value[1:])
    return value.upper()


def logo_colors(img: Image.Image, count: int = 2) -> list[str]:
    """Dominant colors of the logo, ignoring transparent, near-white,
    near-black and gray pixels (backgrounds and text)."""
    rgba = img.convert("RGBA")
    rgba.thumbnail((128, 128))
    pixels = [p for p in rgba.getdata()
              if p[3] > 200 and max(p[:3]) - min(p[:3]) > 40 and 30 < sum(p[:3]) / 3 < 235]
    if not pixels:
        return []
    sample = Image.new("RGB", (len(pixels), 1))
    sample.putdata([p[:3] for p in pixels])
    quant = sample.quantize(colors=6)
    palette = quant.getpalette()
    ranked = sorted(quant.getcolors(), reverse=True)
    out = []
    for _, idx in ranked:
        r, g, b = palette[idx * 3: idx * 3 + 3]
        hexv = f"#{r:02X}{g:02X}{b:02X}"
        if hexv not in out:
            out.append(hexv)
        if len(out) == count:
            break
    return out


# ---------------------------------------------------------------- detection

def detect(url: str, results_dir: str) -> dict:
    if "://" not in url:
        url = "https://" + url
    html_bytes, ctype, final_url = fetch(url, MAX_HTML, truncate=True)
    if "html" not in ctype and not html_bytes.lstrip().startswith(b"<"):
        raise BrandingError(f"{url} didn't return an HTML page")

    parser = BrandParser()
    parser.feed(html_bytes.decode("utf-8", errors="ignore"))

    # Candidates in priority order, de-duplicated, resolved to absolute URLs.
    raw = [("organization logo (structured data)", u) for u in parser.jsonld_logos()] + parser.candidates
    raw.append(("favicon", "/favicon.ico"))
    seen, ordered = set(), []
    for source, href in sorted(raw, key=lambda c: PRIORITY.get(c[0], 9)):
        absolute = urllib.parse.urljoin(final_url, href)
        if absolute not in seen and not absolute.startswith("data:"):
            seen.add(absolute)
            ordered.append((source, absolute))

    out_dir = Path(results_dir).expanduser().resolve() / "branding" / "candidates"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    logos, skipped = [], []
    for source, asset_url in ordered[:10]:
        if len(logos) == 4:
            break
        try:
            body, actype, _ = fetch(asset_url, MAX_IMAGE)
        except BrandingError as exc:
            skipped.append({"source": source, "reason": str(exc)})
            continue
        if "svg" in actype or asset_url.lower().split("?")[0].endswith(".svg") or body.lstrip()[:5] in (b"<svg ", b"<?xml"):
            skipped.append({"source": source, "reason": "SVG logo: Word can't embed it reliably; upload a PNG instead"})
            continue
        try:
            img = Image.open(io.BytesIO(body))
            img.load()
        except Exception:
            skipped.append({"source": source, "reason": "not a readable image"})
            continue
        width, height = img.size
        path = out_dir / f"logo-{len(logos) + 1}.png"
        img.convert("RGBA").save(path, "PNG")
        visible = [p for p in img.convert("RGBA").resize((64, 64)).getdata() if p[3] > 128]
        lum = (sum(0.299 * p[0] + 0.587 * p[1] + 0.114 * p[2] for p in visible) / len(visible)) if visible else 255
        logos.append({
            "file": str(path), "source": source, "width": width, "height": height,
            "colors": logo_colors(img),
            "warning": ("small image, may look blurry in documents" if max(width, height) < 120 else
                        "very light logo, may be invisible on white pages" if lum > 225 else None),
        })

    # Colors: declared theme color, CSS brand variables, then logo colors.
    css = "\n".join(parser.styles)
    for href in parser.stylesheets[:3]:
        try:
            body, _, _ = fetch(urllib.parse.urljoin(final_url, href), MAX_HTML, truncate=True)
            css += "\n" + body.decode("utf-8", errors="ignore")
        except BrandingError:
            continue
    colors, seen_colors = [], set()

    def add(hexv: str, source: str):
        hexv = normalize_hex(hexv)
        if hexv not in seen_colors and hexv not in ("#FFFFFF", "#000000"):
            seen_colors.add(hexv)
            colors.append({"hex": hexv, "source": source})

    def css_rank(item):
        name = item[0].lower()
        step = re.search(r"-(\d{2,3})$", name)
        if not step:
            return 0                      # --primary, --brand-color: the main brand color
        return 1 if step.group(1) in ("500", "600", "700") else 2   # main shades before tints

    # Order of trust: the color the site declares, then the colors of the
    # company's own logo (reliable), then CSS variables (names vary a lot
    # between sites: "accent" or "background" variables are often not the brand).
    if parser.theme_color:
        add(parser.theme_color, "theme-color meta tag")
    for logo in logos[:1]:
        for c in logo["colors"]:
            add(c, f"colors of logo ({logo['source']})")
    for name, value in sorted(CSS_VAR.findall(css), key=css_rank)[:12]:
        if contrast_with_white(normalize_hex(value)) < 1.6:
            continue                      # near-white tint: useless for headings
        add(value, f"CSS variable --{name}")

    return {"site": final_url, "logos": logos, "colors": colors[:6], "skipped": skipped[:6]}


# ---------------------------------------------------------------- saving

def contrast_with_white(hexv: str) -> float:
    def channel(c: int) -> float:
        c = c / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (int(hexv[i:i + 2], 16) for i in (1, 3, 5))
    lum = 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
    return 1.05 / (lum + 0.05)


def readable(hexv: str) -> tuple[str, bool]:
    """Darken a color until it's readable as text on white (WCAG 4.5:1)."""
    r, g, b = (int(hexv[i:i + 2], 16) for i in (1, 3, 5))
    changed = False
    while contrast_with_white(f"#{r:02X}{g:02X}{b:02X}") < 4.5:
        r, g, b = int(r * 0.9), int(g * 0.9), int(b * 0.9)
        changed = True
    return f"#{r:02X}{g:02X}{b:02X}", changed


def save(results_dir: str, logo_path: str | None, primary: str | None, secondary: str | None,
         font: str | None, footer: str | None) -> dict:
    out = Path(results_dir).expanduser().resolve() / "branding"
    out.mkdir(parents=True, exist_ok=True)
    notes = []
    saved_logo = None
    if logo_path:
        src = Path(logo_path).expanduser()
        if not src.is_file():
            raise BrandingError(f"Logo file not found: {src}")
        if src.suffix.lower() == ".svg":
            raise BrandingError("SVG logos aren't supported in Word documents; export it as PNG first")
        try:
            img = Image.open(src)
            img.load()
        except Exception as exc:
            raise BrandingError(f"Not a readable image: {src}") from exc
        saved_logo = out / "logo.png"
        img.convert("RGBA").save(saved_logo, "PNG")
    branding = {"logo": str(saved_logo) if saved_logo else None, "font": font or "Calibri",
                "footer": footer or "{company} · {classification} · {title} v{version}"}
    for key, value, default in (("primary", primary, "#1F3864"), ("secondary", secondary, None)):
        if value is None:
            branding[key] = default
            continue
        if not HEX.match(value.strip()):
            raise BrandingError(f"{key} color must be a hex code like #1F4E79, got {value!r}")
        value = normalize_hex(value)
        if key == "primary":
            fixed, changed = readable(value)
            if changed:
                notes.append(f"Primary color {value} is too light for text on white; using {fixed} for headings")
            branding["primary_original"] = value
            value = fixed
        branding[key] = value
    (out / "branding.json").write_text(json.dumps(branding, indent=2))
    return {"branding": branding, "notes": notes, "file": str(out / "branding.json")}


def load(results_dir: str) -> dict:
    path = Path(results_dir).expanduser().resolve() / "branding" / "branding.json"
    if path.is_file():
        return json.loads(path.read_text())
    return {"logo": None, "font": "Calibri", "primary": "#1F3864", "secondary": None,
            "footer": "{company} · {classification} · {title} v{version}"}
