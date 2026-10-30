"""Guard the cockpit markup so a broken character or a layout regression fails CI.

These are cheap structural assertions, not a browser test: if the mismatch that
pushed the page down (an unbounded chart canvas) or a mojibake character comes
back, this fails before it reaches a video.
"""

from pathlib import Path

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"


def read(name: str) -> str:
    return (FRONTEND / name).read_text(encoding="utf-8")


def test_all_frontend_files_are_valid_utf8():
    for name in ("index.html", "app.js", "style.css"):
        raw = (FRONTEND / name).read_bytes()
        text = raw.decode("utf-8")  # raises on invalid bytes
        assert "\ufffd" not in text, name


BROKEN_LITERALS = (
    # the exact strings that were mangled when written through a cp1254 shell
    "Traffic ? last",
    "demo injector ? synthetic",
    "real HTTP ? :8001",
    "verified 200?403",
    " ? docs/FULL_ARCHIVE_RUN.md",
    "Cloud forensics ? ",
    "returned ? surface",
    'join(" ? ")',
    "(hosted) ? needs",
    "mask ? no network",
)


def test_no_broken_em_dash_or_arrow_in_user_visible_copy():
    """Mojibake regression: these exact literals must never come back.

    A blanket " ? " check is wrong because JavaScript ternaries legitimately
    contain that sequence, so the check is pinned to the strings that broke.
    """
    for name in ("index.html", "app.js"):
        text = read(name)
        for broken in BROKEN_LITERALS:
            assert broken not in text, f"{name} still contains {broken!r}"


def test_user_visible_copy_uses_real_glyphs():
    html = read("index.html")
    assert "Traffic \u2014 last 5 min" in html
    assert "real HTTP \u2192 :8001" in html
    js = read("app.js")
    assert "verified 200\u2192403" in js


def test_chart_canvas_is_height_bounded():
    """The chart once grew unbounded and pushed the whole page down."""
    html = read("index.html")
    start = html.index('id="trafficChart"')
    # the canvas must sit inside a fixed-height wrapper
    wrapper = html[max(0, start - 220) : start]
    assert "height: 42px" in wrapper, wrapper
    assert "max-height: 42px" in wrapper
    assert "overflow: hidden" in wrapper

    css = read("style.css")
    assert ".metric-chart" in css
    assert "max-height: 68px" in css


def test_architecture_overlay_exists_and_is_dismissible():
    html = read("index.html")
    js = read("app.js")

    assert 'id="archBtn"' in html
    assert 'id="archModal"' in html
    assert 'role="dialog"' in html
    assert 'aria-modal="true"' in html
    assert 'id="archClose"' in html
    assert 'id="archBackdrop"' in html

    # the four documented tiers must be present
    for tier in ("1 \u00b7 Edge sensors", "2 \u00b7 Control plane", "3 \u00b7 Model tiers", "4 \u00b7 Protected service"):
        assert tier in html, tier

    assert "openArch" in js
    assert "closeArch" in js
    assert 'event.key !== "Escape"' in js


def test_alert_banner_is_fixed_and_driveable():
    html = read("index.html")
    css = read("style.css")
    js = read("app.js")

    assert 'id="alertBanner"' in html
    assert 'role="status"' in html
    assert 'aria-live="polite"' in html

    # fixed positioning: an in-flow banner would shift the grid
    banner_block = css.split(".alert-banner {", 1)[1].split("}", 1)[0]
    assert "position: fixed" in banner_block
    assert "transform: translateY(-100%)" in banner_block

    assert "showBanner" in js
    assert "bannerForIncident" in js
    assert "is-contained" in css and "is-contained" in js


def test_no_new_runtime_dependency_was_added():
    """Only Chart.js is allowed from a CDN; the overlay is hand-written."""
    html = read("index.html")
    assert html.count("cdn.jsdelivr.net") == 1
    # cache-busting query strings keep a stale asset from masking layout fixes
    assert "style.css?v=" in html
    assert "app.js?v=" in html
    assert "mermaid" not in html.lower()
    assert "d3." not in html.lower()
