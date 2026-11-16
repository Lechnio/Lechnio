#!/usr/bin/env python3
"""Update the profile README: total-stars chart and Buy Me a Coffee supporters.

Security model: this script must only ever work with PUBLIC data.
  * GitHub access uses the workflow's built-in GITHUB_TOKEN, which is scoped
    to this repository only. Personal access tokens (classic or fine-grained),
    OAuth tokens and user tokens are rejected wherever they show up: in the
    environment, in the git config written by actions/checkout, or as GITHUB_TOKEN.
  * The token's scope is verified at runtime: it must reach exactly one public
    repository, this one. Otherwise the run fails before any data is fetched.
  * Private repositories and forks are filtered out of the chart.
  * Redirects to another host are refused, so tokens never leave their API.

Star history: the built-in token can read star COUNTS of public repositories,
but not who starred them and when. So every run records the current total in
assets/stars-history.csv (a new row only when the total changes) and the chart
is drawn from that file. Older history can be backfilled once, locally, with
scripts/seed_star_history.py.

Standard library only: no third-party packages to audit or pin.

Environment:
  GITHUB_TOKEN          built-in workflow token (required in Actions, forbidden locally)
  BMC_TOKEN             Buy Me a Coffee API token (optional; supporters are skipped without it)
  SUPPORTERS_OPTOUT     comma-separated names never to publish (optional, keep it a secret)
  STARS_START_DATE      YYYY-MM-DD; the chart starts on that day (optional)
  DRY_RUN=1             print what would change, write nothing
  SUPPORTERS_PREVIEW=1  local only: list published and hidden supporter names, then stop
"""

from __future__ import annotations

import base64
import datetime as dt
import html
import json
import math
import os
import re
import subprocess
import sys
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

USER = "Lechnio"
BMC_PAGE = f"https://buymeacoffee.com/{USER}"

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
ASSETS = ROOT / "assets"
HISTORY = ASSETS / "stars-history.csv"

GITHUB_API = "https://api.github.com"
BMC_API = "https://developers.buymeacoffee.com/api/v1"

# Token prefixes that may grant access to private repositories.
# "ghs_" (GitHub App installation token, which is what GITHUB_TOKEN is) is the only one allowed.
FORBIDDEN_PREFIXES = ("ghp_", "github_pat_", "gho_", "ghu_", "ghr_")

SUPPORTERS_START = "<!-- SUPPORTERS:START -->"
SUPPORTERS_END = "<!-- SUPPORTERS:END -->"

DRY_RUN = os.environ.get("DRY_RUN") == "1"


def fail(message: str) -> None:
    # stdout, so GitHub Actions turns it into an annotation on the run summary.
    print(f"::error::{message}", flush=True)
    sys.exit(1)


# --------------------------------------------------------------------------- token guard


def git_config_values() -> list[str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "config", "--list", "--includes"],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return []
    return result.stdout.splitlines()


def guard_tokens() -> str | None:
    """Abort unless the only GitHub credential around is the built-in GITHUB_TOKEN."""
    for name, value in os.environ.items():
        if value.strip().startswith(FORBIDDEN_PREFIXES):
            fail(f"Environment variable {name} holds a personal GitHub token. "
                 "This workflow may only use the built-in GITHUB_TOKEN. Remove it from the workflow.")

    for line in git_config_values():
        if any(prefix in line for prefix in FORBIDDEN_PREFIXES):
            fail("The git config contains a personal GitHub token. "
                 "Do not pass 'token:' to actions/checkout or embed tokens in the remote URL.")
        match = re.search(r"basic\s+([A-Za-z0-9+/=]+)", line, re.IGNORECASE)
        if match:
            try:
                credential = base64.b64decode(match.group(1)).decode()
            except ValueError:
                fail("Could not decode the git credentials written by actions/checkout.")
            if not credential.split(":", 1)[-1].startswith("ghs_"):
                fail("actions/checkout is authenticated with something other than GITHUB_TOKEN. "
                     "Remove the 'token:' input from the checkout step.")

    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if os.environ.get("GITHUB_ACTIONS") == "true":
        if not token.startswith("ghs_"):
            fail("GITHUB_TOKEN must be the workflow's built-in token (${{ github.token }}).")
        verify_token_scope(token)
        return token
    if token:
        fail("Run locally without GITHUB_TOKEN. Only public data is needed.")
    return None


def verify_token_scope(token: str) -> None:
    """The built-in token must reach exactly one public repository: this one."""
    expected = os.environ.get("GITHUB_REPOSITORY", "").lower()
    try:
        data = github_get("/installation/repositories?per_page=100", token)
    except urllib.error.HTTPError as error:
        fail(f"Could not verify the token scope (HTTP {error.code}). Refusing to continue.")
    repos = data.get("repositories", [])
    if data.get("total_count") != 1 or len(repos) != 1:
        fail("The token can reach more than one repository. Only the built-in GITHUB_TOKEN is allowed.")
    repo = repos[0]
    if repo.get("private") or repo.get("full_name", "").lower() != expected:
        fail("The token is not scoped to this public repository. Refusing to continue.")


# --------------------------------------------------------------------------- HTTP


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    """urllib copies the Authorization header onto redirects, even to other hosts. Refuse those."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urlparse(req.full_url), urlparse(newurl)
        if (new.scheme, new.netloc) != (old.scheme, old.netloc):
            fail(f"Refusing redirect from {old.scheme}://{old.netloc} to {new.scheme}://{new.netloc}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(SameOriginRedirect)


def http_get(url: str, headers: dict[str, str]) -> tuple[object, dict[str, str]]:
    request = urllib.request.Request(url, headers={"User-Agent": "profile-readme-updater", **headers})
    with OPENER.open(request, timeout=30) as response:
        return json.load(response), dict(response.headers)


def github_headers(token: str | None, accept: str = "application/vnd.github+json") -> dict[str, str]:
    headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def github_get(path: str, token: str | None) -> dict | list:
    data, _ = http_get(GITHUB_API + path, github_headers(token))
    return data


def github_paginate(path: str, token: str | None, accept: str = "application/vnd.github+json") -> list:
    url, items = GITHUB_API + path, []
    while url:
        if urlparse(url).netloc != "api.github.com":
            fail(f"Unexpected pagination host in {url}")
        data, headers = http_get(url, github_headers(token, accept))
        items.extend(data)
        match = re.search(r'<([^>]+)>;\s*rel="next"', headers.get("Link", ""))
        url = match.group(1) if match else None
    return items


# --------------------------------------------------------------------------- stars


def public_repos(token: str | None) -> list[dict]:
    repos = github_paginate(f"/users/{USER}/repos?type=owner&per_page=100", token)
    return [r for r in repos
            if not r.get("private") and r.get("visibility", "public") == "public" and not r.get("fork")]


def fetch_star_total(token: str | None) -> int:
    repos = public_repos(token)
    total = sum(r.get("stargazers_count", 0) for r in repos)
    print(f"Stars: {total} across {len(repos)} public non-fork repositories.")
    return total


def read_history(path: Path = HISTORY) -> list[tuple[dt.date, int]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines()[1:]:
        if line.strip():
            day, total = line.split(",")
            rows.append((dt.date.fromisoformat(day), int(total)))
    return sorted(rows)


def format_history(rows: list[tuple[dt.date, int]]) -> str:
    return "date,total\n" + "".join(f"{day.isoformat()},{total}\n" for day, total in rows)


def record_total(rows: list[tuple[dt.date, int]], day: dt.date, total: int) -> list[tuple[dt.date, int]]:
    """Add today's total, keeping a row only when the total changes."""
    rows = [row for row in rows if row[0] < day]
    if not rows or rows[-1][1] != total:
        rows.append((day, total))
    return rows


def nice_step(max_value: int, ticks: int = 4) -> int:
    raw = max(max_value / ticks, 1)
    magnitude = 10 ** math.floor(math.log10(raw))
    for factor in (1, 2, 5, 10):
        if raw <= factor * magnitude:
            return int(factor * magnitude)
    return int(10 * magnitude)


THEMES = {
    "light": {"text": "#57606a", "grid": "#d0d7de", "line": "#0969da", "fill": "#0969da"},
    "dark": {"text": "#8b949e", "grid": "#30363d", "line": "#58a6ff", "fill": "#58a6ff"},
}


def render_chart(rows: list[tuple[dt.date, int]], start: dt.date | None, theme: str,
                 today: dt.date | None = None) -> str:
    colors = THEMES[theme]
    width, height = 800, 320
    left, right, top, bottom = 52, 24, 56, 40
    plot_w, plot_h = width - left - right, height - top - bottom
    font = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"

    total = rows[-1][1] if rows else 0
    title = f"★ {total} total star{'s' if total != 1 else ''}"
    x_start = max(start, rows[0][0]) if (start and rows) else (rows[0][0] if rows else None)
    subtitle = "across all my public repositories" + (f" · since {x_start:%b %Y}" if start and x_start else "")

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="{font}" role="img" aria-label="{html.escape(title)}">',
        f'<text x="{left}" y="26" font-size="18" font-weight="600" fill="{colors["line"]}">{html.escape(title)}</text>',
        f'<text x="{left}" y="44" font-size="12" fill="{colors["text"]}">{html.escape(subtitle)}</text>',
    ]

    if not rows:
        parts.append(f'<text x="{width / 2}" y="{height / 2 + 20}" font-size="14" text-anchor="middle" '
                     f'fill="{colors["text"]}">No stars yet</text></svg>')
        return "\n".join(parts)

    # The line ends at the start of the current month (or the last change, if later),
    # so the image changes at least monthly. Those commits keep the scheduled
    # workflow alive (GitHub disables schedules after 60 days without activity).
    today = today or dt.datetime.now(dt.timezone.utc).date()
    x_end = max(today.replace(day=1), rows[-1][0])
    if x_end <= x_start:
        x_end = x_start + dt.timedelta(days=30)

    baseline = [value for day, value in rows if day <= x_start][-1]
    events = [(day, value) for day, value in rows if day > x_start]
    step = nice_step(max([baseline, 1] + [value for _, value in events]))
    y_top = math.ceil(max([baseline, 1] + [value for _, value in events]) / step) * step

    def x(day: dt.date) -> float:
        return left + (day - x_start).days / (x_end - x_start).days * plot_w

    def y(value: int) -> float:
        return top + plot_h - value / y_top * plot_h

    for value in range(0, y_top + 1, step):
        parts.append(f'<line x1="{left}" x2="{width - right}" y1="{y(value):.1f}" y2="{y(value):.1f}" '
                     f'stroke="{colors["grid"]}" stroke-width="1"/>')
        parts.append(f'<text x="{left - 8}" y="{y(value) + 4:.1f}" font-size="11" text-anchor="end" '
                     f'fill="{colors["text"]}">{value}</text>')

    months, cursor = [], dt.date(x_start.year, x_start.month, 1)
    while cursor <= x_end:
        if cursor >= x_start:
            months.append(cursor)
        cursor = dt.date(cursor.year + cursor.month // 12, cursor.month % 12 + 1, 1)
    stride = max(1, math.ceil(len(months) / 6))
    for month in months[::stride]:
        parts.append(f'<text x="{x(month):.1f}" y="{height - 14}" font-size="11" text-anchor="middle" '
                     f'fill="{colors["text"]}">{month.strftime("%b %Y")}</text>')

    current = baseline
    path = [f"M{x(x_start):.1f},{y(current):.1f}"]
    for day, value in events:
        path.append(f"L{x(day):.1f},{y(current):.1f}")
        current = value
        path.append(f"L{x(day):.1f},{y(current):.1f}")
    path.append(f"L{x(x_end):.1f},{y(current):.1f}")
    line = " ".join(path)
    area = f"{line} L{x(x_end):.1f},{y(0):.1f} L{x(x_start):.1f},{y(0):.1f} Z"

    parts.append(f'<path d="{area}" fill="{colors["fill"]}" fill-opacity="0.12" stroke="none"/>')
    parts.append(f'<path d="{line}" fill="none" stroke="{colors["line"]}" stroke-width="2.5" '
                 f'stroke-linejoin="round" stroke-linecap="round"/>')
    parts.append("</svg>")
    return "\n".join(parts)


# --------------------------------------------------------------------------- supporters


def clean_name(raw: str) -> str:
    """Supporter names come from strangers: keep plain text only, no Markdown, HTML or links."""
    name = unicodedata.normalize("NFKC", raw)
    name = re.sub(r"<[^>]*>|\]\([^)]*\)|https?://\S+", " ", name)
    name = re.sub(r"[^\w .'-]", "", name)
    return re.sub(r"\s+", " ", name).strip(" .'-")[:32].strip()


def is_hidden(sub: dict) -> bool:
    """BMC does not document these fields, so any sign of privacy hides the person."""
    if sub.get("is_private"):
        return True
    return any(sub.get(field) in (0, "0", False, "private")
               for field in ("support_visibility", "message_visibility"))


def fetch_supporters(token: str) -> tuple[list[str], list[str]]:
    """Return (published, hidden) names of active members."""
    optout = {clean_name(n).casefold() for n in os.environ.get("SUPPORTERS_OPTOUT", "").split(",")
              if clean_name(n)}
    url, public, hidden = f"{BMC_API}/subscriptions?status=active", set(), set()
    while url:
        if urlparse(url).netloc != urlparse(BMC_API).netloc:
            fail(f"Unexpected pagination host in {url}")
        try:
            data, _ = http_get(url, {"Authorization": f"Bearer {token}", "Accept": "application/json"})
        except urllib.error.HTTPError as error:
            if error.code == 404:  # BMC may answer 404 when there are no members yet
                break
            if error.code == 401:
                fail("BMC_TOKEN was rejected by Buy Me a Coffee (HTTP 401). Generate a new token.")
            raise
        for sub in data.get("data", []):
            name = clean_name(sub.get("payer_name") or "")
            if not name or name.casefold() == "someone":
                continue
            if is_hidden(sub) or name.casefold() in optout:
                hidden.add(name)
            else:
                public.add(name)
        url = data.get("next_page_url")
    public = {n for n in public if n.casefold() not in {h.casefold() for h in hidden}}
    print(f"Supporters: {len(public)} published, {len(hidden)} hidden.")
    return sorted(public, key=str.casefold), sorted(hidden, key=str.casefold)


def render_supporters(names: list[str]) -> str:
    if not names:
        return f"_No supporters yet. [Be the first!]({BMC_PAGE})_"
    escaped = (n.replace("_", r"\_") for n in names)
    return "Huge thanks to everyone supporting my work:\n\n" + " · ".join(f"**{n}**" for n in escaped)


def replace_block(text: str, body: str) -> str:
    pattern = re.compile(re.escape(SUPPORTERS_START) + r".*?" + re.escape(SUPPORTERS_END), re.DOTALL)
    if not pattern.search(text):
        fail(f"README.md is missing the {SUPPORTERS_START} / {SUPPORTERS_END} markers.")
    return pattern.sub(lambda _: f"{SUPPORTERS_START}\n{body}\n{SUPPORTERS_END}", text)


# --------------------------------------------------------------------------- main


def write_if_changed(path: Path, content: str) -> None:
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return
    if DRY_RUN:
        print(f"[dry run] would update {path.relative_to(ROOT)}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    print(f"Updated {path.relative_to(ROOT)}")


def main() -> None:
    github_token = guard_tokens()

    bmc_token = os.environ.get("BMC_TOKEN", "").strip()
    if bmc_token.startswith(FORBIDDEN_PREFIXES + ("ghs_",)):
        fail("BMC_TOKEN looks like a GitHub token. Put your Buy Me a Coffee API token there.")

    if os.environ.get("SUPPORTERS_PREVIEW") == "1":
        if os.environ.get("GITHUB_ACTIONS") == "true":
            fail("SUPPORTERS_PREVIEW prints supporter names. Never run it in Actions: the logs are public.")
        if not bmc_token:
            fail("Set BMC_TOKEN to preview supporters.")
        public, hidden = fetch_supporters(bmc_token)
        print("Would publish:", ", ".join(public) or "(nobody)")
        print("Hidden:", ", ".join(hidden) or "(nobody)")
        return

    start_raw = os.environ.get("STARS_START_DATE", "").strip()
    try:
        start = dt.date.fromisoformat(start_raw) if start_raw else None
    except ValueError:
        fail(f"STARS_START_DATE must be YYYY-MM-DD, got {start_raw!r}.")

    today = dt.datetime.now(dt.timezone.utc).date()
    rows = record_total(read_history(), today, fetch_star_total(github_token))
    write_if_changed(HISTORY, format_history(rows))
    for theme in THEMES:
        write_if_changed(ASSETS / f"stars-{theme}.svg", render_chart(rows, start, theme, today))

    if bmc_token:
        readme = README.read_text(encoding="utf-8")
        write_if_changed(README, replace_block(readme, render_supporters(fetch_supporters(bmc_token)[0])))
    else:
        print("BMC_TOKEN not set: supporters section left unchanged.")


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as error:
        where = urlparse(error.url)
        body = error.read(300).decode("utf-8", "replace") if error.fp else ""
        fail(f"HTTP {error.code} from {where.netloc}{where.path}: {body}")
