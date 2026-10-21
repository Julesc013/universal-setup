"""Pure, inactive HTML presentation of an existing task-brief observation."""
from __future__ import annotations

import base64
import hashlib
import html
import json
import unicodedata

MAX_INPUT_BYTES = 64 * 1024
MAX_HTML_BYTES = 512 * 1024
CSS = """html{color:#182434;background:#f4f6f8;font:16px/1.55 system-ui,sans-serif}
body{max-width:72rem;margin:0 auto;padding:2rem 1rem}
h1{font-size:1.65rem;line-height:1.25;margin:.35rem 0 1rem}
h2{font-size:1.15rem;margin:0 0 .8rem}
p{margin:.5rem 0}main{display:grid;gap:1rem}
section,details{background:#fff;border:1px solid #c5ced8;border-radius:.5rem;padding:1rem}
header,footer{margin-bottom:1.2rem}footer{margin-top:1.2rem}
.kicker{font-size:.8rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.notice{border-left:.3rem solid #685000;padding-left:1rem}
.fields{display:grid;grid-template-columns:minmax(8rem,1fr) minmax(0,3fr);gap:.45rem 1rem;margin:0}
dt{font-weight:650}dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
code,pre{font: .86rem/1.5 ui-monospace,Consolas,monospace;overflow-wrap:anywhere;white-space:pre-wrap}
summary{font-weight:650;cursor:pointer}summary:focus-visible{outline:3px solid #174fa3;outline-offset:4px}
li{margin:.35rem 0}.muted{color:#4e5b6b}.identity{font-size:.8rem}
@media(max-width:42rem){body{padding:1rem .7rem}.fields{display:block}dt{margin-top:.6rem}dd{margin-top:.15rem}}
@media print{html{background:white;color:black}body{max-width:none;padding:0}section,details{break-inside:avoid}}
"""


def canonical_json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _text(value, limit=1200):
    """Project values enter text nodes only; controls cannot impersonate layout."""
    text = "unknown" if value is None else value if isinstance(value, str) else canonical_json(value)
    omitted = max(0, len(text) - limit)
    text = "".join(
        "\\u%04x" % ord(c) if unicodedata.category(c) in {"Cc", "Cf", "Cs"} else c
        for c in text[:limit]
    )
    if omitted:
        text += f" [{omitted} more characters; complete observation below]"
    return html.escape(text, quote=True)


def _fields(rows):
    return '<dl class="fields">' + "".join(
        "<dt>" + _text(label) + "</dt><dd>" + _text(value) + "</dd>"
        for label, value in rows
    ) + "</dl>"


def _details(label, value):
    return "<details><summary>" + _text(label) + "</summary><pre>" + html.escape(
        json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False), quote=True
    ) + "</pre></details>"


def _page(data, canonical):
    state = data["result"]
    content = [
        "<header><p class=\"kicker\">AIDE / development brief</p>",
        "<h1>One task, its context and next action</h1>",
        "<p class=\"notice\">Saved observation: <strong>" + _text(state) + "</strong>. "
        "This page is not live state. Rerun the brief to refresh it.</p></header>",
        "<main><section><h2>Next action</h2>",
        "<p>" + _text(data.get("next_action")) + "</p></section>",
    ]
    if state == "REFUSED":
        content.append("<section><h2>Observation unavailable</h2><p>" + _text(data.get("reason")) + "</p></section>")
    else:
        continuation = data["continuation"]
        task = continuation["task"]
        quality = data["quality"]
        lessons = data["lessons"] or {}
        content += [
            "<section><h2>Recorded task</h2>",
            _fields([("Task", task.get("task_id")), ("Objective", task.get("objective")),
                     ("Selected file", data.get("path")), ("Task owner", task.get("owner")),
                     ("Recorded status", task.get("status")), ("Recorded result", task.get("result")),
                     ("Recorded next action", task.get("next_action")), ("Scope record", data.get("scope_ref"))]),
            "<p class=\"muted\">Recorded success does not establish acceptance or finish remaining obligations.</p></section>",
            "<section><h2>Continuation and remaining work</h2>",
            _fields([("Recommendation", continuation.get("recommendation")), ("Reason", continuation.get("reason")),
                     ("Remaining obligations", task.get("remaining_obligations"))]), "</section>",
            "<section><h2>File context</h2>",
            _fields([("File owner", quality.get("owner")), ("Quality observation", quality.get("result")),
                     ("Freshness", quality.get("freshness", "unverified")),
                     ("Coverage", quality.get("coverage", "unknown"))]),
        ]
        for name, relation in quality.get("relations", {}).items():
            # Names are project data too; no names become element IDs or attributes.
            content.append(_fields([(name, relation)]))
        content.append("<p class=\"muted\">Relations are advisory; incomplete information cannot narrow required checks.</p></section>")
        inspection = data.get("symbol_inspection")
        if inspection is not None:
            content += ["<section><h2>Fresh helper evidence</h2>",
                        _fields([("Symbol", inspection["symbol"]), ("Coverage", inspection["coverage"])]),
                        "<p class=\"muted\">Syntax matches do not resolve runtime binding or justify fewer checks.</p>"]
            for item, selection in zip(inspection["files"], data["symbol_selection"]):
                syntax = item["syntax"]
                groups = [syntax.get(name, {"items": [], "omitted": 0})
                          for name in ("definitions", "calls", "imports")]
                locations = [f"{name} line {match['line']}: "
                             + match.get("qualified_name", match["scope"])
                             for name, group in zip(("definitions", "calls", "imports"), groups)
                             for match in group["items"]]
                content.append(_fields([
                    ("Source", item["path"]), ("Selection reason", selection["reason"]),
                    ("Parse state", syntax["state"]), ("Match state", syntax["match_state"]),
                    ("Source SHA-256", syntax.get("sha256")),
                    ("Locations", locations[:3]),
                    ("Omitted matches", max(0, len(locations) - 3) + sum(group["omitted"] for group in groups)),
                ]))
            content += ["</section>", _details("Fresh syntax locations, omissions and recorded context", inspection)]
        content += [
            "<section><h2>Evidence and lessons</h2>",
            _fields([("Task evidence availability", task.get("evidence")),
                     ("Lesson observation", data.get("lesson_state")),
                     ("Selected lessons", len(lessons.get("selected", []))),
                     ("Excluded lessons", len(lessons.get("excluded", [])))]),
            "<p class=\"muted\">Presence and matching hashes do not verify applicability, authorship or correctness.</p></section>",
            _details("File relations and reuse candidates", quality),
            _details("Selected and excluded lessons, with reasons", data.get("lessons")),
            _details("Task evidence, scope and continuation", continuation),
            _details("Source-record identities", data.get("task_record_sha256s")),
        ]
    content += [
        "<section><h2>Observation limits</h2>",
        "<p>No execution or acceptance authority. Whole-work usage remains unknown.</p>",
        "<ul>" + "".join("<li>" + _text(item) + "</li>" for item in data.get("limitations", [])) + "</ul></section>",
        "<details><summary>Complete observation / JSON</summary><pre id=\"observation-json\">",
        html.escape(canonical, quote=True), "</pre></details></main>",
        "<footer><p class=\"identity\">Observation SHA-256 (canonical JSON): <code>",
        hashlib.sha256(canonical.encode("ascii")).hexdigest(), "</code></p>",
        "<p class=\"muted\">Project records own the work. This page contains no actions, scripts or remote resources.</p></footer>",
    ]
    css_hash = base64.b64encode(hashlib.sha256(CSS.encode("ascii")).digest()).decode("ascii")
    csp = "default-src 'none'; base-uri 'none'; form-action 'none'; style-src 'sha256-" + css_hash + "'"
    head = (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" content="' + html.escape(csp, quote=True) + '">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>AIDE task brief</title><style>' + CSS + '</style></head><body>'
    )
    return (head + "".join(content) + "</body></html>\n").encode("ascii", "xmlcharrefreplace").decode("ascii")


def render(data):
    """Return a bounded document, or refuse malformed presentation input."""
    try:
        if not isinstance(data, dict) or data.get("schema_version") != "aide.task-brief.v1":
            raise ValueError("unsupported brief")
        if data.get("result") not in {"OBSERVED", "PARTIAL", "REFUSED"}:
            raise ValueError("unknown observation state")
        if data.get("acceptance_verified") is not False or data.get("execution_admitted") is not False:
            raise ValueError("brief authority boundary is invalid")
        canonical = canonical_json(data)
        if len(canonical.encode("ascii")) > MAX_INPUT_BYTES:
            raise ValueError("brief exceeds 64 KiB")
        if data["result"] != "REFUSED":
            if not isinstance(data["continuation"]["task"], dict) or not isinstance(data["quality"], dict):
                raise ValueError("invalid component")
            if data["lessons"] is not None and not isinstance(data["lessons"], dict):
                raise ValueError("invalid lessons")
        output = _page(data, canonical)
        if len(output.encode("ascii")) > MAX_HTML_BYTES:
            raise ValueError("HTML exceeds 512 KiB")
        return output
    except (TypeError, KeyError, AttributeError, RecursionError) as error:
        raise ValueError("malformed brief projection") from error
