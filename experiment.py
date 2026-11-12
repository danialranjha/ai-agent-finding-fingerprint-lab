"""Contained finding-identity assay. Fixture source is parsed, never executed."""
import ast
import hashlib
import json
import posixpath
from pathlib import Path

METHODS = ("line_position", "function_text", "structural")
BASE = 'def check_note(note):\n    record("SITE_A", note)\n    return note\n'
TWO_SITES = ('def check_note(note):\n    record("SITE_A", note)\n'
             '    record("SITE_B", note)\n    return note\n')


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_path(path):
    """Lexical POSIX fixture paths, not host filesystem canonicalization."""
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        raise ValueError("expected a nonempty POSIX relative path")
    normalized = posixpath.normpath(path)
    if normalized in (".", "..") or normalized.startswith(("/", "../")):
        raise ValueError("path must name a file inside the fixture root")
    return normalized


def observation(source=BASE, path="src/notes.py", symbol="check_note",
                weakness_class="FIXTURE-CLASS-A", site="SITE_A"):
    return dict(source=source, path=path, symbol=symbol,
                weakness_class=weakness_class, site=site)


def locate(item):
    """Find an exact qualified function and its supplied inert record marker."""
    tree = ast.parse(item["source"])
    functions = {}

    def collect(body, prefix=()):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = ".".join((*prefix, node.name))
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if name in functions:
                        raise ValueError("ambiguous qualified function")
                    functions[name] = node
                collect(node.body, (*prefix, node.name))

    collect(tree.body)
    if item["symbol"] not in functions:
        raise ValueError("qualified function not found")
    function = functions[item["symbol"]]
    calls = []

    def find_sites(node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "record" and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == item["site"]):
            calls.append(node)
        for child in ast.iter_child_nodes(node):
            find_sites(child)

    for node in function.body:
        find_sites(node)
    if len(calls) != 1:
        raise ValueError("expected exactly one supplied site in the function")
    lines = item["source"].splitlines(keepends=True)
    text = "".join(lines[function.lineno - 1:function.end_lineno])
    return {"line": calls[0].lineno, "function_start": function.lineno,
            "function_end": function.end_lineno, "function_text": text}


def key_components(item, method):
    location = locate(item)
    path = normalize_path(item["path"])
    symbol = item["symbol"]
    weakness_class = item["weakness_class"]
    if not isinstance(weakness_class, str) or not weakness_class:
        raise ValueError("a supplied weakness class is required")
    base = [path, symbol, weakness_class]
    if method == "structural":
        return base
    if method == "line_position":
        return base + [location["line"]]
    if method == "function_text":
        return base + [sha256(location["function_text"])]
    raise ValueError("unknown identity method")


def fingerprint(item, method):
    components = key_components(item, method)
    return {"components": components, "digest": sha256(canonical(components))}


def record_event(index, key):
    """A local association sink; stores no vulnerability verdict."""
    if key in index:
        return {"event": "UPDATE", "record_id": index[key]}
    identifier = "record-" + str(len(index) + 1)
    index[key] = identifier
    return {"event": "CREATE", "record_id": identifier}


def cases():
    return [
        ("unchanged", "ordinary twin", observation(), observation()),
        ("leading_comments", "line shift only", observation(),
         observation(source="# one\n# two\n# three\n" + BASE)),
        ("body_comment", "comment after supplied site", observation(),
         observation(source=BASE.replace("    return", "    # note\n    return"))),
        ("formatting", "whitespace in supplied statement", observation(),
         observation(source=BASE.replace('record("SITE_A", note)', 'record( "SITE_A",  note )'))),
        ("path_alias", "lexically equivalent relative path", observation(),
         observation(path="./src/tmp/../notes.py")),
        ("renamed_symbol", "structural distinction", observation(),
         observation(source=BASE.replace("check_note", "review_note"), symbol="review_note")),
        ("moved_file", "structural distinction", observation(), observation(path="lib/notes.py")),
        ("changed_class", "structural distinction", observation(),
         observation(weakness_class="FIXTURE-CLASS-B")),
        ("changed_body", "same metadata with different body, no verdict inference", observation(),
         observation(source=BASE.replace('record("SITE_A", note)', 'record("SITE_A", str(note))'))),
        ("two_sites", "different supplied sites in one function/class", observation(source=TWO_SITES),
         observation(source=TWO_SITES, site="SITE_B")),
    ]


def run():
    rows = []
    for name, family, before, after in cases():
        for method in METHODS:
            left, right = fingerprint(before, method), fingerprint(after, method)
            index = {}
            events = [record_event(index, left["digest"]), record_event(index, right["digest"])]
            rows.append({"case": name, "family": family, "method": method,
                         "before": {**before, "location": locate(before), **left},
                         "after": {**after, "location": locate(after), **right},
                         "equal": left["digest"] == right["digest"],
                         "events": events, "record_count": len(index)})
    return {"schema": 1, "scope": "inert source and supplied metadata; no detector or model",
            "case_count": 10, "method_count": 3, "paired_comparisons": len(rows), "rows": rows}


def evidence(result):
    text = ["# Finding identity: measured fixture evidence", "",
            "Ten designed pairs, three methods, 30 comparisons. No sampled attacks, model, detector or target execution.",
            "Equal means the two supplied records share a key, not that a vulnerability is real, unchanged or fixed.", "",
            "| Source/metadata pair | Line position | Function text | Structural |",
            "|---|---|---|---|"]
    for name, _, _, _ in cases():
        rows = [r for r in result["rows"] if r["case"] == name]
        cells = ["same / UPDATE" if r["equal"] else "different / CREATE" for r in rows]
        text.append("| " + " | ".join([name, *cells]) + " |")
    text += ["", "## Exact leading-comment trace", "",
             "The supplied SITE_A statement moves from line 2 to line 5. Its path, qualified function and supplied class do not change.", ""]
    pair = next(r for r in result["rows"] if r["case"] == "leading_comments")
    for label in ["before", "after"]:
        text += [label.title() + ":", "```python", pair[label]["source"].rstrip(), "```", ""]
    for row in [r for r in result["rows"] if r["case"] == "leading_comments"]:
        text += ["- " + row["method"] + ": `" + canonical(row["before"]["components"]) + "` → `"
                 + canonical(row["after"]["components"]) + "`; second event "
                 + row["events"][1]["event"] + ", " + str(row["record_count"]) + " local record(s)."]
    text += ["", "## Grouping limit", "",
             "two_sites supplies SITE_A at line 2 and SITE_B at line 3 in the same function, file and class.",
             "Line position produces two local records. Function text and Structural each produce one: their keys intentionally omit the site.",
             "This is a design-level grouping collision, not a SHA-256 collision. No finding truth is judged.", "",
             "changed_body also keeps Structural equal. A stable issue association cannot certify a fresh security verdict.",
             "All complete source strings, tuples, digests, locations and events are in artifacts/run.json.", ""]
    return "\n".join(text)


if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    result = run()
    (root / "artifacts").mkdir(exist_ok=True)
    (root / "artifacts/run.json").write_text(json.dumps(result, indent=2) + "\n")
    (root / "evidence.md").write_text(evidence(result))
    print("Recorded 10 designed pairs, 3 methods, 30 paired comparisons.")
