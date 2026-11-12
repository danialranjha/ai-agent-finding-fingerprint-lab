# Finding identity: measured fixture evidence

Ten designed pairs, three methods, 30 comparisons. No sampled attacks, model, detector or target execution.
Equal means the two supplied records share a key, not that a vulnerability is real, unchanged or fixed.

| Source/metadata pair | Line position | Function text | Structural |
|---|---|---|---|
| unchanged | same / UPDATE | same / UPDATE | same / UPDATE |
| leading_comments | different / CREATE | same / UPDATE | same / UPDATE |
| body_comment | same / UPDATE | different / CREATE | same / UPDATE |
| formatting | same / UPDATE | different / CREATE | same / UPDATE |
| path_alias | same / UPDATE | same / UPDATE | same / UPDATE |
| renamed_symbol | different / CREATE | different / CREATE | different / CREATE |
| moved_file | different / CREATE | different / CREATE | different / CREATE |
| changed_class | different / CREATE | different / CREATE | different / CREATE |
| changed_body | same / UPDATE | different / CREATE | same / UPDATE |
| two_sites | different / CREATE | same / UPDATE | same / UPDATE |

## Exact leading-comment trace

The supplied SITE_A statement moves from line 2 to line 5. Its path, qualified function and supplied class do not change.

Before:
```python
def check_note(note):
    record("SITE_A", note)
    return note
```

After:
```python
# one
# two
# three
def check_note(note):
    record("SITE_A", note)
    return note
```

- line_position: `["src/notes.py","check_note","FIXTURE-CLASS-A",2]` → `["src/notes.py","check_note","FIXTURE-CLASS-A",5]`; second event CREATE, 2 local record(s).
- function_text: `["src/notes.py","check_note","FIXTURE-CLASS-A","f946092fb74fc76c1441200722c35ffe2dc6d0c9a9a29eaeffe21a8605aaba38"]` → `["src/notes.py","check_note","FIXTURE-CLASS-A","f946092fb74fc76c1441200722c35ffe2dc6d0c9a9a29eaeffe21a8605aaba38"]`; second event UPDATE, 1 local record(s).
- structural: `["src/notes.py","check_note","FIXTURE-CLASS-A"]` → `["src/notes.py","check_note","FIXTURE-CLASS-A"]`; second event UPDATE, 1 local record(s).

## Grouping limit

two_sites supplies SITE_A at line 2 and SITE_B at line 3 in the same function, file and class.
Line position produces two local records. Function text and Structural each produce one: their keys intentionally omit the site.
This is a design-level grouping collision, not a SHA-256 collision. No finding truth is judged.

changed_body also keeps Structural equal. A stable issue association cannot certify a fresh security verdict.
All complete source strings, tuples, digests, locations and events are in artifacts/run.json.
