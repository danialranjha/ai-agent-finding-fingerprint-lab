import unittest
import experiment as e


class IdentityTests(unittest.TestCase):
    def test_hand_authored_matrix(self):
        expected = {
            "unchanged": (True, True, True),
            "leading_comments": (False, True, True),
            "body_comment": (True, False, True),
            "formatting": (True, False, True),
            "path_alias": (True, True, True),
            "renamed_symbol": (False, False, False),
            "moved_file": (False, False, False),
            "changed_class": (False, False, False),
            "changed_body": (True, False, True),
            "two_sites": (False, True, True),
        }
        result = e.run()
        self.assertEqual(len(result["rows"]), 30)
        for name, flags in expected.items():
            for method, flag in zip(e.METHODS, flags):
                row = next(r for r in result["rows"] if r["case"] == name and r["method"] == method)
                with self.subTest(case=name, method=method):
                    self.assertEqual(row["equal"], flag)
                    self.assertEqual(row["events"][1]["event"], "UPDATE" if flag else "CREATE")
                    self.assertEqual(row["record_count"], 1 if flag else 2)

    def test_leading_comment_exact_tuple(self):
        a, b = e.observation(), e.observation(source="# one\n# two\n# three\n" + e.BASE)
        self.assertEqual(e.key_components(a, "line_position"), ["src/notes.py", "check_note", "FIXTURE-CLASS-A", 2])
        self.assertEqual(e.key_components(b, "line_position"), ["src/notes.py", "check_note", "FIXTURE-CLASS-A", 5])
        self.assertEqual(e.key_components(b, "structural"), ["src/notes.py", "check_note", "FIXTURE-CLASS-A"])

    def test_site_collision_is_retained(self):
        a, b = e.observation(source=e.TWO_SITES), e.observation(source=e.TWO_SITES, site="SITE_B")
        self.assertNotEqual(e.locate(a)["line"], e.locate(b)["line"])
        self.assertEqual(e.fingerprint(a, "structural"), e.fingerprint(b, "structural"))

    def test_class_separates_identity(self):
        self.assertNotEqual(e.fingerprint(e.observation(), "structural"),
                            e.fingerprint(e.observation(weakness_class="FIXTURE-CLASS-B"), "structural"))

    def test_changed_body_is_not_a_verdict(self):
        row = next(r for r in e.run()["rows"] if r["case"] == "changed_body" and r["method"] == "structural")
        self.assertNotEqual(row["before"]["source"], row["after"]["source"])
        self.assertTrue(row["equal"])
        self.assertNotIn("verdict", row)

    def test_path_normalization_and_rejection(self):
        self.assertEqual(e.normalize_path("./src/tmp/../notes.py"), "src/notes.py")
        for path in ("", ".", "..", "../notes.py", "/notes.py", "//host/file", "src/../../file", "a\\b", "a\x00b"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                e.normalize_path(path)

    def test_qualified_symbols_separate_classes(self):
        source = 'class A:\n    def check(self):\n        record("SITE_A", 1)\nclass B:\n    def check(self):\n        record("SITE_A", 1)\n'
        a, b = e.observation(source=source, symbol="A.check"), e.observation(source=source, symbol="B.check")
        self.assertNotEqual(e.fingerprint(a, "structural"), e.fingerprint(b, "structural"))

    def test_duplicate_and_missing_symbols(self):
        with self.assertRaises(ValueError):
            e.locate(e.observation(source=e.BASE + e.BASE))
        with self.assertRaises(ValueError):
            e.locate(e.observation(symbol="missing"))

    def test_missing_or_duplicate_sites(self):
        for source in ('def check_note(note):\n    pass\n', e.BASE.replace('    return note', '    record("SITE_A", note)')):
            with self.subTest(source=source), self.assertRaises(ValueError):
                e.locate(e.observation(source=source))

    def test_nested_site_not_attributed_to_parent(self):
        source = 'def check_note(note):\n    def inner():\n        record("SITE_A", note)\n'
        with self.assertRaises(ValueError):
            e.locate(e.observation(source=source))
        self.assertEqual(e.locate(e.observation(source=source, symbol="check_note.inner"))["line"], 3)

    def test_invalid_inputs(self):
        with self.assertRaises(SyntaxError):
            e.locate(e.observation(source="not python !!!"))
        with self.assertRaises(ValueError):
            e.fingerprint(e.observation(), "unknown")
        with self.assertRaises(ValueError):
            e.fingerprint(e.observation(weakness_class=""), "structural")

    def test_record_association_and_tuple_encoding(self):
        index = {}
        self.assertEqual(e.record_event(index, "a"), {"event": "CREATE", "record_id": "record-1"})
        self.assertEqual(e.record_event(index, "a"), {"event": "UPDATE", "record_id": "record-1"})
        self.assertEqual(e.record_event(index, "b"), {"event": "CREATE", "record_id": "record-2"})
        self.assertNotEqual(e.canonical(["a,b", "c"]), e.canonical(["a", "b,c"]))


if __name__ == "__main__":
    unittest.main()
