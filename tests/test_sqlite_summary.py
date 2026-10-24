import copy
import json
from pathlib import Path
import unittest
from src.sqlite_summary import bank, counts, derive, execute


class SQLiteSummaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = json.loads((Path(__file__).resolve().parents[1]/"results/sqlite-summary/executions.json").read_text())

    def test_real_authorizer_bank(self):
        for probe in bank():
            actual = execute(probe["id"])
            # JSON-normalize only the documented SQLite result-row tuples.
            self.assertEqual(json.loads(json.dumps(actual)), self.records["source"][probe["id"]])

    def test_missing_source_and_corrupt_binding(self):
        missing = copy.deepcopy(self.records)
        missing["source"].pop()
        with self.assertRaises(ValueError): derive(missing)
        corrupt = copy.deepcopy(self.records)
        corrupt["source"][0]["event"]["bucket"] = 1
        with self.assertRaises(ValueError): derive(corrupt)

    def test_distinctness_validation_precedes_set_equality(self):
        events = [x["event"] for x in self.records["source"]]
        self.assertEqual(counts([0,4,8,12,0],events), [4,0])
        for ids in ([0,False], [0,0.0], [-1], [16]):
            with self.assertRaises(ValueError): counts(ids,events)
        for index in (True, 0.0, -1, 16):
            with self.assertRaises(ValueError): execute(index)
