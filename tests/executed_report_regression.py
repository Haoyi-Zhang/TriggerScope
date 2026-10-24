import copy
import unittest
from src.executed_report import application, derive, study


class ExecutedReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records, cls.summary = study()

    def test_counts_and_frontier_dispatch(self):
        result = self.summary
        self.assertEqual(result['capacity'], [[1,1,0,0],[0,0,1,1]])
        self.assertEqual(result['count_report'], [1,1])
        self.assertEqual(result['exact_spectrum'], [0,1])
        self.assertEqual(result['cardinality_spectrum'], [0,1,2])
        self.assertIsNone(result['exact_action']['next_test_candidate'])
        self.assertEqual(result['relaxed_action']['next_test_candidate'], 2)
        self.assertFalse(result['dispatch_adds_distinct_evidence'])

    def test_dropped_source_or_probe_is_rejected(self):
        for edit in ('source', 'probe', 'output', 'trace', 'raw-result'):
            records = copy.deepcopy(self.records)
            if edit == 'source': records['source_executions'].pop()
            elif edit == 'probe': records['source_executions'][0]['stdout'] = 'RESULT [1,0,0]\n'
            elif edit == 'output': records['source_executions'][0]['output'] = [0,0,0]
            elif edit == 'trace': records['source_executions'][0]['trace'] = [1]
            else: records['source_executions'][0]['stdout'] = records['source_executions'][0]['stdout'].replace('RESULT [1, 0, 0]', 'RESULT [0, 0, 0]')
            with self.assertRaises(ValueError): derive(records)

    def test_invalid_source_inputs_are_rejected(self):
        for value in (-1, 4, True, 0.0, '0'):
            with self.assertRaises(ValueError): application(value)


if __name__ == '__main__': unittest.main()
