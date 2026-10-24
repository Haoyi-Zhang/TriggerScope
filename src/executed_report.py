"""An owned four-input execution/report control, not an Android observation.

The child contains four reviewed branches with one emitted event each. Exhaustive
execution binds this finite source to the declared horizon-one language. Routing
receives counts only, not the captured selection or its actual omitted class.
"""
from pathlib import Path
import argparse
import json
import subprocess
import sys

from .androlog_adapter import adapt_sessions, parse_session
from .checker import check
from .producer import certify
from .summary_audit import audit_decision, cardinality_spectrum, matching_spectrum


def application(case):
    """Four benign policy-probe branches; all accepted inputs are enumerated."""
    if type(case) is not int or not 0 <= case < 4:
        raise ValueError('case must be an integer in 0..3')
    if case == 0:
        print('OWNED_TRACE STATEMENT=left-check')
        return [1, 0, 0]
    if case == 1:
        print('OWNED_TRACE STATEMENT=right-check')
        return [0, 1, 0]
    if case == 2:
        print('OWNED_TRACE STATEMENT=read-check')
        return [0, 0, 1]
    print('OWNED_TRACE STATEMENT=idle-check')
    return [0, 0, 0]


def declared_model():
    return {'events': [{'kind': i, 'value': 0, 'context': 0,
                        'bucket': 0 if i < 2 else 1} for i in range(4)],
            'monitors': [{'op': 'ever', 'guard': {'field': 'kind', 'equals': i}}
                         for i in range(3)],
            'triggers': [0, 1, 2], 'horizon': 1, 'min_length': 1,
            'environment_locked': True, 'report_modulus': 1}


PROBE_MAP = {'STATEMENT='+label: i for i, label in enumerate(
    ('left-check', 'right-check', 'read-check', 'idle-check'))}


def capture(case):
    result = subprocess.run([sys.executable, '-B', '-m', 'src.executed_report',
                             '--child', str(case)], cwd=Path(__file__).resolve().parents[1],
                            capture_output=True, text=True, encoding='utf-8',
                            timeout=5, check=True)
    lines = result.stdout.splitlines()
    trace = parse_session(lines, 'OWNED_TRACE', PROBE_MAP)
    outputs = [json.loads(line[7:]) for line in lines if line.startswith('RESULT ')]
    if len(outputs) != 1 or trace != (case,):
        raise ValueError('source execution/probe mismatch')
    return {'case': case, 'stdout': result.stdout, 'stderr': result.stderr,
            'returncode': result.returncode, 'trace': list(trace), 'output': outputs[0]}


def derive(records):
    """Recheck the complete control and its summary-only decision independently."""
    source = records['source_executions']
    if [x['case'] for x in source] != list(range(4)):
        raise ValueError('incomplete finite input enumeration')
    expected = [[1,0,0], [0,1,0], [0,0,1], [0,0,0]]
    for row, output in zip(source, expected):
        trace = parse_session(row['stdout'].splitlines(), 'OWNED_TRACE', PROBE_MAP)
        outputs = [json.loads(line[7:]) for line in row['stdout'].splitlines()
                   if line.startswith('RESULT ')]
        if (row['returncode'] != 0 or row['stderr'] or list(trace) != [row['case']]
                or row['trace'] != list(trace) or row['output'] != output or outputs != [output]):
            raise ValueError('source transcript mismatch')
    selected = records['selected_executions']
    if [x['case'] for x in selected] != [0, 2, 0]:
        raise ValueError('selection changed')
    for row in selected + [records['relaxed_dispatch']]:
        if row != source[row['case']]:
            raise ValueError('execution differs from exhaustive source control')
    model = declared_model()
    all_source = adapt_sessions(model, [x['trace'] for x in source])
    if all_source['allocation'] != all_source['capacity']:
        raise ValueError('source model contains unexecuted or missing words')
    report = adapt_sessions(model, [x['trace'] for x in selected])
    certificate = certify(model, report['count_report'])
    checked = check(model, report['count_report'], certificate)
    N, n = report['capacity'], report['count_report']
    exact, loose = checked['spectrum'], cardinality_spectrum(N, n)
    if matching_spectrum(N, n) != exact:
        raise ValueError('ordinary same-information matching disagrees')
    exact_action = audit_decision(4, exact, [2])
    loose_action = audit_decision(4, loose, [2])
    if records['relaxed_dispatch']['case'] != loose_action['next_test_candidate']:
        raise ValueError('dispatched candidate mismatch')
    after = adapt_sessions(model, [x['trace'] for x in selected + [records['relaxed_dispatch']]])
    if after['count_report'] != n or after['distinct_words'] != report['distinct_words']:
        raise ValueError('duplicate control unexpectedly added evidence')
    return {'source_inputs_executed': 4, 'selection_executions': 3,
            'distinct_selected_traces': report['distinct_traces'],
            'duplicate_executions_removed': report['duplicate_sessions_removed'],
            'capacity': N, 'count_report': n, 'exact_spectrum': exact,
            'cardinality_spectrum': loose, 'same_information_matching_agrees': True,
            'diagnostic_catalogue': [2], 'exact_action': exact_action,
            'relaxed_action': loose_action, 'extra_dispatches_in_this_control': 1,
            'dispatch_adds_distinct_evidence': False,
            'scope': 'owned exhaustive four-input horizon-one control; not device or third-party tool validation'}


def study():
    records = {'source_executions': [capture(i) for i in range(4)],
               'selected_executions': [capture(i) for i in (0,2,0)],
               'relaxed_dispatch': capture(2)}
    return records, derive(records)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--child', type=int)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.child is not None:
        print('RESULT '+json.dumps(application(args.child)))
        return
    if args.output is None or args.output.exists():
        parser.error('a fresh --output directory is required')
    records, summary = study()
    args.output.mkdir(parents=True)
    for name, value in (('executions', records), ('summary', summary)):
        (args.output/(name+'.json')).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
