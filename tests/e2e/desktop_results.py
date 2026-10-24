"""Fail-closed public results for installed desktop acceptance (no HID imports)."""
import argparse
import json
from pathlib import Path

BASELINE = '5dc4b7c83709a57773724e87fe4781a2f3cd0be5'
COMMON = {'ready', 'immediate-access', 'approved-registration', 'approved-assertion', 'policy-set',
          'restart', 'policy-retained', 'retained-restart', 'retained-rerun', 'setup-rerun',
          'rp-policy-allowed', 'rp-policy-unlisted', 'identification', 'reset', 'seccomp'}
REQUIRED = {
    'fresh': COMMON | {'denied-registration', 'denied-assertion', 'timeout-registration', 'timeout-assertion',
                      'cancel-registration', 'cancel-assertion', 'restart-registration', 'restart-assertion',
                      'notification-missing', 'notification-recovery', 'forced-pin-change-blocked',
                      'forced-pin-change', 'retained-pin-change', 'retained-notification-recovery'} |
             {f'recovered-{mode}-{kind}' for mode in ('denied', 'timeout', 'cancel', 'restart')
              for kind in ('registration', 'assertion')},
    'upgrade': COMMON | {'pin-missing', 'update', 'retained-update'},
}


def scenario_pass(result):
    rows = result.get('events', [])
    metadata = result.get('metadata', {})
    scenario = metadata.get('scenario')
    return (scenario in REQUIRED and metadata.get('native_executed') is True
            and result.get('cleanup') is True and bool(rows)
            and all(row.get('status') == 'pass' for row in rows)
            and REQUIRED[scenario] <= {row.get('case') for row in rows})


def seccomp_event(result):
    return next((row for row in result.get('events', []) if row.get('case') == 'seccomp'), None)


def seccomp_summary(result):
    """One line on whether the daemon made a system call outside @system-service."""
    event = seccomp_event(result)
    if event is None:
        return 'NOT CHECKED'
    if 'error_type' in event:
        return f"FAILED: the check did not complete ({event['error_type']})"
    refused = event.get('refused', [])
    calls = sorted({f"{row.get('name') or 'syscall'} {row.get('syscall')}" for row in refused})
    canaries = event.get('canaries', {})
    lost = len(event.get('lost', [])) + len(event.get('missed_kernel_messages', []))
    return '; '.join([
        'PASS' if event.get('status') == 'pass' else 'FAILED',
        f'refused calls for pqkey: {len(refused)}' + (f" ({', '.join(calls)})" if calls else ''),
        'canaries: ' + ', '.join(f"{phase} {'logged' if seen else 'MISSING'}" for phase, seen in canaries.items()),
        f'lost records: {lost}',
        'filter counts: ' + '/'.join(event.get('filter_counts', [])),
    ])


def initialize(directory, source):
    directory.mkdir(parents=True, exist_ok=True)
    for scenario in REQUIRED:
        folder = directory / scenario
        folder.mkdir(exist_ok=True)
        (folder / 'result.json').write_text(json.dumps({
            'metadata': {'scenario': scenario, 'source': source, 'baseline': BASELINE, 'native_executed': False},
            'events': [], 'cleanup': False, 'acceptance_pass': False}, indent=2) + '\n')
    return finalize(directory, 'incomplete')


def finalize(directory, workflow_status):
    rows = []
    for scenario in REQUIRED:
        try:
            result = json.loads((directory / scenario / 'result.json').read_text())
            cleanup = (directory / scenario / 'runner-cleanup-status').read_text().strip() == '0'
            passed = result.get('metadata', {}).get('scenario') == scenario and scenario_pass(result) and cleanup
        except (OSError, ValueError, TypeError, KeyError):
            result, passed, cleanup = {}, False, False
        rows.append({'scenario': scenario, 'passed': passed, 'runner_cleanup': cleanup,
                     'seccomp': seccomp_event(result), 'result': result})
    passed = workflow_status == 'success' and all(row['passed'] for row in rows)
    report = {'workflow_status': workflow_status, 'acceptance_pass': passed, 'scenarios': rows,
              'interaction': 'automated interaction with real Dunst/dmenu; no physical human presence claim'}
    (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    lines = ['# Installed Linux desktop acceptance', '', '**' + ('PASS' if passed else 'INCOMPLETE / FAILED') + '**', '',
             report['interaction'], '', f'Workflow stage status: `{workflow_status}`.', '']
    for row in rows:
        lines.append(f"- {row['scenario']}: {'PASS' if row['passed'] else 'INCOMPLETE / FAILED'}; runner cleanup: {row['runner_cleanup']}")
        for event in row['result'].get('events', []):
            lines.append(f"  - {event['case']}: {event['status']}")
    lines += ['', '## System call filter', '',
              'The daemon runs with `SystemCallFilter=@system-service` and `SystemCallErrorNumber=EPERM` from an'
              ' acceptance-only drop-in, and the kernel journals each call the filter refuses. PASS: no record'
              ' names pqkey, both canary refusals were journaled, and no record was lost.', '']
    lines.extend(f"- {row['scenario']}: {seccomp_summary(row['result'])}" for row in rows)
    (directory / 'summary.md').write_text('\n'.join(lines) + '\n')
    return passed


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('--initialize', metavar='SOURCE_SHA')
    parser.add_argument('--workflow-status', default='incomplete')
    args = parser.parse_args()
    if args.initialize:
        initialize(args.directory, args.initialize)
    else:
        raise SystemExit(0 if finalize(args.directory, args.workflow_status) else 1)
