# Summary-only SQLite policy audit

The workflow audits a local query sandbox that permits SELECT, INSERT, UPDATE
and DELETE on `public_data` and denies all four on `protected_data`. The
16-request inventory is the Cartesian product of those operations, two table
roles and two parameter variants. It is a standard positive/negative policy
matrix, not selected by searching capacities or spectra. No third-party package,
external target or arbitrary SQL is executed. Each benign request starts with
the same two-row in-memory database. Thus choices are independent; this is not
a certificate for a stateful unrestricted SQL history.

Primary API support checked on 2026-10-24:
https://www.sqlite.org/c3ref/set_authorizer.html
https://docs.python.org/3.12/library/sqlite3.html#sqlite3.Connection.set_authorizer

SQLite documents the callback as a statement-preparation authorization mechanism,
including query sandbox use. The harness uses real Python `sqlite3.set_authorizer`,
zero statement-cache entries and fresh connections, so callbacks are not replaced
by fabricated outcome labels or bypassed by cached statement reuse. The callback
only records action codes and returns OK or DENY; it does not modify its database.
Raw SQL templates, bound parameters, callback records, rows and authorization
errors are retained. Syntax/other errors cannot be counted as expected denials.
This is an owned configuration audit grounded in a public security API, not an
independent deployment, source extraction for all SQLite or a vulnerability case.

## Source, disclosure and collection contract

One normalized trace is the complete bank request: operation, table role,
parameter variant and observed allow/deny. The fixed inventory is exhausted to
obtain the 16-event, horizon-one source language. Two output predicates identify
read versus mutation and public versus protected, producing four ordered classes.
The consumer knows the sandbox policy and bank, but receives only distinct
counts in the allow and deny buckets, not selected query identities. This is a
restricted information-sharing policy; no cryptographic privacy or log
authenticity property is claimed.

The sender validates every bank ID before deduplication and retains exact
distinct IDs; duplicate executions do not change counts. The universe needs at
most 16 IDs (a 2-byte bitset suffices in principle, not measured Python memory),
16 source-capacity executions and two exported integer counts. The implemented
collector uses a Python set, not that ideal bitset. Raw callbacks and selected
identities are retained for local reproducibility but never passed to the
summary-routing functions. Changing the bank, schema, callback or preparation
policy requires new source correspondence. Stateful queries, prepared-statement
reuse, arbitrary SQL and authenticated private collection require other evidence.

## Comparators and actual actions

All 65,536 labelled subsets induce 81 distinct count reports. Every report is
compared using the same N,n with the once-prefix producer/checker, ordinary
per-candidate matching, separately implemented per-outcome circulation and the
existing cardinality-plus-exclusion relaxation. All exact methods agree with
direct subset outcomes. Four catalogues (none, all, read-policy diagnostics,
mutation-policy diagnostics) give 324 queries. Cardinality adds 21 finite
branches, changes 22 complete-feasibility answers, 14 catalogue-sufficiency
answers and 14 next-candidate choices. All zero-difference rows are retained.

Four executed campaigns are public smoke (one default public probe per verb),
default policy (both table roles per verb), census and duplicate smoke. The
default-policy and census spectra do not change; both smoke reports do.
For public smoke, n=(4,0), exact first omissions are {0,1}; cardinality adds
3 and COMPLETE. With the existing mutation-policy catalogue {2,3}, exact routing
has no first-omission candidate, while cardinality dispatches protected INSERT
probe 6. That actual call is denied and adds one new distinct trace: this is not
a redundant-execution result. The new report (4,1) has exact outcomes {0,1,3};
the actual selected campaign still omits protected-read class 1. The extra
diagnostic has useful later-class evidence but does not address the original
possible first omissions. The result demonstrates a changed audit decision,
not measured field benefit, detector improvement or an across-the-board saving.

Seven rotating-order timing batches after one untimed pass record all 81 reports.
The summary-only prefix, matching, circulation and cardinality arms receive
identical N,n. A separate full prefix construction includes source construction and witness generation; checker
cost includes complete source replay; matching/circulation/cardinality receive
only N,n. These are explicitly different boundaries, not a fair end-to-end
speed competition. One actual diagnostic-call interval includes fresh database
setup, callback installation, execution and close. Full raw timings, environment,
positive and negative decision results are retained separately.

```sh
python -B -m src.sqlite_summary --output results/fresh-sqlite-summary
python -B -m src.sqlite_summary --output results/sqlite-summary --verify --table ../paper/generated/sqlite-summary.tex
python -B -m unittest tests.test_sqlite_summary -v
```
