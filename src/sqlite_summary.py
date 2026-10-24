"""A bounded SQLite authorizer audit, with summary-only routing consumers.

No arbitrary SQL is accepted: the complete benign request bank below is fixed.
Every request gets a fresh in-memory database and uncached statement compilation.
"""
import argparse
import itertools
import json
from pathlib import Path
import platform
import sqlite3
import statistics
import time

from .producer import certify, enumerate_model, matching_prefix, spectrum
from .checker import check
from .baseline import exact_spectrum
from .summary_audit import audit_decision, cardinality_spectrum, matching_spectrum

VERBS = ("select", "insert", "update", "delete")


def bank():
    # SQL operation, public/protected table, two parameter values. No search over
    # matrices, capacities, report counts or spectra selects these requests.
    return [{"id":op*4+private*2+variant, "operation":verb,
             "kind":op, "private":private, "variant":variant}
            for op,verb in enumerate(VERBS) for private in (0,1) for variant in (0,1)]


def execute(index):
    if type(index) is not int or not 0 <= index < 16:
        raise ValueError("fixed request bank index")
    probe = bank()[index]
    db = sqlite3.connect(":memory:", cached_statements=0)
    callbacks = []
    try:
        for table in ("public_data","protected_data"):
            db.execute(f"CREATE TABLE {table}(id INTEGER PRIMARY KEY, value INTEGER)")
            db.executemany(f"INSERT INTO {table} VALUES (?,?)", [(0,10),(1,20)])
        db.commit()

        def authorizer(action, arg1, arg2, database, context):
            deny = arg1 == "protected_data" and action in (
                sqlite3.SQLITE_READ, sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE)
            callbacks.append([action,arg1,arg2,database,context,int(deny)])
            return sqlite3.SQLITE_DENY if deny else sqlite3.SQLITE_OK

        db.set_authorizer(authorizer)
        table = "protected_data" if probe["private"] else "public_data"
        templates = {"select":f"SELECT value FROM {table} WHERE id=?",
                     "insert":f"INSERT INTO {table} VALUES (?,30)",
                     "update":f"UPDATE {table} SET value=30 WHERE id=?",
                     "delete":f"DELETE FROM {table} WHERE id=?"}
        parameter = probe["variant"] + (2 if probe["operation"] == "insert" else 0)
        error = None
        try:
            rows = db.execute(templates[probe["operation"]], (parameter,)).fetchall()
        except sqlite3.DatabaseError as exc:
            error, rows = str(exc), []
        denied = any(x[-1] for x in callbacks)
        if (bool(error) != denied or denied != bool(probe["private"]) or not callbacks):
            raise ValueError("statement/authorizer contract mismatch")
        return {"probe":probe,"sql":templates[probe["operation"]],"parameter":parameter,
                "callbacks":callbacks,"denied":denied,"rows":rows,"error":error,
                "event":{"kind":probe["kind"],"value":probe["private"],
                         "context":probe["variant"],"bucket":int(denied)}}
    finally:
        db.close()


def model(records):
    return {"events":[r["event"] for r in records],
            "monitors":[{"op":"ever","guard":{"field":"kind","equals":0}},
                        {"op":"ever","guard":{"field":"value","equals":1}}],
            "triggers":[0,1],"horizon":1,"min_length":1,
            "environment_locked":False,"report_modulus":1}


def counts(indices, events):
    # Validate before deduplication. A duplicate run adds no distinct evidence.
    if any(type(i) is not int or not 0 <= i < len(events) for i in indices):
        raise ValueError("unknown or aliased probe identity")
    return [sum(events[i]["bucket"]==b for i in set(indices)) for b in (0,1)]


def derive(records):
    source = records["source"]
    if [r["probe"] for r in source] != bank():
        raise ValueError("complete fixed request bank required")
    for r in source:
        p = r["probe"]
        if (r["denied"] != bool(p["private"]) or not r["callbacks"]
                or any(x[-1] for x in r["callbacks"]) != r["denied"]
                or bool(r["error"]) != r["denied"]
                or r["event"] != {"kind":p["kind"],"value":p["private"],"context":p["variant"],"bucket":p["private"]}):
            raise ValueError("source execution/event binding")
    m = model(source)
    dag = enumerate_model(m)
    N = dag["capacity"]
    classes = [tuple(s) for s in dag["classes"]]
    class_for = [classes.index((int(r["probe"]["kind"]==0),r["probe"]["private"])) for r in source]
    # Independent labelled-subset oracle for every attainable count pair.
    oracle = {}
    for mask in range(1<<16):
        selected = [i for i in range(16) if mask>>i&1]
        n = tuple(counts(selected,m["events"]))
        represented = {class_for[i] for i in selected}
        outcome = next((c for c in range(4) if c not in represented),4)
        oracle.setdefault(n,set()).add(outcome)
    reports = []
    catalogues = [[],list(range(4)),[c for c,s in enumerate(classes) if s[0]],
                  [c for c,s in enumerate(classes) if not s[0]]]
    differences = {"extra_branches":0,"complete_feasibility":0,"sufficiency":0,"next_candidate":0}
    for n in itertools.product(range(9),repeat=2):
        cert = certify(m,list(n),dag)
        exact = check(m,list(n),cert)["spectrum"]
        if (exact != sorted(oracle[n]) or matching_spectrum(N,list(n)) != exact
                or exact_spectrum(N,list(n)) != exact):
            raise ValueError("prefix/checker/matching/circulation/subset mismatch")
        loose = cardinality_spectrum(N,list(n))
        differences["extra_branches"] += len(set(loose)-set(exact)-{4})
        differences["complete_feasibility"] += (4 in loose) != (4 in exact)
        decisions = []
        for q in catalogues:
            e,l = audit_decision(4,exact,q),audit_decision(4,loose,q)
            differences["sufficiency"] += e["catalogue_sufficient"] != l["catalogue_sufficient"]
            differences["next_candidate"] += e["next_test_candidate"] != l["next_test_candidate"]
            decisions.append({"catalogue":q,"exact":e,"cardinality":l})
        reports.append({"counts":list(n),"certificate":cert,"exact":exact,"cardinality":loose,"decisions":decisions})
    campaigns = []
    plans = {"public-smoke":[0,4,8,12],"default-policy":[0,2,4,6,8,10,12,14],
             "census":list(range(16)),"duplicate-smoke":[0,4,8,12,0]}
    for name,indices in plans.items():
        captured = records["campaigns"][name]
        if [r["probe"]["id"] for r in captured] != indices:
            raise ValueError("campaign plan")
        for r in captured:
            if r != source[r["probe"]["id"]]:
                raise ValueError("captured campaign differs from fixed source probe")
        n = counts(indices,m["events"])
        report = next(r for r in reports if r["counts"] == n)
        campaigns.append({"name":name,"executions":len(indices),"distinct":len(set(indices)),
                          "counts":n,"exact":report["exact"],"cardinality":report["cardinality"]})
    # The write-policy catalogue follows the operation inventory, not an outcome.
    q = catalogues[-1]
    smoke = campaigns[0]
    e,l = audit_decision(4,smoke["exact"],q),audit_decision(4,smoke["cardinality"],q)
    dispatch = records["dispatch"]
    c = l["next_test_candidate"]
    if c is None or e["next_test_candidate"] is not None or dispatch != source[dag["representatives"][c][0]]:
        raise ValueError("diagnostic routing contrast")
    after = counts(plans["public-smoke"]+[dispatch["probe"]["id"]],m["events"])
    return {"source_model":m,"capacity":N,"classes":dag["classes"],"reports":reports,
            "source_probes":16,"labelled_subsets":1<<16,"distinct_reports":len(reports),
            "catalogue_queries":len(reports)*len(catalogues),"differences":differences,"campaigns":campaigns,
            "dispatch":{"catalogue":q,"exact":e,"cardinality":l,"probe":dispatch["probe"]["id"],
                        "new_distinct_evidence":after!=smoke["counts"],"after_counts":after,
                        "after_exact":next(r["exact"] for r in reports if r["counts"]==after)},
            "collection_contract":{"max_private_identities":16,"minimum_identity_bitset_bytes":2,
                                   "exported_count_coordinates":2,"source_capacity_probes":16,
                                   "diagnostic_inventory":"read/write x public/protected; least bank probe per class"}}


def benchmark(summary):
    m,N=summary["source_model"],summary["capacity"]
    methods={"prefix_with_witnesses":lambda r:certify(m,r["counts"],enumerate_model(m)),
             "prefix_summary":lambda r:spectrum(N,r["counts"],matching_prefix(N,r["counts"])["prefix"]),
             "checker_full_source":lambda r:check(m,r["counts"],r["certificate"]),
             "matching_summary":lambda r:matching_spectrum(N,r["counts"]),
             "circulation_summary":lambda r:exact_spectrum(N,r["counts"]),
             "cardinality_summary":lambda r:cardinality_spectrum(N,r["counts"])}
    samples={name:[] for name in methods}
    # One untimed pass per method; seven rotating-order complete 81-report batches.
    for name,f in methods.items():
        for row in summary["reports"]: f(row)
    names=list(methods)
    for repeat in range(7):
        order=names[repeat%len(names):]+names[:repeat%len(names)]
        for name in order:
            start=time.perf_counter_ns()
            for row in summary["reports"]: methods[name](row)
            samples[name].append(time.perf_counter_ns()-start)
    return {"samples_batch_ns":samples,"reports_per_batch":81,"repeats":7,
            "median_ns_per_report":{n:statistics.median(v)/81 for n,v in samples.items()},
            "boundaries":"prefix_summary/matching/circulation/cardinality use same N,n; prefix_with_witnesses includes source construction/witnesses; checker full source replay; no common end-to-end speed claim",
            "python":platform.python_version(),"sqlite":sqlite3.sqlite_version,"platform":platform.platform()}


def export(summary,path):
    lines=[r"\begin{tabular}{@{}lrrll@{}}",r"\toprule",r"Campaign & Runs & Distinct & Exact & Cardinality\\",r"\midrule"]
    fmt=lambda xs:r"$\{"+",".join("C" if x==4 else str(x) for x in xs)+r"\}$"
    for c in summary["campaigns"]:
        lines.append(f'{c["name"]} & {c["executions"]} & {c["distinct"]} & '+fmt(c["exact"])+" & "+fmt(c["cardinality"])+r"\\")
    path.write_text("\n".join(lines+[r"\bottomrule",r"\end{tabular}"])+"\n",encoding="utf-8")


def main():
    # Both exported tables are derived from independently retained raw records.
    ap=argparse.ArgumentParser()
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--verify",action="store_true")
    ap.add_argument("--table",type=Path)
    a=ap.parse_args()
    if a.verify:
        records=json.loads((a.output/"executions.json").read_text(encoding="utf-8"))
        summary=derive(records)
        if summary!=json.loads((a.output/"summary.json").read_text(encoding="utf-8")):
            raise ValueError("retained summary mismatch")
    else:
        if a.output.exists(): raise ValueError("fresh output required")
        source=[execute(i) for i in range(16)]
        plans={"public-smoke":[0,4,8,12],"default-policy":[0,2,4,6,8,10,12,14],
               "census":list(range(16)),"duplicate-smoke":[0,4,8,12,0]}
        records={"source":source,"campaigns":{n:[execute(i) for i in ids] for n,ids in plans.items()},
                 "dispatch":execute(6)}
        summary=derive(records)
        measurement=benchmark(summary)
        start=time.perf_counter_ns(); actual=execute(summary["dispatch"]["probe"])
        measurement["diagnostic_call_ns"]=time.perf_counter_ns()-start
        if actual!=records["dispatch"]: raise ValueError("diagnostic replay")
        a.output.mkdir(parents=True)
        for n,v in (("executions",records),("summary",summary),("measurements",measurement)):
            (a.output/(n+".json")).write_text(json.dumps(v,indent=2)+"\n",encoding="utf-8")
    if a.table:
        export(summary,a.table)
        export_measurement(a.output,a.table.with_name("sqlite-summary-cost.tex"))
    print(json.dumps({k:summary[k] for k in ("source_probes","distinct_reports","labelled_subsets","catalogue_queries","differences","campaigns","dispatch")}))


def export_measurement(folder,path):
    measured=json.loads((folder/"measurements.json").read_text(encoding="utf-8"))
    if measured["reports_per_batch"]!=81 or measured["repeats"]!=7:
        raise ValueError("measurement denominator")
    labels={"prefix_summary":"Once prefix, summary", "matching_summary":"Per-candidate matching",
            "circulation_summary":"Per-outcome circulation", "cardinality_summary":"Cardinality + exclusion",
            "prefix_with_witnesses":"Source + prefix + witnesses", "checker_full_source":"Full source/certificate check"}
    lines=[r"\begin{tabular}{@{}lr@{}}",r"\toprule",r"Local boundary & Median $\mu$s/report\\",r"\midrule"]
    for key,label in labels.items():
        samples=measured["samples_batch_ns"][key]
        if len(samples)!=7 or any(type(x) is not int or x<=0 for x in samples):
            raise ValueError("raw timing samples")
        value=statistics.median(samples)/81
        if measured["median_ns_per_report"][key]!=value:
            raise ValueError("timing aggregate")
        lines.append(f"{label} & {value/1000:.3f}"+r"\\")
    if type(measured["diagnostic_call_ns"]) is not int or measured["diagnostic_call_ns"]<=0:
        raise ValueError("actual diagnostic timer")
    path.write_text("\n".join(lines+[r"\bottomrule",r"\end{tabular}"])+"\n",encoding="utf-8")


if __name__=="__main__": main()
