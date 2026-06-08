# Soak observability (Grafana / Datadog)

> Tracks issue [#85](https://github.com/wienerlabs/mosaic/issues/85).
> The `mosaic-soak` runner emits a Prometheus-format metrics file
> (`*.prom`) next to its markdown report. This document specifies how to
> ingest it and the dashboard + alerts the mainnet-readiness gate needs.

## What the runner emits

Every soak run writes two files at the configured `report_path` stem:

| File | Consumer |
|---|---|
| `<stem>.md` | Humans (committed to `docs/devnet-soak/`) |
| `<stem>.prom` | Prometheus / Grafana / Datadog |

The `.prom` file is Prometheus text exposition format:

```
# HELP mosaic_soak_unexpected_failure_total Outcomes that were neither a valid accept nor a documented tampered reject. ALERT WHEN > 0.
# TYPE mosaic_soak_unexpected_failure_total counter
mosaic_soak_unexpected_failure_total 0
...
mosaic_soak_cu{dispatch="groth16_bn254",stat="median"} 84100
mosaic_soak_cu{dispatch="groth16_bn254",stat="baseline"} 84027
```

### Metrics

| Metric | Type | Meaning |
|---|---|---|
| `mosaic_soak_total_txs` | counter | Transactions submitted |
| `mosaic_soak_accepted_valid_total` | counter | Valid proofs accepted |
| `mosaic_soak_rejected_tampered_total` | counter | Tampered proofs correctly rejected |
| `mosaic_soak_unexpected_failure_total` | counter | **The gate.** Anything that was neither a valid accept nor a documented soundness reject |
| `mosaic_soak_duration_seconds` | gauge | Run wall-clock |
| `mosaic_soak_cu_drift_alerts_total` | counter | CU samples past the drift tolerance |
| `mosaic_soak_cu{dispatch,stat}` | gauge | Per-dispatch CU (`min`/`median`/`p95`/`max`/`samples`/`baseline`) |

## Ingestion

### Prometheus / Grafana

Point a Prometheus node-exporter textfile collector at the soak output
directory, or push to a Pushgateway from the soak wrapper:

```bash
# node-exporter textfile collector
cp docs/devnet-soak/<stem>.prom /var/lib/node_exporter/textfile/mosaic_soak.prom

# or push-gateway
cat docs/devnet-soak/<stem>.prom \
  | curl --data-binary @- http://pushgateway:9091/metrics/job/mosaic_soak
```

### Datadog

The Datadog agent's `prometheus`/`openmetrics` integration scrapes the
same file or the pushgateway endpoint. Map `mosaic_soak_*` to
`mosaic.soak.*` in the integration config.

## Dashboard panels

1. **Soundness gate (single stat, red/green).** `mosaic_soak_unexpected_failure_total`. Green at `0`, red at `>= 1`. This is the panel the on-call watches.
2. **Outcome mix (time series).** `accepted_valid_total`, `rejected_tampered_total`, `unexpected_failure_total` stacked over the run.
3. **CU vs baseline per dispatch (time series).** For each `dispatch`, plot `stat="median"` and `stat="p95"` against the `stat="baseline"` line. A widening gap is the early warning the bench's static baseline can't show.
4. **CU drift alerts (counter).** `mosaic_soak_cu_drift_alerts_total` over time.
5. **Throughput (gauge).** `total_txs / duration_seconds`.

## Alerts

| Alert | Condition | Severity | Action |
|---|---|---|---|
| Soundness failure | `mosaic_soak_unexpected_failure_total > 0` | **P0** | Page on-call; this is a soundness or liveness break per `docs/rollback-playbook.md`. Halt the soak; do not advance the deploy ladder. |
| CU drift | `mosaic_soak_cu_drift_alerts_total > 0` | P2 | Investigate vs the pinned baseline; possible validator-cost change or a verifier regression. |
| CU hard ceiling | `mosaic_soak_cu{stat="max"} > 1400000` for any dispatch | P1 | A single verification approached the per-tx CU cap; investigate before mainnet. |
| Soak stalled | `rate(mosaic_soak_total_txs)` flat for > 5 min during a run | P2 | RPC outage or runner hang; check the cluster + re-run. |

The P0 soundness alert is the load-bearing one: the pre-mainnet gate
(`AUDIT-CHECKLIST.md`) requires at least one 24-hour soak with
`mosaic_soak_unexpected_failure_total == 0` for the full duration.

## Related

- `crates/mosaic-soak/` - the runner that emits these metrics
- `docs/devnet-soak/README.md` - run instructions + pass/fail criteria
- `docs/rollback-playbook.md` - the incident response the P0 alert triggers
- `docs/compute-unit-budget.md` - the pinned CU baselines the drift alert compares against
- Issue [#67](https://github.com/wienerlabs/mosaic/issues/67) - soak harness
- Issue [#85](https://github.com/wienerlabs/mosaic/issues/85) - this observability stack
