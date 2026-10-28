# glsec benchmark history

Data branch, written by the
[Benchmark history](https://github.com/glsec/glsec/blob/main/.github/workflows/benchmark-history.yml)
workflow (glsec/glsec#875, #879) and read by glsec.github.io for its
[performance page](https://glsec.github.io/performance/). Nothing here is
built or released.

## `inputs/`

The pipelines that are measured. `inputs/v1/synthetic.yml` is the output of
`largePipeline(2000, 0)` from `cmd/glsec/scale_test.go`, written with

```sh
GLSEC_BENCH_INPUT=inputs/v1/synthetic.yml go test -run TestWriteBenchmarkInput ./cmd/glsec
```

An input is never changed in place: every commit and every old release is
measured on the same file, so a different input is a new directory (`v2`) and
a new series, selected by `input_version` in the records.

## `data/benchmarks.jsonl`

One JSON record per line, appended for every push to `main` that changes Go
code, and once per release by a manual backfill run.

| Field | Meaning |
|---|---|
| `schema` | Record format: `1` before glsec#879, `2` since (adds `ref` and the ratio fields) |
| `kind` | `main` (a push to main) or `release` (backfill of a release) |
| `commit`, `date` | The measured commit and its commit date (ISO 8601) |
| `version` | `glsec --version` of the binary |
| `rules` | Number of rules (`glsec list`), `null` for versions without `list` |
| `input`, `input_version` | Which file under `inputs/` was scanned |
| `cli.median_ms`, `cli.runs_ms` | Wall time of the CLI scanning the input: median and every run |
| `cli.flags` | Flags passed: those of `--no-cache`, `--no-repo-config`, `--no-ignores`, `--no-exit-codes` the version has |
| `ref` | Schema 2, `main` records: the latest release when the record was taken; `null` otherwise |
| `cli.ratio` | Schema 2: `cli.median_ms` divided by the median of `ref`, both measured in the same job, taking turns; `null` without `ref`. Below 1 is faster than the release |
| `cli.ref_median_ms`, `cli.ref_runs_ms` | Schema 2, with `ref`: the release's median and every run |
| `go_bench` | Medians of `BenchmarkRules` and `BenchmarkRun` (`ns_per_op`, `bytes_per_op`, `allocs_per_op`, `runs`), `null` for releases |
| `go_version`, `cpu` | Toolchain and runner CPU; time depends on them, allocations don't |
| `measured_at` | When the record was taken |

Times come from shared GitHub runners and vary by 10 to 30% from run to run.
Records from one backfill run share a machine and compare with each other; for
`main` records, compare `cli.ratio`, which takes the runner out.
