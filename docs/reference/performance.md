# Performance reference

This reference lists what each operation of the Rust implementation costs
as a principal's history grows, beside the bound the design promises for
it, and what a whole simulated network costs to run. It describes the code
as built and says where a bound is not met or not attempted. Every number
here comes from the commands in "How to reproduce"; none is a
specification or a service guarantee.

The measured quantity that matters is the _count_ of work, not the time:
commits replayed, signatures verified, index rows read, blobs read,
requests made. A count either grows with the history length `n` or it does
not, on any machine. Times are given for scale and depend on the hardware
below.

## Machine and method

| Item          | Value                                                                                       |
| :------------ | :------------------------------------------------------------------------------------------ |
| CPU           | Intel Core Ultra 7 155U, 14 hardware threads                                                |
| Memory        | 30 GB                                                                                       |
| Storage       | NVMe SSD, LUKS-encrypted, btrfs (zstd:1). One `fsync` costs about 8 ms                      |
| OS            | Linux 7.0.8 (Fedora 43)                                                                     |
| Toolchain     | Rust nightly 1.102 (2026-11-18), `--release` unless a row says debug                        |
| Bench storage | Benches create their data directories in the temporary directory, which was a RAM disk here |

Two consequences of that last row. The benches' times leave out disk
syncs, because syncing a RAM disk is free; the cost of a sync is measured
separately under "Durability cost". And the numbers are one machine's: the
counts transfer to another machine, the milliseconds do not.

## Per-operation cost against history length

The benches build a principal with `n` commits, then perform one operation
and count what it touched. `n` is 10, 100, 1000 and 10000. The "Counts"
column gives the measured counts at the smallest and the largest `n`; for
every row except the first write after a restart they were the same at all
four sizes, and a count that does not change is the bound being met.

The first table is the storage engine, called directly.

| Operation                     | Bound                         | Counts at n = 10 and n = 10000                         | Time, ms at n = 10 / 100 / 1000 / 10000 |
| :---------------------------- | :---------------------------- | :----------------------------------------------------- | :-------------------------------------- |
| Write one commit (kept)       | O(new): 0 commits replayed    | replayed 0; 7 index rows; 4 blobs read                 | 0.90 / 0.71 / 0.98 / 8.3                |
| Read the tip                  | O(1): 0 replayed              | replayed 0; 3 index rows                               | 0.03 / 0.04 / 0.03 / 0.04               |
| Read a patch from the tip     | O(1): 0 replayed              | replayed 0; 5 index rows                               | 0.07 / 0.07 / 0.06 / 0.07               |
| Refused push (bad signature)  | O(bundle), independent of `n` | replayed 0; 6 index rows; 4 blobs read                 | 0.70 / 0.49 / 0.76 / 7.9                |
| Refused push (unknown key)    | O(bundle), independent of `n` | replayed 0; 6 index rows; 4 blobs read                 | 0.21 / 0.19 / 0.49 / 7.8                |
| After a restart, first write  | O(n), once per principal      | replayed n + 6; index rows 2n + 19; blobs read 5n + 42 | 9.5 / 52 / 502 / 9642                   |
| After a restart, second write | O(new): 0 replayed            | replayed 0; 7 index rows; 4 blobs read                 | 0.71 / 1.0 / 1.7 / 12.6                 |

The second table is the same engine behind the HTTP server, one request per
operation, and the gossip loop between servers.

| Operation                       | Bound                         | Counts at n = 10 and n = 10000                                 | Time, ms at n = 10 / 100 / 1000 / 10000       |
| :------------------------------ | :---------------------------- | :------------------------------------------------------------- | :-------------------------------------------- |
| `POST /push` (one new commit)   | O(new): 0 replayed            | replayed 0; 1 request                                          | 0.82 / 0.84 / 1.1 / 7.8                       |
| `GET /tip`                      | O(1): 0 replayed              | replayed 0                                                     | 0.32 / 0.35 / 0.57 / 5.2                      |
| `GET /patch` from the tip       | O(1): 0 replayed              | replayed 0                                                     | 0.21 / 0.21 / 0.21 / 0.22                     |
| `GET /proof` (extends, member)  | O(log n) hashes, 0 replayed   | replayed 0; response 1.2 to 2.3 KB across the sizes            | 0.27 / 0.31 / 0.56 / 5.3                      |
| `POST /auth/login`              | O(1): 0 replayed              | replayed 0                                                     | 5.1 / 4.9 / 5.1 / 10                          |
| `POST /auth/session` (token)    | O(1): 0 replayed              | replayed 0                                                     | 0.20 / 0.23 / 0.46 / 5.0                      |
| Refused push (either kind)      | O(bundle), independent of `n` | replayed 0                                                     | 0.2 to 0.5 / 0.2 to 0.6 / 0.5 to 0.8 / 5 to 8 |
| Gossip round, idle              | O(peers) requests, 0 replayed | 4 requests; replayed 0                                         | 0.39 / 0.44 / 0.64 / 5.7                      |
| Gossip round, first (cold memo) | 0 replayed (state is kept)    | 4 requests; replayed 0                                         | 1.2 / 1.3 / 1.8 / 16                          |
| Gossip pull of k new commits    | O(k) commits replayed         | k = 1: replayed 1; k = 10: replayed 10                         | k = 10: 14 / 13 / 19 / 110                    |
| Fork location                   | O(h): see "Deferred", below   | proof asks 5 / 8 / 11 / 15, plus 1 patch ask, 1 commit fetched | 6.1 / 24 / 192 / 2808                         |

Reading the tables:

- Every bound that says "0 replayed" or "O(1)" is met: the count did not
  move across a thousandfold change in `n`. The same holds at larger
  histories than these (1024 to 2048 commits) in the bound tests below.
- The proof size grows by about one hash for each doubling of `n`, which is
  the O(log n) bound. The number of proof requests during fork location
  grows the same way: 5, 8, 11, 15 requests for `n` = 10, 100, 1000, 10000.
- Login costs about 5 ms at every `n`, against 0.2 ms for a token check.
  The difference is a signature verification, not history: it does not
  change with `n`.
- The restart row is the one place the cost is meant to grow with `n`: a
  restarted server replays a principal's chain once, on first use, and
  then keeps the verified state. The second write after a restart costs
  what any write costs.
- **The times at n = 10000 carry a floor of about 5 ms** that shows up even
  on a token check, which reads no history. The counts at that size are
  unchanged, so the floor is not work the operation does. It was not
  traced; the likely cause is storage maintenance running in the
  background after the 50 to 90 seconds it takes to build the history.
  Read the counts at 10000, and the times up to 1000.

## Bound tests

The bounds above are also enforced as tests, so a change that makes an
operation grow with `n` fails the build rather than a benchmark someone
must remember to read. Each test runs the operation on principals of
several sizes and asserts the counts are equal, so a count that grows,
even logarithmically, fails; the tests count work and never time it.

| Suite                             | Fast tier (histories to 16 times larger) | Large tier (up to 128 times larger) |
| :-------------------------------- | :--------------------------------------- | :---------------------------------- |
| Storage engine (`u3_bounds`)      | 15 pass                                  | 14 pass                             |
| Server and gossip (`u3_bounds`)   | 14 pass                                  | 13 pass                             |
| Stitched proofs (`stitch_bounds`) | 7 pass                                   | 5 pass                              |

The large tier is marked `#[ignore]` and runs with `-- --ignored`; in
release it took 6 s (storage), 10 s (server) and 4 s (proofs) on the
machine above. All 68 pass.

## Whole-network simulation

The network simulation (`netsim_network`) runs five servers, twelve
principals and 94 operations under injected faults (partitions, restarts,
forks, thefts, backup restores), seed 20261116, with the servers' default
limits. Release build, on the machine above, storage on the real disk:

| Measure                                       | Value                 |
| :-------------------------------------------- | :-------------------- |
| Wall time                                     | 55 s                  |
| Summed server CPU, all server processes       | 5.7 s                 |
| Gossip rounds, summed over servers            | 59                    |
| Commits replayed by gossip, summed            | 39                    |
| Convergence at the three barriers             | 1.11, 1.15 and 1.15 s |
| Server errors (5xx), rate-limit answers (429) | 0, 0                  |

For scale, the same run as a debug build took 130 s wall, 122 s of server
CPU and 136 replayed commits. Before the bounds above held, a debug build
of the same simulation (80 generated operations) took 782 CPU-seconds and
replayed 23,661 commits through gossip alone.

Where the simulation's wall time goes. The server CPU is a tenth of it. A
single command that creates a new local store (`cyphr init`, which is what
creating a principal or pairing a device does, and also the first command a
fresh verifier runs) takes 1.8 s on this disk and 3.7 s when four run at
once, against 0.1 s for a command on an existing store. That time is
about 240 disk syncs, not computation: on a RAM disk the same run takes 17
s and a create takes 50 ms. A first push of a new principal to a
server, from the command line, takes 41 ms.

## Durability cost

Every accepted commit is synced to disk before the server answers, once
per commit, and there is no group commit: a bundle of `K` commits costs `K`
syncs. The cost shows up as latency that grows with the number of pushes
in flight, and as a ceiling on throughput of about one sync time per
commit.

Measured against a release server with raised rate limits (the defaults
answer `429` beyond 50 pushes a second), 336 pushes to 16 principals,
new data directory per run, two runs of each:

| Pushes in flight | Latency p50 |        p99 |        Max | Pushes per second (implied by p50) |
| ---------------: | ----------: | ---------: | ---------: | ---------------------------------: |
|                1 |      8.9 ms |    10.4 ms |   27-31 ms |                                112 |
|                8 |    60-65 ms |   85-93 ms |  91-121 ms |                            125-135 |
|               16 |  122-128 ms | 153-168 ms | 162-173 ms |                            125-131 |

One push is one sync of about 8 ms. Eight pushes in flight each wait about
eight syncs, and sixteen about sixteen: latency scales with the queue
while throughput stays flat at 110 to 135 pushes a second, whatever the
concurrency. That is what syncs that do not overlap look like; a slow disk
alone would not make latency proportional to the number of pushes in
flight. The mechanism (a lock around the journal) was not traced here. At the default push limit (50 a second, burst 100) the
sync ceiling of about 110 a second is not reached, so the stall does not
appear in ordinary operation, and the simulation's four concurrent
operations stayed within the same limit. It would appear for a server that
raises the push limit, or with a slower disk, where each sync costs more.

## Deferred

These are known costs the implementation does not reduce yet.

- **Group commit.** One sync for a bundle of `K` commits instead of `K`
  syncs, and one sync shared by concurrent pushes, would remove the
  throughput ceiling and the queueing latency in "Durability cost". Not
  built.
- **Fork location is O(h), not O(depth + log n).** The number of requests
  is logarithmic (5, 8, 11, 15 for `n` from 10 to 10000, plus one patch
  and one commit), but the time is not: 6 ms, 24 ms, 192 ms, 2.8 s. After
  the fork position is found, the holder verifies the fork by replaying its
  own chain up to the fork height `h`. Reaching O(fork depth + log n)
  needs the holder to keep a snapshot of its verified state at
  intermediate positions, which is a design change, not tuning.
- **Creating a local store costs about 240 disk syncs.** Every `cyphr init`
  and every first use of a new store pays 1.8 s on the disk above, once per
  device or verifier. It is a fixed cost, independent of history, and it
  dominates a short simulation. The syncs come from creating the store's storage
  layers; which call issues each was not traced.
- **A restart replays each principal once.** By design: O(n) on the first
  write after a restart, then O(new). At `n` = 10000 that first write took
  9.6 s here.

## How to reproduce

From `rs/`, release profile:

```sh
cargo test --release -p cyphr-storage --test u3_bounds
cargo test --release -p cyphr-server --test u3_bounds
cargo test --release -p cyphr --test stitch_bounds
# the large tier, 128 times growth
cargo test --release -p cyphr-storage --test u3_bounds -- --ignored
cargo test --release -p cyphr-server --test u3_bounds -- --ignored
cargo test --release -p cyphr --test stitch_bounds -- --ignored
# the tables above; U3_NS names the history lengths
U3_NS=10,100,1000,10000 ./bench-u3.sh
# the network simulation; CYPHR_SCENARIO_SEED sets the seed
CYPHR_SCENARIO_SEED=20261116 cargo test --release -p cyphr-scenarios \
  --test netsim netsim_network -- --nocapture
```

Set `TMPDIR` to a directory on the disk you want to measure: the benches
and the simulation write there, and on a RAM disk they leave out the cost
of syncs.
