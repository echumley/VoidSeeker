#!/usr/bin/env python3
"""
cc_index_dump_all_shards.py
Iterate every cc-index shard for a given Common Crawl INDEX_NAME and write
a separate NDJSON text file per shard with URL+metadata (full JSON lines).

Examples:
  python cc_index_dump_all_shards.py \
    --index CC-MAIN-2025-38 \
    --out ./cc-index-dump \
    --max-shards 4 \
    --filter /admin /login /cockpit /manage /console \
    --workers 8

Notes:
- Handles both CDXJ (cdx-*.gz) and JSONL (part-*.gz) shard formats.
- Uses multithreading to process shards concurrently (I/O bound).
"""

import argparse
import gzip
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Descriptive UA per RFC 7231
USER_AGENT = "voidseeker-cc-index/1.0 (research; contact: you@example.com)"

# Manifest listing every cc-index shard for the crawl
# e.g. https://data.commoncrawl.org/crawl-data/CC-MAIN-2025-38/cc-index.paths.gz
MANIFEST_TMPL = "https://data.commoncrawl.org/crawl-data/{index}/cc-index.paths.gz"


def make_session() -> requests.Session:
    """Create a requests.Session with retry/backoff and connection pooling."""
    s = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retries, pool_connections=32, pool_maxsize=32)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"user-agent": USER_AGENT})
    return s


def fetch_manifest(index_name: str, only_part: bool = False, only_cdx: bool = False) -> List[str]:
    """Fetch and decompress cc-index.paths.gz; return list of shard URLs."""
    if only_part and only_cdx:
        raise ValueError("Choose only one of --only-part or --only-cdx")

    manifest_url = MANIFEST_TMPL.format(index=index_name)
    print(f"[*] Fetching manifest: {manifest_url}")
    r = requests.get(manifest_url, headers={"user-agent": USER_AGENT}, stream=True, timeout=60)
    r.raise_for_status()

    shard_urls: List[str] = []
    with gzip.GzipFile(fileobj=r.raw) as gz:
        for bline in gz:
            line = bline.decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            url = line if line.startswith("http") else f"https://data.commoncrawl.org/{line}"
            shard_urls.append(url)

    # Optional filtering by shard type
    if only_part:
        shard_urls = [u for u in shard_urls if "/collections/" in u and "/part-" in u]
    elif only_cdx:
        shard_urls = [u for u in shard_urls if "/indexes/" in u and "/cdx-" in u]

    print(f"[+] Manifest lists {len(shard_urls)} shard(s)")
    return shard_urls


def parse_json_line_any(line: str) -> Optional[dict]:
    """
    Parse a single line that may be:
      - pure JSON (starts with '{'), or
      - CDXJ: '<urlkey> <json>'
    Returns dict or None.
    """
    line = line.strip()
    if not line:
        return None
    if line[0] == "{":  # pure JSON per line
        return json.loads(line)
    # CDXJ: split once on first space
    try:
        _, json_part = line.split(" ", 1)
        return json.loads(json_part)
    except Exception:
        return None


def dump_shard(
    shard_url: str,
    out_dir: str,
    overwrite: bool = False,
    filter_contains: Optional[List[str]] = None,
    session: Optional[requests.Session] = None,
) -> Tuple[str, int]:
    """
    Stream a single cc-index shard (gzipped CDXJ/JSONL) and write matching JSON lines
    to a .ndjson file in out_dir. Returns (outfile, count_written).
    """
    path = urlparse(shard_url).path
    base = os.path.basename(path)  # e.g., cdx-00000.gz or part-00000.gz
    out_name = base.replace(".gz", ".ndjson")
    out_path = os.path.join(out_dir, out_name)

    if os.path.exists(out_path) and not overwrite:
        print(f"[!] {out_name} exists; skipping (use --overwrite to replace)")
        return out_path, 0

    os.makedirs(out_dir, exist_ok=True)
    print(f"[*] Streaming shard: {shard_url}")
    sess = session or make_session()
    r = sess.get(shard_url, stream=True, timeout=120)
    r.raise_for_status()

    wrote = processed = skipped = decode_errors = 0
    t0 = time.time()
    last_update = t0

    # Normalize filter substrings to lowercase once
    filt = [s.lower() for s in (filter_contains or [])]

    with gzip.GzipFile(fileobj=r.raw) as gz, open(out_path, "w", encoding="utf-8") as out:
        for bline in gz:
            processed += 1
            try:
                line = bline.decode("utf-8", errors="ignore")
                rec = parse_json_line_any(line)
                if rec is None:
                    decode_errors += 1
                    continue

                if filt:
                    u = (rec.get("url") or "").lower()
                    if not any(s in u for s in filt):
                        skipped += 1
                        pass
                    else:
                        out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                        wrote += 1
                else:
                    out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    wrote += 1

                now = time.time()
                if (now - last_update >= 2.0) or (processed % 100_000 == 0) or (wrote and wrote % 50_000 == 0):
                    elapsed = now - t0
                    rate = processed / elapsed if elapsed > 0 else 0
                    print(
                        f"    [*] Proc: {processed:,} | Wrote: {wrote:,} | Skipped: {skipped:,} | "
                        f"DecodeErr: {decode_errors:,} | Rate: {rate:,.0f} rec/s",
                        end="\r",
                    )
                    last_update = now

            except json.JSONDecodeError:
                decode_errors += 1
                continue
            except Exception as e:
                print(f"\n    [!] Error processing line: {e}")
                continue

    elapsed = time.time() - t0
    print(
        f"\n[+] Completed {out_name}: wrote {wrote:,} record(s) in {elapsed:.1f}s "
        f"(proc={processed:,}, skipped={skipped:,}, decodeErr={decode_errors:,})"
    )
    return out_path, wrote


def fetch_commoncrawl_urls():
    ap = argparse.ArgumentParser(
        description="Dump Common Crawl cc-index shards to per-shard NDJSON files (multithreaded)."
    )
    ap.add_argument("--index", required=True, help="Crawl index name, e.g., CC-MAIN-2025-38")
    ap.add_argument("--out", default="./cc-index-dump", help="Output directory (per-shard files inside INDEX subdir)")
    ap.add_argument("--overwrite", action="store_true", help="Overwrite existing per-shard files")
    ap.add_argument("--max-shards", type=int, default=0, help="Limit number of shards processed (0 = all)")
    ap.add_argument("--filter", nargs="*", default=None, help="Optional substrings to filter 'url' (e.g., --filter /admin /login)")
    ap.add_argument("--workers", type=int, default=8, help="Number of concurrent shard workers (I/O bound; try 4–16)")
    ap.add_argument("--only-part", action="store_true", help="Process only 'part-*.gz' JSONL shards")
    ap.add_argument("--only-cdx", action="store_true", help="Process only 'cdx-*.gz' CDXJ shards")
    args = ap.parse_args()

    try:
        shards = fetch_manifest(args.index, only_part=args.only_part, only_cdx=args.only_cdx)
    except Exception as e:
        print(f"[!] Failed to fetch manifest: {e}")
        sys.exit(2)

    if args.max_shards and args.max_shards > 0:
        print(f"[*] Limiting to first {args.max_shards} shard(s)")
        shards = shards[: args.max_shards]

    out_dir = os.path.join(args.out, args.index)
    os.makedirs(out_dir, exist_ok=True)
    filt = [s.lower() for s in args.filter] if args.filter else None

    print("\n" + "=" * 80)
    print(f"[*] Starting shard processing (workers={args.workers})")
    print(f"[*] Total shards to process: {len(shards)}")
    print(f"[*] Output directory: {out_dir}")
    if filt:
        print(f"[*] Filters: {', '.join(filt)}")
    print("=" * 80 + "\n")

    total_written = 0
    total_start = time.time()

    def worker(shard_url: str) -> Tuple[str, int, float, Optional[str]]:
        t0 = time.time()
        session = make_session()  # per-thread session
        try:
            out_path, wrote = dump_shard(
                shard_url=shard_url,
                out_dir=out_dir,
                overwrite=args.overwrite,
                filter_contains=filt,
                session=session,
            )
            elapsed = time.time() - t0
            return out_path, wrote, elapsed, None
        except Exception as e:
            return "", 0, time.time() - t0, str(e)
        finally:
            try:
                session.close()
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        future_map = {ex.submit(worker, u): u for u in shards}
        done = 0
        for fut in as_completed(future_map):
            shard_url = future_map[fut]
            done += 1
            try:
                out_path, wrote, elapsed, err = fut.result()
                name = os.path.basename(urlparse(shard_url).path)
                if err:
                    print(f"[{done}/{len(shards)}] [ERR] {name} -> {err}")
                else:
                    total_written += wrote
                    print(f"[{done}/{len(shards)}] [OK ] {os.path.basename(out_path)} wrote {wrote:,} recs in {elapsed:.1f}s")
            except Exception as e:
                print(f"[{done}/{len(shards)}] [EXC] {shard_url} -> {e}")

            avg = (time.time() - total_start) / done
            remaining = (len(shards) - done) * avg
            print(f"    ETA ~ {remaining/60:.1f} min | total written: {total_written:,}")

    total_elapsed = time.time() - total_start
    print("\n" + "=" * 80)
    print("[✓] ALL SHARDS COMPLETE")
    print(f"[✓] Total records written: {total_written:,}")
    print(f"[✓] Total time: {total_elapsed/60:.1f} minutes ({total_elapsed:.1f}s)")
    print("=" * 80)


if __name__ == "__main__":
    fetch_commoncrawl_urls()