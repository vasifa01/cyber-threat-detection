"""Replays real NSL-KDD test traffic and URLs against the API to simulate a
live network, so the dashboard shows detections in real time.

Usage (from repo root, with the backend running):
    .venv/bin/python simulator/replay_traffic.py --rate 2 --count 300
"""

import argparse
import csv
import json
import logging
import random
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.ml.traffic import FEATURE_COLUMNS  # noqa: E402

DATA = ROOT / "ml" / "data"
log = logging.getLogger("simulator")

# A handful of "attacker" IPs make repeat offenders visible on the blocklist.
ATTACKER_IPS = [f"203.0.113.{i}" for i in range(10, 40)]


def internal_ip() -> str:
    return f"10.0.{random.randint(0, 5)}.{random.randint(2, 254)}"


def load_traffic(limit: int) -> list[tuple[dict, bool]]:
    rows = []
    with open(DATA / "KDDTest+.txt", newline="") as fh:
        for raw in csv.reader(fh):
            features = dict(zip(FEATURE_COLUMNS, raw[:41]))
            rows.append((features, raw[41] != "normal"))
    random.shuffle(rows)
    return rows[:limit]


def load_urls(limit: int) -> list[str]:
    with open(DATA / "urls.csv", newline="", encoding="utf-8", errors="ignore") as fh:
        urls = [r["url"] for r in csv.DictReader(fh)
                if r.get("url") and " " not in r["url"] and len(r["url"]) < 300]
    return random.sample(urls, min(limit, len(urls)))


def post(api: str, path: str, body: dict) -> dict | None:
    req = urllib.request.Request(
        f"{api}{path}", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        log.warning("HTTP %s on %s: %s", exc.code, path, exc.read()[:200])
    except urllib.error.URLError as exc:
        log.error("Cannot reach API at %s (%s). Is the backend running?", api, exc.reason)
        sys.exit(1)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--rate", type=float, default=2.0, help="events per second")
    parser.add_argument("--count", type=int, default=500, help="total events (0 = forever)")
    parser.add_argument("--url-share", type=float, default=0.25,
                        help="fraction of events that are URLs instead of traffic")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    random.seed(args.seed)
    pool_size = args.count or 5000
    traffic = load_traffic(pool_size)
    urls = load_urls(pool_size)
    delay = 1.0 / args.rate if args.rate > 0 else 0
    sent = 0

    log.info("Streaming to %s at %.1f events/s (Ctrl+C to stop)", args.api, args.rate)
    try:
        while args.count == 0 or sent < args.count:
            if random.random() < args.url_share:
                body = {"url": urls[sent % len(urls)], "source_ip": internal_ip()}
                res = post(args.api, "/api/analyze/url", body)
            else:
                features, is_attack = traffic[sent % len(traffic)]
                ip = random.choice(ATTACKER_IPS) if is_attack else internal_ip()
                res = post(args.api, "/api/analyze/traffic",
                           {"source_ip": ip, "features": features})
            sent += 1
            if res and res["is_threat"]:
                log.info("#%d %-8s %-9s conf=%.2f sev=%s %s", sent, res["source"],
                         res["label"], res["confidence"], res["severity"], res["action"] or "")
            time.sleep(delay)
    except KeyboardInterrupt:
        pass
    log.info("Sent %d events", sent)


if __name__ == "__main__":
    main()
