"""
Manual evaluation runner for SentinelTi.

Loads data/manual_eval_urls.csv, runs enrich_score on each URL,
and prints basic confusion counts + sample disagreements.
"""

from __future__ import annotations

import csv
from pathlib import Path
from collections import Counter

from .scoring import enrich_score


def main() -> None:
    # repo root = sentinelti/.. (adjust if your structure differs)
    root = Path(__file__).resolve().parents[1]
    eval_path = root / "data" / "manual_eval_urls.csv"

    if not eval_path.exists():
        raise SystemExit(f"Manual eval file not found: {eval_path}")

    rows = []
    with eval_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("url", "").strip()
            label = row.get("label", "").strip()
            if not url or not label:
                continue
            rows.append(row)

    results = []
    for row in rows:
        url = row["url"].strip()
        true_label = row["label"].strip()
        notes = row.get("notes", "").strip()
        r = enrich_score(url)
        results.append((url, true_label, notes, r))

    # Confusion on final_label
    counts = Counter()
    for _, true_label, _, r in results:
        pred = r["final_label"]
        counts[(true_label, pred)] += 1

    print("Confusion (true_label -> final_label):")
    for (true_label, pred), c in sorted(counts.items()):
        print(f"  {true_label:10s} -> {pred:10s}: {c}")

    print("\nSample disagreements:")
    for url, true_label, notes, r in results:
        if true_label != r["final_label"]:
            print(f"- URL:        {url}")
            print(f"  true_label: {true_label}")
            print(f"  final_label:{r['final_label']}")
            print(f"  risk:       {r['risk']}")
            print(f"  prob_mal:   {r['prob_malicious']:.3f}")
            print(f"  reasons:    {', '.join(r['reasons'])}")
            if notes:
                print(f"  notes:      {notes}")
            print()

if __name__ == "__main__":
    main()

"""
Here’s a concise TODO notes list for tomorrow based on today’s manual_eval:

1) Hard malicious still labeled benign  
- `http://login-office365.com`  
- `http://login.example.com/@secure-check`  
- `http://example.com/login.php?user=admin&password=admin`  
- `http://free-gift-card.example.biz/claim`  
- `http://crypto-giveaway.example.cc/wallet/connect`  
- `http://support-example.com.remote-help-session.ru`  
- `http://examp1e.com/login`  
- `http://faceboo-k.com/security-check`  
- `http://very-long-subdomain-with-many-levels.login.secure.update.example.com/path`  
- `http://example.reallylongtldthatisweirdlysuspicious/login`  
- `http://cdn.example.com/script.js?callback=https://evil.com/hook`  
- `http://example.com/api/share?link=https%3A%2F%2Fevil.com%2Fpromo`  
- `http://example.com/tracker?u=http://evil.phish.xyz/landing`  

Notes:  
- Consider small, targeted heuristics for:
  - Fake brand logins without clear brand tokens.  
  - Cleartext creds in query (`user=admin&password=admin`).  
  - “gift card”, “giveaway”, “remote-help-session” lures.  
  - Nested URLs in non-redirect params (currently detected but not enough score to flip label).

2) Benign over-flagged as suspicious (potential false positives)  
- `http://example.net/blog/2025/01/security-tips`  
- `https://secure.portal.example.org/account/login`  
- `https://secure.examplebank.com/auth/login?returnUrl=/accounts/overview`  
- `https://docs.example.com/products/platform/v2/guide/getting-started/installation`  
- `http://[::1]/login`  

Notes:  
- All hit deep-path and/or token heuristics.  
- Decide whether to:
  - Further soften deep-path/token impact for clearly benign patterns (blog/docs/portal), or  
  - Accept them as slightly noisy but safe for v1.

3) Private/local IP strength  
- `http://127.0.0.1/admin`, `http://192.168.0.100/login`, `http://10.0.0.1/dashboard`, `http://172.20.5.4/portal` are now **high risk / malicious**.  

Notes:  
- Confirm if “malicious” is desired for gray internal URLs or if they should cap at “suspicious” (maybe private IP bump should be strong but not always push to high risk when model is low).
"""