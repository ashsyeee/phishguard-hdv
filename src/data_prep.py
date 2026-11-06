"""
data_prep.py - Step 1: Data layer with 4-category labeling.

This module builds the combined training/dev corpus for PhishGuard-HDV and
assigns EVERY row exactly one of four ground-truth categories:

    * real_legitimate        - real, non-malicious URLs (from PhiUSIIL, label 0)
    * real_phishing          - real, malicious URLs     (from PhiUSIIL, label 1)
    * hallucinated            - fabricated, NON-RESOLVING URLs that Stage A
                                 (hallucination detector) must learn to reject.
                               Generated synthetically (see below).
    * real_but_misdescribed   - a real URL the LLM made a false claim about.
                               [optional 4th category, included because it costs
                                little and makes the viva story stronger]

WHY THIS LAYOUT MATTERS (maps to FYP report Chapter 3)
-------------------------------------------------------
PhishGuard-HDV is a TWO-QUESTION system:
    Stage A answers:  "Does this URL actually exist / is it grounded?"
    Stage B answers:  "Is this (real) URL malicious?"

Those are different questions, so the labels live in different types of column:

    * category                   -> what the row IS (the 4-category ground truth)
    * exists_ground_truth        -> evaluation target for Stage A
    * is_phishing_ground_truth   -> evaluation target for Stage B

Stratified splitting by `category` guarantees every category appears in every
split, so neither stage can "cheat" by having a category missing from a split.

SAFETY OF THE SYNTHETIC "HALLUCINATED" SET
-------------------------------------------
Hallucinated URLs are generated with IANA / RFC-2606 RESERVED top-level
domains: `.example`, `.invalid`, `.test`. The IANA convention guarantees these
names are non-routable across the Internet and are reserved for documentation
- they CANNOT resolve to a real host and CANNOT be registered by anyone. This
gives Stage A a clean, defensible, and 100 % safe ground truth: the detector
should classify them as "does not exist" purely because the names are
structurally fake, with nothing real ever involved.

PHIUSIIL COLUMN ASSUMPTION (verified against the Kaggle export)
---------------------------------------------------------------
The Kaggle export `PhiUSIIL_Phishing_URL_Dataset.csv` (ndarvind/
phiusiil-phishing-url-dataset) exposes the URL under column `URL` and the
ground-truth phish flag under `label`, where 0 = legitimate and 1 = phishing.
Candidate aliases are accepted in case your export differs; if none match, a
clear error lists the actual columns so the dataset is never silently
mislabeled.
"""

from __future__ import annotations

import argparse
import itertools
import logging
import random
import re
import sys
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import unquote, urlparse

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

logger = logging.getLogger("phishguard.data_prep")

# ---------------------------------------------------------------------------
# Paths - resolved relative to this file so the scripts work from any cwd.
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
LLM_DIR = DATA_DIR / "llm_generated"
PROCESSED_DIR = DATA_DIR / "processed"

DEFAULT_PHIUSIIL_FILENAME = "PhiUSIIL_Phishing_URL_Dataset.csv"

# ---------------------------------------------------------------------------
# 4-category vocabulary - single source of truth used by every later split.
# ---------------------------------------------------------------------------
CAT_LEGIT = "real_legitimate"
CAT_PHISH = "real_phishing"
CAT_HALLU = "hallucinated"
CAT_MISDESC = "real_but_misdescribed"
ALL_CATEGORIES = (CAT_LEGIT, CAT_PHISH, CAT_HALLU, CAT_MISDESC)

# PhiUSIIL label semantics (VERIFIED against the raw file):
#     label = 1 -> LEGITIMATE   (134,850 rows)
#     label = 0 -> PHISHING     (100,945 rows)
# The published dataset has 134,850 legitimate and 100,945 phishing URLs, and
# label=1 is the legitimate class. Getting this backwards silently inverts the
# whole classifier, so it is documented here and asserted in _parse_label().
PHIUSIIL_URL_COLUMNS = ("URL", "url", "Url", "urls")
PHIUSIIL_LABEL_COLUMNS = ("label", "Label", "Result", "result")

# ---------------------------------------------------------------------------
# Synthetic (fake) URL generation - see module docstring for the safety story.
# ---------------------------------------------------------------------------
RESERVED_TLDS = ("example", "invalid", "test")  # RFC-2606: non-routable by IANA

# Well-known brands an LLM might plausibly "invent" a page for.
BRANDS = (
    "paypal", "apple", "amazon", "google", "netflix", "microsoft",
    "facebook", "instagram", "linkedin", "ebay", "chase", "wellsfargo",
    "bankofamerica", "coinbase", "github", "dropbox",
)

# Lookalike brands with character substitution (the classic 'paypa1' trick).
# This is exactly the input Stage A's similarity scoring is meant to catch.
SUBSTITUTED_BRANDS = {
    "paypal": "paypa1",
    "apple": "app1e",
    "netflix": "netf1ix",
    "microsoft": "mlcrosoft",
    "amazon": "arnazon",
    "google": "go0gle",
    "linkedin": "l1nkedin",
    "ebay": "eb4y",
    "chase": "cbvse",  # replaced visually-similar letters ('h' -> 'b')
}

# Number-verbatim templates; `.reserved_tld` is appended to each.
HALLUCINATED_TEMPLATES = (
    "{brand}-secure",
    "{brand}.secure",
    "{brand}-login",
    "{brand}-verify",
    "{brand}-billing",
    "{brand}-account",
    "secure-{brand}",
    "verify-{brand}",
    "login-{brand}",
    "update-{brand}",
    "confirm-{brand}",
    "{brand}-24x7",
    "{brand}-support-claim",
    "{brand}fraudalert",
)

# Example-path fragments to make lookalikes "plausible" (still fake).
HALLUCINATED_PATHS = (
    "/",
    "/signin",
    "/account/verify",
    "/security/confirm",
    "/billing/update",
    "/login",
    "/unlock",
    "/verify/token",
)

# Real, resolvable RFC-2606 example domains used for the 4th category.
MISDESC_DOMAINS = ("example.com", "example.org", "example.net")

# "Plausible-sounding" false claims an LLM might attach to a REAL url.
# The URL is real; the CLAIM is the fabrication - that is the misdescription.
MISDESC_CLAIMS = (
    "your account will be closed unless you sign in",
    "you have won a free 12-month subscription, claim it here",
    "a payment of $499.00 failed - update your billing details",
    "this is the official login of the bank, enter your password",
    "your session expired, re-authenticate to keep your data",
)

# Word pool used ONLY by the --demo placeholder dataset (see _build_demo...).
_DEMO_WORDS = (
    "home", "about", "cart", "checkout", "news", "profile", "media",
    "login", "verify", "account", "billing", "update", "secure", "signin",
)


# ===========================================================================
# URL normalisation / domain helpers
# ===========================================================================


def normalise_url(url: object) -> str:
    """Return a canonical, lowercased copy of `url` ("" if unusable).

    Lowercasing + re-adding a scheme makes de-duplication and downstream
    feature extraction deterministic - "PayPal.com" and "paypal.com" must
    collapse to the same row.
    """
    if url is None or (isinstance(url, float) and np.isnan(url)):
        return ""
    s = str(url).strip()
    if not s:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", s):
        s = "https://" + s  # assume a bare domain/host was given
    try:
        p = urlparse(s)
    except ValueError:
        return ""
    host = (p.hostname or "").lower()
    if not host:
        return ""
    scheme = (p.scheme or "https").lower()
    path = unquote(p.path or "")
    query = unquote(p.query or "")
    port = f":{p.port}" if p.port else ""
    return f"{scheme}://{host}{port}{path}?{query}".rstrip("?")


def extract_domain(url: object) -> str:
    """Return just the lowercase hostname of `url` ('' if none)."""
    s = normalise_url(url)
    if not s:
        return ""
    try:
        return (urlparse(s).hostname or "").lower()
    except ValueError:
        return ""


# ===========================================================================
# PhiUSIIL loading (with honest failure messages)
# ===========================================================================


def _find_raw_csv(path: Optional[str]) -> Optional[Path]:
    """Locate the PhiUSIIL csv: explicit path > default name > any csv."""
    if path:
        p = Path(path)
        return p if p.is_file() else RAW_DIR / p.name if (RAW_DIR / p.name).is_file() else None
    default = RAW_DIR / DEFAULT_PHIUSIIL_FILENAME
    if default.is_file():
        return default
    csvs = sorted(RAW_DIR.glob("*.csv"))
    if csvs:
        logger.warning("Default file %r not found; using %s", DEFAULT_PHIUSIIL_FILENAME, csvs[0])
        return csvs[0]
    return None


def _detect_columns(df: pd.DataFrame) -> Tuple[str, str]:
    """Return (url_col, label_col) using documented candidates.

    Raises ValueError (with the actual columns) rather than guessing wrong -
    mislabeled data is worse than no data.
    """
    url_col = next((c for c in PHIUSIIL_URL_COLUMNS if c in df.columns), None)
    label_col = next((c for c in PHIUSIIL_LABEL_COLUMNS if c in df.columns), None)
    if url_col is None or label_col is None:
        raise ValueError(
            "Could not find PhiUSIIL columns. Expected URL column in "
            f"{PHIUSIIL_URL_COLUMNS} and label column in {PHIUSIIL_LABEL_COLUMNS}. "
            f"Actual columns in {list(df.columns)[:20]}..."
            "\nIf your export uses different headers, add them to the "
            "PHIUSIIL_URL_COLUMNS / PHIUSIIL_LABEL_COLUMNS tuples at the top."
        )
    return url_col, label_col


def _parse_label(value: object) -> bool:
    """Map a PhiUSIIL label value to the boolean `is_phishing`.

    PhiUSIIL convention (verified): label 1 = legitimate, label 0 = phishing.
    The mapping is intentionally explicit and raises on anything unrecognised
    so the ground truth can never be silently inverted.
    """
    if isinstance(value, bool):
        return not value                       # True(=1) means legitimate
    if isinstance(value, (int, float)):
        return float(value) == 0.0             # 0 = phishing
    v = str(value).strip().lower()
    if v in {"0", "phishing", "phish", "malicious"}:
        return True
    if v in {"1", "legitimate", "legit", "benign"}:
        return False
    raise ValueError(f"Unrecognised PhiUSIIL label value: {value!r}")


def load_phiussiil(path: Optional[str] = None) -> pd.DataFrame:
    """Load the real PhiUSIIL csv into a clean, 2-category DataFrame.

    Gracefully tells the user WHERE the file must go if it is missing.
    """
    resolved = _find_raw_csv(path)
    if resolved is None:
        raise FileNotFoundError(
            "PhiUSIIL dataset not found.\n"
            f"Place the csv at: {RAW_DIR / DEFAULT_PHIUSIIL_FILENAME}\n"
            "(or any *.csv in data/raw/, or pass --phiussiil <path>)\n"
            "Download source: Kaggle - 'ndarvind/phiusiil-phishing-url-dataset'."
        )
    logger.info("Loading PhiUSIIL from %s", resolved)
    df = pd.read_csv(resolved, dtype=str, on_bad_lines="warn")
    url_col, label_col = _detect_columns(df)
    df = df[[url_col, label_col]].copy()
    df.columns = ["url", "result_raw"]

    df["url"] = df["url"].map(normalise_url)
    df["domain"] = df["url"].map(extract_domain)
    df["is_phishing"] = df["result_raw"].map(_parse_label)

    # Cleaning: drop unusable rows, then de-duplicate on normalised url.
    n_raw = len(df)
    df = df[(df["url"] != "") & (df["domain"] != "")]
    df = df.drop_duplicates(subset="url", keep="first").reset_index(drop=True)
    dropped = n_raw - len(df)
    if dropped:
        logger.warning("Dropped %d unusable/duplicate PhiUSIIL rows", dropped)

    df["source"] = "phiussiil"
    df["category"] = np.where(df["is_phishing"], CAT_PHISH, CAT_LEGIT)
    df["exists_ground_truth"] = True
    df["note"] = ""
    return df[["url", "domain", "category", "source",
               "exists_ground_truth", "is_phishing", "note"]]


# ===========================================================================
# Synthetic LLM output generation (categories 3 and 4)
# ===========================================================================


def _build_hallucinated_rows(n: int, rng: random.Random) -> list[dict]:
    """Generate n plausible-looking but FAKE urls (category: hallucinated).

    Every hostname ends in an RFC-2606 reserved TLD so the name is
    non-resolvable by IANA mandate - safe, deterministic, defensible.
    """
    rows: list[dict] = []
    used_domains: set[str] = set()
    while len(rows) < n:
        brand = rng.choice(BRANDS)
        # ~25 % of the time use a character-substituted lookalike ('paypa1').
        template = rng.choice(HALLUCINATED_TEMPLATES)
        if rng.random() < 0.25 and brand in SUBSTITUTED_BRANDS:
            brand = SUBSTITUTED_BRANDS[brand]
        label = template.format(brand=brand)
        tld = rng.choice(RESERVED_TLDS)
        host = f"{label}.{tld}".lower()
        if host in used_domains:
            continue
        used_domains.add(host)
        path = rng.choice(HALLUCINATED_PATHS)
        rows.append({
            "url": f"https://{host}{path}",
            "domain": host,
            "category": CAT_HALLU,
            "source": "llm_synthetic",
            "exists_ground_truth": False,
            "is_phishing": False,  # Stage-b is never reached; left neutral.
            "note": (f"Synthetic LLM-hallucinated lookalike of brand "
                     f"{brand!r}; reserved TLD .{tld} guarantees it does "
                     f"not resolve."),
        })
    return rows


def _build_misdescribed_rows(n: int, rng: random.Random) -> list[dict]:
    """Generate n REAL urls the LLM made a false claim about (category 4).

    The host is a real, resolvable RFC-2606 example domain; the *claim* is
    fabricated. This row is not used to train the Stage B classifiers - it
    exists to prove the system can represent 'real but wrongly described'.
    """
    rows: list[dict] = []
    for i in range(n):
        host = rng.choice(MISDESC_DOMAINS)
        claim = rng.choice(MISDESC_CLAIMS)
        rows.append({
            "url": f"https://{host}/llm-claimed/{i}",
            "domain": host,
            "category": CAT_MISDESC,
            "source": "llm_synthetic",
            "exists_ground_truth": True,
            "is_phishing": False,  # the URL itself is benign - only the claim lies
            "note": f"REAL url ; LLM claim '{claim}' is FALSE.",
        })
    return rows


def generate_hallucinated_set(
    n_hallucinated: int = 200,
    n_misdescribed: int = 40,
    seed: int = 42,
) -> pd.DataFrame:
    """Build the full synthetic LLM-output set and persist it.

    Returns a DataFrame containing the 'hallucinated' and
    'real_but_misdescribed' categories (clearly labeled, safe placeholder
    domains only). Writes a csv to data/llm_generated/ for auditability.
    """
    rng = random.Random(seed)
    rows = _build_hallucinated_rows(n_hallucinated, rng)
    rows += _build_misdescribed_rows(n_misdescribed, rng)
    df = pd.DataFrame(rows, columns=[
        "url", "domain", "category", "source",
        "exists_ground_truth", "is_phishing", "note"])
    LLM_DIR.mkdir(parents=True, exist_ok=True)
    out = LLM_DIR / "llm_synthetic_urls.csv"
    df.to_csv(out, index=False)
    logger.info("Wrote %d synthetic LLM rows to %s", len(df), out)
    return df


# ===========================================================================
# --demo placeholder (development only; NEVER real data)
# ===========================================================================


def _build_demo_phiussiil(n: int = 600, seed: int = 42) -> pd.DataFrame:
    """Placeholder PhiUSIIL substitute for DEVELOPMENT/demo runs only.

    WHY IT EXISTS: `data_prep.py --demo` must remain runnable before the real
    PhiUSIIL csv is downloaded, so the whole pipeline can be exercised and
    tested end-to-end. All rows use the resolvable RFC-2606 example.com host
    and differ only by path - the host truly resolves, so Stage A passes them
    and Stage B can be exercised on lexical differences.

    SAFETY: example.com is reserved for documentation (RFC 2606); no real
    brand, no real phishing content is fabricated.
    """
    rng = random.Random(seed)
    rows: list[dict] = []
    for i in range(n):
        is_phish = rng.random() < 0.5
        parts = rng.choices(_DEMO_WORDS, k=rng.randint(2, 4))
        path = "/" + "/".join(parts)
        rows.append({
            "url": f"https://example.com{path}-{i}",
            "domain": "example.com",
            "category": CAT_PHISH if is_phish else CAT_LEGIT,
            "source": "demo_placeholder",
            "exists_ground_truth": True,
            "is_phishing": is_phish,
            "note": "DEV PLACEHOLDER - replace with real PhiUSIIL data.",
        })
    return pd.DataFrame(rows, columns=[
        "url", "domain", "category", "source",
        "exists_ground_truth", "is_phishing", "note"])


# ===========================================================================
# Clean + merge + split
# ===========================================================================


def clean_and_merge(real: pd.DataFrame, synthetic: pd.DataFrame,
                    domain_dedup: bool = True) -> pd.DataFrame:
    """Concatenate real + synthetic sets, drop dupes, enforce the vocabulary.

    de-duplication happens at TWO levels:
      * identical URL strings are always collapsed (keep first);
      * with `domain_dedup` (default), all rows sharing a registrable domain
        are collapsed to a single representative row. This is the leak fix:
        the previous URL-only dedup left 2,691 phishing rows in the test split
        whose DOMAIN was already in training, inflating held-out scores. A
        phishing campaign reuses one domain across many paths, so a
        URL-level split cannot be trusted.
    """
    merged = pd.concat([real, synthetic], ignore_index=True)
    merged = merged[merged["url"] != ""]
    merged = merged.drop_duplicates(subset="url", keep="first").reset_index(drop=True)

    if domain_dedup:
        before = len(merged)
        merged = merged.drop_duplicates(subset="domain", keep="first") \
                       .reset_index(drop=True)
        if before - len(merged):
            logger.info("Domain-level dedup collapsed %d extra rows", before - len(merged))

    # Defensive: any unexpected category value is a bug, fail loudly.
    bad = set(merged["category"].unique()) - set(ALL_CATEGORIES)
    if bad:
        raise ValueError(f"Unexpected categories produced: {bad}")
    return merged


def stratified_split(
    df: pd.DataFrame,
    val_frac: float = 0.15,
    test_frac: float = 0.15,
    seed: int = 42,
    group_col: Optional[str] = "domain",
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """70/15/15 train/val/test split, stratified by `category`.

    WHY STRATIFY: with a 4-category corpus, random splits can strip a rare
    category out of a split. Stratification keeps every category in every
    split, so per-stage evaluation is always meaningful.

    WHY GROUP BY `domain`: a URL-level split can place one path of a domain in
    training and another path of the SAME domain in test. That is leakage - the
    model has already seen the domain - and it inflates held-out metrics. When
    `group_col` names a real column, whole domains are assigned to exactly one
    split (GroupShuffleSplit), so no registrable domain straddles two splits.
    """
    train_frac = 1.0 - val_frac - test_frac
    if not (-1e-9 <= train_frac <= 1 + 1e-9):
        raise ValueError("val_frac + test_frac must be <= 1")

    if group_col and group_col in df.columns:
        train, temp = _group_split(df, group_col, test_size=val_frac + test_frac,
                                   seed=seed)
        val, test = _group_split(temp, group_col,
                                 test_size=test_frac / (val_frac + test_frac),
                                 seed=seed)
    else:
        if group_col:
            logger.warning("group_col %r absent - falling back to a row-level "
                           "stratified split (leakage risk)", group_col)
        train, temp = train_test_split(
            df, test_size=val_frac + test_frac,
            stratify=df["category"], random_state=seed)
        val, test = train_test_split(
            temp, test_size=test_frac / (val_frac + test_frac),
            stratify=temp["category"], random_state=seed)

    for name, part in (("train", train), ("val", val), ("test", test)):
        present = set(part["category"].unique())
        if present != set(ALL_CATEGORIES):
            logger.warning("%s split is missing categories: %s", name,
                           set(ALL_CATEGORIES) - present)
    _assert_no_domain_overlap(train, val, test, group_col)
    return train, val, test


def _group_split(df: pd.DataFrame, group_col: str, test_size: float,
                 seed: int) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Split so every `group_col` value lands in exactly one side.

    Proportional allocation by the MOST PREDOMINANT category within each group
    keeps the category balance near the requested fraction without splitting a
    domain. Random tie-breaking keeps it reproducible under `seed`.
    """
    from sklearn.model_selection import GroupShuffleSplit

    groups = df[group_col].astype(str).values
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_idx, temp_idx = next(gss.split(df, groups=groups))
    return df.iloc[train_idx].reset_index(drop=True), \
        df.iloc[temp_idx].reset_index(drop=True)


def _assert_no_domain_overlap(train, val, test, group_col: Optional[str]) -> None:
    """Fail loudly if any domain appears in more than one split (the leak)."""
    if not group_col or group_col not in train.columns:
        return
    tr = set(train[group_col].astype(str))
    va = set(val[group_col].astype(str))
    te = set(test[group_col].astype(str))
    overlaps = (tr & va) | (tr & te) | (va & te)
    if overlaps:
        raise ValueError(
            f"Split leakage: {len(overlaps)} domain(s) appear in more than one "
            f"split (e.g. {sorted(overlaps)[:5]}). The grouped split must keep "
            f"each '{group_col}' in exactly one split.")


def write_splits(train, val, test, full) -> None:
    """Persist processed splits + a readable processing report."""
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    train.to_csv(PROCESSED_DIR / "train.csv", index=False)
    val.to_csv(PROCESSED_DIR / "val.csv", index=False)
    test.to_csv(PROCESSED_DIR / "test.csv", index=False)
    full.to_csv(PROCESSED_DIR / "all_processed.csv", index=False)

    lines = [
        "PhishGuard-HDV - data processing report",
        "=" * 45,
        f"total rows                  : {len(full)}",
        "",
        "rows per category (full set):",
        full["category"].value_counts().to_string(),
        "",
        "rows per split:",
        pd.concat([train.assign(split="train"),
                   val.assign(split="val"),
                   test.assign(split="test")])
          .pivot_table(index="split", columns="category", aggfunc="size", fill_value=0)
          .to_string(),
        "",
        "leakage check (registrable domains per split must be disjoint):",
        f"  train domains: {train['domain'].nunique()}",
        f"  val   domains: {val['domain'].nunique()}",
        f"  test  domains: {test['domain'].nunique()}",
        f"  overlap (train&test): {len(set(train['domain']) & set(test['domain']))}",
        f"  overlap (train&val) : {len(set(train['domain']) & set(val['domain']))}",
        f"  overlap (val&test)  : {len(set(val['domain']) & set(test['domain']))}",
    ]
    report = PROCESSED_DIR / "processing_report.txt"
    report.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Wrote splits to %s", PROCESSED_DIR)


def build_all(
    phiussiil_path: Optional[str] = None,
    demo: bool = False,
    n_hallucinated: int = 200,
    n_misdescribed: int = 40,
    seed: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """End-to-end Step 1: load(live or demo) >> synthetic >> merge >> split.

    Returns (full, train, val, test).
    """
    if demo:
        logger.warning(
            "DEMO mode: using generated placeholder data, NOT real PhiUSIIL. "
            "Do not use for evaluation.")
        real = _build_demo_phiussiil(seed=seed)
    else:
        real = load_phiussiil(phiussiil_path)

    synthetic = generate_hallucinated_set(
        n_hallucinated=n_hallucinated, n_misdescribed=n_misdescribed, seed=seed)
    full = clean_and_merge(real, synthetic)

    train, val, test = stratified_split(full, seed=seed)
    write_splits(train, val, test, full)
    return full, train, val, test


def main(argv: Optional[list[str]] = None) -> int:
    """CLI: python src/data_prep.py [--demo] [--phiussiil <path>] [--seed N]."""
    parser = argparse.ArgumentParser(description="Step 1 - data layer")
    parser.add_argument("--phiussiil", help="explicit path to the PhiUSIIL csv")
    parser.add_argument("--demo", action="store_true",
                        help="use a generated dev placeholder instead of PhiUSIIL")
    parser.add_argument("--n-hallucinated", type=int, default=200)
    parser.add_argument("--n-misdescribed", type=int, default=40)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    try:
        full, train, val, test = build_all(
            args.phiussiil, args.demo, args.n_hallucinated,
            args.n_misdescribed, args.seed)
    except FileNotFoundError as e:
        print(f"\nERROR: {e}\n", file=sys.stderr)
        return 1

    splits = pd.concat([
        train.assign(split="train"),
        val.assign(split="val"),
        test.assign(split="test"),
    ])
    print("\n=== Step 1 complete: 4-category dataset ===")
    print(pd.crosstab(splits["split"], splits["category"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())