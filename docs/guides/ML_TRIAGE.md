# Learned Triage Ranking

A scan of a well-known brand returns hundreds of registered permutations, and
the risk score orders them by a formula that is the same for everyone. But
teams differ in what they act on. A bank cares most about mail capability,
because that is the prerequisite for the wire-fraud email. A consumer SaaS
cares most about a cloned login page. A game studio may ignore both and care
about anything selling fake keys.

This feature learns that difference from your own past decisions and reorders
findings accordingly. It is optional, off by default, and strictly additive.

## The rule this feature is built around

**The model ranks. It does not score.**

The deterministic risk score is unchanged whether this is on or off, and it
stays the number that appears in reports and takedown requests. That is the
same rule the AI triage layer follows, for the same reason: a takedown request
to a registrar has to rest on evidence anyone can reproduce. "Registered nine
days ago, valid SPF and DKIM, serving a login page, scored 85" is an argument
a registrar can check. "Our model put it first" is not.

What the model changes is the **order** of a list a human reads, and which
findings surface at the top of a long report.

## Getting started

There is no pre-trained model, and there deliberately isn't one. A model
shipped with the tool would encode some other organisation's idea of what
matters, which is exactly the thing this feature exists to replace.

### 1. Label findings as you triage them

```bash
# Worth acting on: escalated, reported, blocked, taken down
typo-sniper --label secure-example-login.com=acted

# Reviewed and judged not worth acting on
typo-sniper --label example-fanclub.com=dismissed

# Several at once, with a note
typo-sniper \
  --label a.com=acted --label b.com=dismissed
```

**`dismissed` matters as much as `acted`**, and it is the half teams forget.
A model trained only on confirmed-bad examples learns that everything is bad.
If you look at a finding and decide it is nothing, that decision is training
data — record it.

### 2. Check where you are

```bash
typo-sniper -i domains.txt --ml-status
```

```
Labels
  acted:     24
  dismissed: 19
  ✓ 43 labels (24 acted, 19 dismissed)

Model
  trained on 43 labels (24 acted, 19 dismissed)
  cross-validated ROC AUC: 0.831 (±0.074, 5 folds)
  most influential features
    mail_posture               +1.204
    age_days_log               +0.887
    title_parked_words         -0.771
```

### 3. Train

```bash
pip install -e ".[ml]"
typo-sniper -i domains.txt --ml-train
```

Training refuses to run below **30 labels total** and **8 of each class**.
Those floors are not arbitrary politeness: below them a model fits noise, and
a confidently wrong ranking is worse than no ranking, because it looks like
signal.

### 4. Rank

```bash
typo-sniper -i domains.txt --ml-rank
```

Findings are ordered by the model. Each one carries `ml_rank` and `ml_explain`
in the JSON export, so a reordered report says why it was reordered.

## Why logistic regression

A gradient boosted ensemble would probably score a point or two higher on the
same labels. Three things made a linear model the better trade here:

- **It explains itself.** You can open the model file and read that
  `mail_posture` carries weight +1.2 and `title_parked_words` carries -0.8.
  For a tool whose output justifies takedown requests, "why is this first?"
  needs an answer.
- **It is small.** Label sets here are tens of examples, not millions. A
  high-capacity model on forty labels memorises them.
- **It needs no runtime dependency.** See below.

## Training needs scikit-learn. Scoring does not.

The trained model is stored as **JSON** — feature names, weights, intercept,
and the standardisation constants — and scoring is a dot product and a sigmoid
written in plain Python. So:

- A host that runs scans installs nothing. Only whoever trains needs `.[ml]`.
- A model file is readable and reviewable, like any other config.
- **Nothing is ever unpickled.** `pickle.load` on a model file is arbitrary
  code execution, and model files get emailed between colleagues and committed
  to repositories. JSON cannot execute.

That last point is a security property, not a convenience, and it is why the
format is fixed even though pickle would have been less code.

## What the model sees

34 features, all deterministic and all traceable to a field you can look at:

| Group | Examples |
|---|---|
| Lexical | length, digits, hyphens, punycode, entropy |
| Relational | edit distance to the brand, distance relative to brand length, whether the brand name is contained, TLD match |
| DNS | A and MX presence and count, with failed-lookup sentinels excluded |
| Registration | age (log-scaled), recency, whether the registrant is privacy-shielded |
| Posture | mail capability, TLS validity, live HTTP, certificate count |
| Content | brand mentioned in the title, credential words, parked-page words |
| Prior | the deterministic risk score |

The risk score is included as a feature rather than replaced. It encodes
expert judgement that forty labels cannot rediscover, so the model starts from
it and learns adjustments, instead of relearning the problem from scratch.

Two details worth knowing:

- **A failed lookup is not evidence.** A `mail_posture` of `unknown` scores the
  same as `none` rather than being treated as a signal, and DNS sentinels like
  `!ServFail` are not counted as records.
- **Age is log-scaled.** The difference between 3 and 30 days matters far more
  than the difference between 1000 and 1027.

## Features come from the *earliest* snapshot

When training, each label is matched against the oldest retained scan that saw
that domain — not the newest.

This matters more than it sounds. A domain you successfully had taken down
resolves nowhere today. Training on its current state would teach the model
that **dead domains are the dangerous ones**: an inversion of the truth,
learned from perfectly good labels, that would then rank every parked domain
above every live one. The earliest snapshot is the closest available record to
the state the domain was in when you judged it.

A consequence: labels for domains that have aged out of the history retention
window cannot be used, and `--ml-status` reports how many are in that state.
Raise `history_retain` if you see that number growing.

## Failure behaviour

Every failure mode is additive-only:

- No model trained → findings are ordered by risk score, as they always were.
- A model trained on an older feature set → refused with a message telling you
  to retrain, rather than silently scoring a mismatched vector and producing
  plausible nonsense.
- A corrupt model file → logged, ignored, scan continues.
- Scoring throws on one finding → that finding sorts last and keeps every
  deterministic field it had.

There is no path where ranking failing loses a finding or changes a risk score.

## When it will not help

Be honest with yourself about the label set:

- **If your decisions track the risk score exactly**, the model has nothing to
  learn and will reproduce the existing order. That is a real outcome and
  `--ml-status` will show it as an unremarkable ROC AUC near 0.5–0.6.
- **If you only label the bad ones**, training refuses, by design.
- **If your criteria change** — new brand, new threat, new policy — the old
  labels now describe a different problem. Retrain, and consider clearing
  labels that no longer reflect how you would decide today.
