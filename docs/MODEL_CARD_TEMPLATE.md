# Model card template

`reports/model_card.py` generates a card for every registered model. It is stored at
`.local/models/<domain>/<model_id>/MODEL_CARD.md` and shown on the model page. The card is private
by default. These sections are required:

1. **Identity.** Model id, domain (and the statement that it only applies to that domain), algorithm
   + scikit-learn version, status.
2. **Inputs.** Feature set + schema version, feature order, stateless transforms, window config +
   cfg hash.
3. **Training.**
   - Dataset id, provenance, privacy class; experiment id; split manifest hash.
   - Number of train windows, train cutoff, exclusions (non-baseline labels, ineligible windows).
   - Baseline assumption and contamination risk.
   - Hyperparameter grid trials and the selection rule; random state.
4. **Score semantics.**
   - `anomaly_score = -score_samples(X)`, higher = more anomalous.
   - It is not a probability of attack. `contamination='auto'` is not a malicious-traffic rate.
   - How the UI percentile is computed.
5. **Operating threshold.** Value, version, criterion (validation max-F1 or quantile), any manual
   override with reason.
6. **Validation metrics.** Used for selection, so optimistic.
7. **Frozen test metrics.**
   - T1 and T2 with supports, N/A for undefined values, grouped-alert counts.
   - Whether the test was previously seen.
8. **Limitations / known false positives.**
   - Operational failures and authorized load.
   - Low-and-slow attacks below window variance.
   - Tiny windows with duplicate vectors.
   - Missing fields lead to abstention.
   - The dataset caveat (synthetic / lab).
9. **Provenance.** Creation time and actor, pseudonym key id, artifact format/hash, integrity key id,
   dependency versions. Artifacts and baselines trained on private data are not public by default.
