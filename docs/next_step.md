# Next Steps

## Priority next session

### 1. Finish threshold tuning workflow

- Run threshold analysis against the newest XGBoost artifact.
- Review the generated JSON in `docs/model_metrics/`.
- Pick the best threshold for deployment, likely optimizing for F1 or a precision-recall tradeoff that fits the project goals.
- Update the artifact metadata or training flow so the chosen threshold becomes the default deployment threshold.

Suggested command:

```bash
python -m sentinelti.ml.threshold_analysis --artifact sentinelti/models/url_classifier_xgb.joblib --optimize-for f1
```

### 2. Expose richer model metadata in the API

Update `sentinelti/api.py` so `/model-info` can return additional metadata when present, especially:

- `top_features`
- possibly threshold provenance later (artifact vs env)

Then extend `tests/test_api.py` to cover the richer response payload.

### 3. Decide what to do with Logistic Regression

Current state:

- Logistic Regression trains successfully.
- It throws a convergence warning with the current configuration.

Evaluate one of these options:

- add feature scaling for the Logistic Regression pipeline,
- increase `max_iter`,
- try a different solver,
- or keep it as a secondary benchmark model if XGBoost remains clearly stronger.

### 4. Frontend alignment

Once `/model-info` is enriched, update the frontend to display:

- model type
- threshold
- key metrics
- top features

Also harden React components against null or partial metadata.

## Nice-to-have after that

- Add a small doc describing the ML artifact schema.
- Add a script to write threshold recommendations back into artifact metadata.
- Consider a future Ollama-based explanation layer only after the deterministic ML pipeline is fully settled.