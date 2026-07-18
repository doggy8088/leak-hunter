# Risk model

Findings receive a 0-100 risk score from the matched pattern plus context adjustments.

- Critical: 90-100
- High: 75-89
- Medium: 40-74
- Low: 0-39

Secrets in environment/config files receive a small boost. A file named exactly `.env.example` receives a 25-point reduction instead and does not receive the environment-file boost. Documentation and obvious placeholders are suppressed or reduced. The score is a triage signal, not proof that a credential is valid.
