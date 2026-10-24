# Withings Dashboard

Private Web-App, die die Messungen einer Withings-Waage anzeigt.

- `site/` – die App (wird über GitHub Pages veröffentlicht). Die Messwerte liegen verschlüsselt in `site/data.enc.json`.
- `scripts/withings.py` – holt die Messungen von Withings.
- `.github/workflows/abruf.yml` – Abruf morgens alle 5 Minuten, sonst stündlich.
- `state/token.enc` – verschlüsselter Withings-Zugang.
- `config.json` – `start_datum` (JJJJ-MM-TT): ab welchem Tag die App rechnet. `null` = alle Messungen.

Benötigte Secrets: `WITHINGS_CLIENT_ID`, `WITHINGS_CLIENT_SECRET`, `STATE_KEY`, `DASHBOARD_PASSWORD`.
