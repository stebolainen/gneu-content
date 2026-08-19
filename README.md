# gneu-content

Separat, icke-exekverbart content-repo för Adam.

Adam får skapa strukturerade events men har ingen produktionsåtkomst.

## Filer

- `events.json` — publicerbara events
- `manifest.json` — generation + SHA-256 för exakt events.json
- `validate_content.py` — fristående validator
- `AGENTS.md` — Adams arbetsregler
- `.github/workflows/validate.yml` — obligatorisk CI

## Arbetsgång

Efter ändring:

```bash
python3 validate_content.py --write-manifest
python3 validate_content.py
```

Skydda `published` med required status check `validate`.
Låt inte Adam få administrationsbehörighet eller rätt att kringgå branch protection.

På gneu.se sätts därefter:

```php
'ADAM_CONTENT_BASE_URL' => 'https://raw.githubusercontent.com/OWNER/gneu-content/published',
```

Produktionens cron hämtar materialet. Adam har ingen kontakt med Loopia.

## 9.9 Autonomous Publisher Gate

Repositoryts `main` fungerar som kontrollplan för automatisk publicering.
`publisher_gate.py` och `.github/workflows/publisher.yml` får aldrig ändras av
Adams normala content-PR:er.

Autopublish är fail-closed och avstängd tills `AUTOPUBLISH_ENABLED=true`.
Se `docs/publisher-9.9.md`.
