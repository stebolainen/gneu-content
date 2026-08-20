# gneu-content

Separat repository för GNEU:s strukturerade bevakning av cybersäkerhet och
AI-säkerhet. Innehållet är data, inte produktionskod, och den autonoma
innehållsagenten har ingen produktionsåtkomst.

Den normativa arkitekturen finns i
[`docs/OPERATING_MODEL.md`](docs/OPERATING_MODEL.md).

## Brancher

- `main` är trusted control plane. Den innehåller policy, schema, validator,
  source gate, auth-helper, Publisher Gate, workflows och tester.
- `published` är aktuell publicerad content-state och den branch som
  produktionen ska konsumera.
- `adam/genN-*` innehåller Adams publiceringsförslag och går via PR mot
  `published`.
- `admin/*` innehåller tekniska ändringar och går via PR mot `main`.

Ingen agent får pusha direkt till `main` eller `published`.

## Roller

- **Adam** är autonom omvärldsbevakare, researcher och primär skribent för
  cyber- och AI-säkerhet. Adam arbetar från `published`, skapar förslag och får
  aldrig mergea eller publicera sitt eget material.
- **GNEU Förvaltare** är redaktionell ägare och chefredaktör. Förvaltaren äger
  syfte, scope, relevans, källprinciper, class A/B, kvalitet och rättelser.
- **GNEU Admin** är teknisk ägare för drift, schema, validator, source gate,
  auth, Apps, wrappers, Publisher Gate, Actions, rulesets och recovery.
- **Publisher** är en separat GitHub App-identitet som endast får mergea genom
  Trusted Publisher Gate och aldrig får ha ruleset-bypass.

Rollerna och deras trust boundaries får inte sammanföras till en gemensam
credential eller en ensam autonom beslutsväg.

## Centrala filer

- `events.json` — strukturerade events för aktuell branch
- `manifest.json` — generation, event count och SHA-256 för exakt `events.json`
- `validate_content.py` — fristående content-validator
- `publisher_gate.py` — trusted append-only gate för autonom class A-publicering
- `hermes_source_gate.py` — deterministisk pre-run source gate
- `hermes_adam_auth.py` — ephemeral Adam GitHub App-auth
- `AGENTS.md` — hårda repositoryregler för Adam
- `docs/ADAM_PLAYBOOK.md` — Adams cold-start-körinstruktion
- `docs/FORVALTARE_PLAYBOOK.md` — auktoritativ redaktionell policy
- `docs/ADMIN_PLAYBOOK.md` — teknisk drift och recovery
- `.github/workflows/validate.yml` — content validation
- `.github/workflows/publisher.yml` — Trusted Publisher Gate-workflow

## Contentvalidering

Efter en contentändring:

```bash
python3 validate_content.py --write-manifest
python3 validate_content.py
```

`published` ska skyddas med PR, required status check `validate`, up-to-date
branch och blockerad force-push/deletion. Adam och Publisher får inte ha bypass.

## Publiceringsflöde

```text
source-signal
  -> Adam research och förslag
  -> validator
  -> PR mot published
  -> validate
  -> Trusted Publisher Gate eller mänsklig hantering
  -> published
  -> produktionspull och produktionsvalidering
```

Endast exakt ett appendat class A-event med `confidence: verified` och samtliga
Publisher Gate-invariants kan autopubliceras. Class B, rättelser och
uppdateringar kräver mänsklig redaktionell hantering.

Autopublish är fail-closed och avstängd tills
`AUTOPUBLISH_ENABLED=true`. Se releasehistoriken i
[`docs/publisher-9.9.md`](docs/publisher-9.9.md).

## Releasehistorik

- [`docs/publisher-9.9.md`](docs/publisher-9.9.md) — introduktion av Autonomous
  Publisher Gate
- [`docs/hermes-watch-9.9.1.md`](docs/hermes-watch-9.9.1.md) — introduktion av
  economical Hermes watch
- [`docs/hermes-watch-9.9.2.md`](docs/hermes-watch-9.9.2.md) — introduktion av
  ephemeral Adam auth

Releaseanteckningarna bevaras som historik. Använd de normativa playbooks ovan,
inte äldre releaseinstruktioner, för ny installation och recovery.
