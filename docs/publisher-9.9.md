# gneu-content 9.9 — Autonomous Publisher Gate

## Syfte

9.9 separerar innehållsagenten Adam från publiceringsbeslutet.

Adam får fortsätta:
- bevaka källor
- skapa `adam/genN-*` branches
- ändra `events.json` + `manifest.json`
- validera
- skapa PR mot `published`

Adam får **inte** merge-behörighet.

En separat GitHub App (`gneu-content-publisher`) får endast den behörighet som
krävs för att merge:a en redan godkänd PR.

## Kontrollplan

Workflow: `.github/workflows/publisher.yml`

Workflowen ligger på repositoryts default branch `main` och körs var femte minut.
Den använder endast betrodd kod från `main`.

PR-branchens kod checkas aldrig ut och exekveras aldrig.

PR-data hämtas via GitHub API och behandlas som opålitlig data.

## Gate 9.9

Autopublish tillåts endast när samtliga krav är uppfyllda:

1. PR är öppen och inte draft.
2. Base är exakt `published`.
3. Head finns i samma repository — forks blockeras.
4. Branch matchar `adam/genN-*`.
5. Head bygger direkt ovanpå aktuell `published`; divergerad/gammal branch blockeras.
6. Exakt två filer är ändrade:
   - `events.json`
   - `manifest.json`
7. Båda filerna är modifierade, inte skapade/raderade.
8. GitHub Actions-checken `validate` har `success` på exakt aktuell head SHA.
9. Base och head har giltigt schema, manifest, count och SHA-256.
10. Generation ökar exakt +1.
11. Branchens `genN` matchar generationen.
12. Befintliga publicerade events är byte-semantiskt oförändrade i JSON-strukturen.
13. Exakt ett event får appendas per automatisk generation.
14. Det nya eventet måste vara `publication_class: A`.
15. Det nya eventet måste ha `confidence: verified`.
16. Event-id får inte redan finnas.
17. Head körs genom en **trusted copy** av `validate_content.py` från `main`.
18. Merge använder `--match-head-commit` för att blockera TOCTOU/head-byte.

Class B, korrigering av befintliga events, flera nya events eller förändringar av
validator/workflow/AGENTS kräver fortsatt mänsklig hantering.

## Kill switch

Autopublish är AV tills repository variable:

`AUTOPUBLISH_ENABLED=true`

sätts.

Saknas variabeln eller har annat värde gör schemat ingen merge.

## Dry-run

Workflowen kan startas manuellt med `workflow_dispatch` och `dry_run=true`.
Då görs hela gate-kontrollen men ingen GitHub App-token skapas och ingen merge sker.

Det är rekommenderat första läget.

## GitHub App

Skapa en separat GitHub App, exempelvis:

`gneu-content-publisher`

Installera den **endast** på `stebolainen/gneu-content`.

Repository permissions:
- Contents: Read and write
- Pull requests: Read and write
- Metadata: Read-only (implicit)

Ingen:
- Administration
- Actions write
- Secrets
- Environments
- andra repositories

Spara därefter:

Repository variable:
`PUBLISHER_APP_CLIENT_ID`

Repository secret:
`PUBLISHER_APP_PRIVATE_KEY`

Workflowen använder `actions/create-github-app-token` för ett kortlivat
installation-token. Appens privata nyckel går aldrig till Adam.

## Ruleset

`published` ska fortsatt kräva:
- pull request
- required status check `validate`
- branch up to date
- force-push blockerat
- deletion blockerat

Publisher App ska **inte** få bypass av ruleset.

Gate använder aldrig `--admin`.

## Rollseparation

Adam:
`source -> event -> validator -> PR`

Publisher:
`PR -> trusted gate -> merge`

Loopia:
`published -> HTTPS pull -> production validator -> atomic snapshot -> Pulse`

Tre separata säkerhetsgränser.
