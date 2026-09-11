# Admin GitHub App broker runtime contract

Dessa filer är den versionshanterade source of truth för GNEU Admins
GitHub App-broker och wrapper:

- `runtime/admin/gneu-github-app` -> `/usr/local/sbin/gneu-github-app`
- `runtime/admin/gneu-admin-github` -> `/usr/local/bin/gneu-admin-github`

Brokern är gemensam för Admin och Förvaltaren, men väljer token-permissions
efter profil. Endast `gneu-admin` får begära `workflows: write`.
`gneu-forvaltare` får endast begära `contents: write` och
`pull_requests: write`. Adam använder sin separata credential-adapter och
Publisher mintar token separat i GitHub Actions.

## Separat read-only-väg för gneu-se

`gneu-admin-github gneu-se-read` är en separat Admin-väg som aldrig använder
det befintliga write-capable tokenet för `stebolainen/gneu-content`. För varje
godkänt anrop mintar brokern ett eget installation-token för installation
`155274448` med exakt repositoryurval:

```json
{"repositories":["gneu-se"]}
```

Token-requesten innehåller endast `actions: read`, `contents: read` och
`pull_requests: read`. GitHub ger repository-metadata implicit read-only;
`metadata` skickas därför inte som explicit permission i token-requesten.
Brokern verifierar både permissions och att tokenets faktiska repositorylista
är exakt `stebolainen/gneu-se` innan den utför läsningen. Tokenet återkallas i
`finally` och värdet skrivs aldrig ut.

Tillåtna namngivna operationer är:

```text
gneu-admin-github gneu-se-read repo
gneu-admin-github gneu-se-read workflow-run RUN_ID
gneu-admin-github gneu-se-read workflow-jobs RUN_ID
gneu-admin-github gneu-se-read workflow-job JOB_ID
gneu-admin-github gneu-se-read pr-list
gneu-admin-github gneu-se-read pr-view PR_NUMBER
gneu-admin-github gneu-se-read branch BRANCH
gneu-admin-github gneu-se-read ref heads/BRANCH
gneu-admin-github gneu-se-read contents PATH [--ref REF]
```

`workflow-job` returnerar även GitHubs stegmetadata. Separat loggdownload är
inte tillåten: Actions loggendpoint kan redirecta till extern objektlagring och
denna broker har ingen godkänd cross-origin- eller säker filhanteringsmodell.

### Fail-closed outputkontrakt

GitHubs råa responseobjekt får aldrig skrivas till stdout, stderr, logg eller
felmeddelande. Varje namngiven operation verifierar i stället förväntad
root- och fälttyp och projicerar endast följande fält:

- `repo`: namn, fullständigt namn, owner-login, private/default branch samt
  archived/disabled;
- `workflow-run`: run-, workflow- och attempt-ID, namn, event, status,
  conclusion, head branch/SHA och tidsstämplar;
- `workflow-jobs` och `workflow-job`: total count samt job-ID, namn, status,
  conclusion, head-SHA, tidsstämplar och motsvarande allowlistade stegfält;
- `pr-list` och `pr-view`: nummer, titel, state, draft, merge-/create-/update-
  tid, user-login samt base/head ref och SHA;
- `branch` och `ref`: namn/ref, protected samt objekttyp och SHA;
- `contents`: namn, path, SHA, size och type; en fil får dessutom innehålla
  endast `encoding` och själva API-innehållet i `content`.

URL:er, repositoryobjekt, links, runnerdetaljer och alla andra fält kastas
bort. Oväntad shape ger endast `BLOCKED_UNSAFE_RESPONSE`; råvärdet inkluderas
aldrig i felet. Före serialisering kontrolleras det projicerade objektets keys
och URL-querystruktur som defense in depth mot credential-, token- och
signaturfält. HTTP-fel normaliseras till statuskod utan serverstyrd message.
Endast canonical JSON från den färdiga projektionen får skrivas till stdout.

Alla operationer använder fasta GET-endpoints för exakt
`stebolainen/gneu-se`. Det finns ingen caller-styrd repositoryparameter eller
generell API-pass-through. `gh api`, skrivmetoder, workflow dispatch/rerun/
cancel, branchmutation, PR-mutation, contents- och workflowskrivning, releases
och permissionsmutation förblir blockerade. Den äldre `check`/`exec`-vägen och
dess tokenpolicy för `stebolainen/gneu-content` är oförändrade.

## Separat teknisk gneu-se PR-writer

Efter human merge och separat provisioning finns en ny route:

```text
gneu-admin-github gneu-se-admin-pr check --request /absolute/request.json
gneu-admin-github gneu-se-admin-pr create --request /absolute/request.json
```

`check` är en helt lokal schema-/policykontroll utan mint eller nätverk. Den
bevisar inte remote base/branch-state. `create` utför hela create-only-cykeln;
det finns inga generella shell-, Git-, URL-, API- eller permissionsargument.
Requestfilen måste vara en begränsad regular file, inte symlink/FIFO. JSON
avvisar dubbla eller okända keys. Exempel (syntetisk SHA; ersätt med verifierad
current main):

```json
{
  "expected_main_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "branch": "admin/technical-example",
  "title": "Technical example",
  "message": "Technical example",
  "files": [{"path": "docs/technical-example.md", "content": "Technical documentation.\n"}]
}
```

### Roller och token

- `gneu-se-read` = observation only, oförändrad GET-policy och read-token.
- `gneu-se-admin-pr` = endast teknisk ny Admin-branch och PR.
- Human = review och merge; denna route kan aldrig mergea.

Writer mintar separat per operation, endast från `gneu-admin` och installation
`155274448`, med `repositories: ["gneu-se"]`. Requesten är exakt
`contents: write`, `pull_requests: write`; endast om en tillåten workflowfil
ingår läggs `workflows: write` till. Metadata är implicit read. Mint-resultatets
permissions måste matcha exakt (utöver implicit metadata), och tokenets faktiska
repositorylista måste vara exakt `stebolainen/gneu-se` innan första repoanropet.
Actions, administration, secrets, variables, environments och övriga permissions
begärs aldrig. Token stannar i broker-minnet och återkallas i `finally`; inget
caller-kommando får credentials. Ingen live writer-token eller gneu-se-write
behövs för PR-sessionens syntetiska regressionstester.

### Create-only, expected base och fel

`expected_main_sha` krävs alltid för en request. Före varje write läses main
igen och måste matcha exakt, annars `STALE_BASE`. En ny commit får exakt en
parent, denna main-SHA. Endast en ny ref till den commiten skapas, aldrig en
ref-update. Detta motsvarar en ny branch direkt ovanpå exact main med en enda
teknisk commit. Det finns ingen automatisk rebase eller append-commit-route.

Branchsyntax är den snävare delmängden `admin/<lowercase-hyphenated-slug>`.
Redan existerande/matchande ref eller tidigare PR för branch blockerar. PR-base
är hårdkodad `main`. Efter skapande verifieras commit-parent/tree, branch/head,
PR och aktuell main igen. GitHub erbjuder ingen atomisk transaktion som låser
main över alla anrop: en extern race kan lämna orphan Git-objekt eller en ny
Admin-branch/PR medan routen failar. Den kan fortfarande aldrig skriva main.
Ingen automatisk retry, force, overwrite, rollback, delete eller close görs;
operatören inspekterar eventuell partiell state innan nästa humanbeslut.

### Filpolicy

Positiv allowlist: exakt den befintliga rootfilen `deploy.sh`, tekniska
`.py/.php/.sh/.json/.md` under `scripts/`, Markdown under `docs/`, root
`test_*.py` samt exakt `.github/workflows/<name>.yml|yaml`.
`scripts/config.php`, secret-/credentialkataloger, path traversal, symlinks,
submodules, modeändringar och deletions blockeras. Nya filer skrivs fortsatt som
regular blobs mode `100644`; befintliga regular blobs mode `100644` eller
`100755` får uppdateras endast med exakt sitt befintliga mode bevarat.
`deploy.sh` måste redan finnas i trusted base och behåller därmed sitt befintliga
mode `100755`; den får aldrig skapas som ny rootfil. Requesten har högst 40
filer, 200 KB per fil och 800 KB sammanlagt UTF-8-innehåll.

Alla `data/`, `aihot/`, `sitemap.xml`, `ai-hot.html` och andra publiceringsytor
är därmed uteslutna, inte bara de nu kända canonical AI-hot-filerna. Brokern
verifierar föräldrarnas Git-typer och jämför hela resulting trädet med exakt
allowlistad delta innan commit/ref/PR. Inga response-objekt eller filinnehåll
skrivs ut; endast validerad repo/branch/base/commit/PR-metadata projiceras.
Felmeddelanden är fasta koder och återger inte rå exceptions.

Detta är inte production deployment eller AI-hot publication authorization.
Tekniska workflowförslag är säkerhetsrelevanta: GitHub kan köra sina normala
push/PR-checks efter branch/PR-skapande. Avsaknad av `actions: write` är inte ett
förbud mot sådana automatiska triggers. Human review och befintliga GitHub
workflow-/secret-skydd krävs; brokern exekverar aldrig föreslagen kod själv.

Regression: `test_admin_gneu_se_writer.py`, befintliga Admin auth-policy- och
sanitizationtester. Samtliga tidigare read-/gneu-content-funktioner jämförs
AST-mässigt med trusted baseline. Inga ändringar i gneu-content-policyn.

## Installation efter merge

Runtimefilerna får aldrig handredigeras. Installera dem endast efter att
ändringen har mergats, från en ren checkout av exakt verifierad mergecommit på
`origin/main`. Installation, deploy eller merge ingår inte i en PR-session.

1. Hämta `origin` genom den installerade Admin-wrappern och verifiera checkout:

   ```bash
   /usr/local/bin/gneu-admin-github exec -- git fetch origin
   test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
   test -z "$(git status --porcelain)"
   ```

2. Registrera source-hasharna innan installation:

   ```bash
   sha256sum runtime/admin/gneu-github-app \
     runtime/admin/gneu-admin-github
   ```

3. Installera båda filerna från samma checkout:

   ```bash
   install -o root -g root -m 0755 \
     runtime/admin/gneu-github-app \
     /usr/local/sbin/gneu-github-app
   install -o root -g root -m 0755 \
     runtime/admin/gneu-admin-github \
     /usr/local/bin/gneu-admin-github
   ```

4. Verifiera byteidentitet och SHA-256 mot source of truth:

   ```bash
   cmp --silent runtime/admin/gneu-github-app \
     /usr/local/sbin/gneu-github-app
   cmp --silent runtime/admin/gneu-admin-github \
     /usr/local/bin/gneu-admin-github
   sha256sum runtime/admin/gneu-github-app \
     /usr/local/sbin/gneu-github-app \
     runtime/admin/gneu-admin-github \
     /usr/local/bin/gneu-admin-github
   ```

5. Kör permission-checken:

   ```bash
   /usr/local/bin/gneu-admin-github check
   /usr/local/bin/gneu-admin-github gneu-se-check
   ```

   Checken ska visa `contents: write`, `pull_requests: write` och
   `workflows: write` och ska avslutas utan fel. Tokenvärdet får aldrig visas
   eller sparas. `gneu-se-check` ska dessutom visa endast repository
   `stebolainen/gneu-se`, `actions: read`, `contents: read`,
   `pull_requests: read` och implicit `metadata: read`. Brokern återkallar
   token i `finally`.

Om checkout, hash, bytejämförelse eller permission-check avviker ska
installationen betraktas som blockerad. Ändra inte runtimefilen för att få
kontrollen att passera; rätta den trackade källan genom en ny Admin-PR.
