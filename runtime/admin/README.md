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

Alla operationer använder fasta GET-endpoints för exakt
`stebolainen/gneu-se`. Det finns ingen caller-styrd repositoryparameter eller
generell API-pass-through. `gh api`, skrivmetoder, workflow dispatch/rerun/
cancel, branchmutation, PR-mutation, contents- och workflowskrivning, releases
och permissionsmutation förblir blockerade. Den äldre `check`/`exec`-vägen och
dess tokenpolicy för `stebolainen/gneu-content` är oförändrade.

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
