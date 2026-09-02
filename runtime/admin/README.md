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
   ```

   Checken ska visa `contents: write`, `pull_requests: write` och
   `workflows: write` och ska avslutas utan fel. Tokenvärdet får aldrig visas
   eller sparas. Brokern återkallar token i `finally`.

Om checkout, hash, bytejämförelse eller permission-check avviker ska
installationen betraktas som blockerad. Ändra inte runtimefilen för att få
kontrollen att passera; rätta den trackade källan genom en ny Admin-PR.
