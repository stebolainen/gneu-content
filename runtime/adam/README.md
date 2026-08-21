# Adam runtime contract 9.9.3

Dessa filer är versionshanterade runtime-mallar för Hermes-profilen gneu.

Installerade mål:

- runtime/adam/ADAM_SOUL_TEMPLATE.md -> /root/.hermes/profiles/gneu/SOUL.md
- hermes_source_gate.py -> /root/.hermes/profiles/gneu/scripts/gneu-content-source-gate.py
- hermes_adam_auth.py -> /root/.hermes/profiles/gneu/scripts/gneu-content-adam-auth.py
- hermes_adam_github.py -> /root/.hermes/profiles/gneu/scripts/gneu-content-adam-github.py
- runtime/adam/gneu-content-watch.prompt.md -> prompt för det pausade jobbet gneu-content-watch

Cronjobbet ska vara pausat under installation och verifiering. Dess exakta runtimekontrakt är:

- workdir: /root/gneu-content
- pre-run script: gneu-content-source-gate.py
- no_agent: false
- enabled toolsets: terminal, file, web
- skills: endast grounded-citations
- ingen github-auth eller github-pr-workflow
- prompt: exakt runtime/adam/gneu-content-watch.prompt.md
- state: paused tills samtliga aktiveringsgates i docs/ADMIN_PLAYBOOK.md passerar

Kopiera endast från en verifierad checkout av aktuell origin/main. Installera inga secrets genom denna mall. Alla tre Pythonfiler ska installeras tillsammans med mode 0700, ägare root. SOUL installeras med mode 0600. Jämför SHA-256 mellan checkout och runtime efter installation.

Auth-status kontrolleras utan mint med:

/usr/bin/python3 -I /root/.hermes/profiles/gneu/scripts/gneu-content-adam-auth.py status

Ready kräver owner-only credentialdirectory, numeriskt canonical App ID och en lokalt validerbar private key. Statuskommandot gör inget GitHub-anrop och skapar ingen token.

Legacyfilerna /root/gneu-inbox/github-token och /root/gneu-inbox/github-token.meta.json får inte finnas före aktivering. Om en 9.9.2-token finns ska Admin köra helperns cleanup separat medan jobbet är pausat och därefter verifiera frånvaro utan att visa tokenvärdet.

Varje autentiserad Adam-operation använder exakt:

/usr/bin/python3 -I /root/.hermes/profiles/gneu/scripts/gneu-content-adam-github.py -- <allowlisted-command>

Jobbet får inte aktiveras förrän installerade hashes, auth-status, adapterpolicy, branchskydd, source-state bootstrap, full cold-start-cykel och ack-semantik har verifierats enligt docs/ADMIN_PLAYBOOK.md.

Source-state har en exakt canonical path i gneu-profilen, owner-kontrollerad
katalog, owner-only-fil, symlinkskydd, atomisk fsync-skrivning och processlås.
Malformed eller osäker state ger `state_corrupt`, väcker fail-closed och får
inte tyst bootstrapas över.

## Exakt installation efter merge

Kör som Admin från en ren `/root/gneu-admin` på den verifierade mergecommiten i
`origin/main`. Jobb-ID ska först hämtas med
`HERMES_HOME=/root/.hermes/profiles/gneu hermes cron list --all`; gissa det
aldrig.

1. Pausa befintligt jobb:

   `HERMES_HOME=/root/.hermes/profiles/gneu hermes cron pause <job-id>`

2. Installera kontrollfilerna från samma trusted checkout medan jobbet är pausat:

   `install -o root -g root -m 0700 hermes_source_gate.py /root/.hermes/profiles/gneu/scripts/gneu-content-source-gate.py`

   `install -o root -g root -m 0700 hermes_adam_auth.py /root/.hermes/profiles/gneu/scripts/gneu-content-adam-auth.py`

   `install -o root -g root -m 0700 hermes_adam_github.py /root/.hermes/profiles/gneu/scripts/gneu-content-adam-github.py`

   `install -o root -g root -m 0600 runtime/adam/ADAM_SOUL_TEMPLATE.md /root/.hermes/profiles/gneu/SOUL.md`

3. Jämför SHA-256 för varje repositoryfil mot respektive runtimekopia.

4. Om legacy-token finns, kör först nu cleanup med den installerade och
   hashverifierade 9.9.3-helpern. Verifiera sedan att både token och metadata
   saknas utan att visa innehållet:

   `/usr/bin/python3 -I /root/.hermes/profiles/gneu/scripts/gneu-content-adam-auth.py cleanup`

5. Ersätt jobbkontraktet medan jobbet fortfarande är pausat. `--skill`
   ersätter hela skill-listan och tar därmed bort `github-auth` och
   `github-pr-workflow`:

   `HERMES_HOME=/root/.hermes/profiles/gneu hermes cron edit <job-id> --prompt "$(cat runtime/adam/gneu-content-watch.prompt.md)" --skill grounded-citations --script gneu-content-source-gate.py --workdir /root/gneu-content --agent`

6. Verifiera med
   `HERMES_HOME=/root/.hermes/profiles/gneu hermes cron list --all` att jobbet
   är pausat. Läs därefter
   `/root/.hermes/profiles/gneu/cron/jobs.json` read-only och verifiera exakt en
   skill (`grounded-citations`), enabled toolsets (`terminal`, `file`, `web`),
   workdir, pre-run script, `no_agent: false`, prompt och fortsatt paused state
   mot denna mall. Om enabled toolsets avviker kan nuvarande `hermes cron edit`
   inte korrigera fältet; installationen är då blockerad tills jobbet säkert
   återskapas genom Hermes `cronjob`-API med exakt kontrakt och pausas före
   första möjliga körning.

7. Kör auth-helperns `status` och negativa adaptertester utan att visa secrets.
   Förväntat före separat secretprovisionering är `auth_required`.

8. Provisionera Adams separata GitHub App-secrets efter uttryckligt godkännande.
   Verifiera App-installation, minsta permissions, owner-only filskydd,
   adapterkommando, cleanup och live negativa adaptertester.

9. Verifiera `published` ruleset, App-bypass och required checks live.

10. Verifiera source-state bootstrap och en full cold-start-cykel. Kör därefter
    Publisher `workflow_dispatch` med `dry_run=true` och verifiera att ingen
    merge skedde.

11. Aktivera cron sist och endast efter att samtliga blockerare nedan är stängda.

## Blockerare före aktivering

- PR:n ska vara mergad och installationen gjord från exakt verifierad mergecommit
  på `origin/main`;
- runtimefiler, SOUL, cronprompt och skills ska vara installerade enligt 9.9.3,
  hashverifierade och read-back-verifierade medan jobbet är pausat;
- Adams App-secrets och App-installation ska vara provisionerade och verifierade;
- live negativa adaptertester och cleanup ska passera;
- `published` ruleset, App-bypass och required checks ska vara verifierade;
- source-state/bootstrap, full cold-start och Publisher dry-run ska passera;
- cron ska aktiveras sist.

## Accepterade kvarvarande risker

- Same-UID/root-/proc innebär att en komprometterad Adamprocess med
  private-key-access kan implementera egen App-signering. Risken är uttryckligen
  accepterad för nuvarande miljö och blockerar inte installation,
  secretprovisionering eller första kontrollerade aktivering.
- `--ack` är policybegränsat men inte kryptografiskt eller cycle-bound. Risken är
  uttryckligen accepterad och blockerar inte första kontrollerade aktiveringen.

## Framtida hardening

- separat Linux-identitet/process/container och privilegieseparerad broker för
  signering/mint utan direkt private-key-access för Adam;
- cycle-bound ack med trusted success-proof och verifierbart remote-resultat.
