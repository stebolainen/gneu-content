# gneu-content 9.9.3 — Adam credential adapter

Detta dokument beskriver det versionshanterade installations- och
anropskontraktet för Adams policybegränsade GitHub-adapter. Den normativa
arkitekturen finns i [`OPERATING_MODEL.md`](OPERATING_MODEL.md), Adams körsteg i
[`ADAM_PLAYBOOK.md`](ADAM_PLAYBOOK.md) och Admins recoveryprocedur i
[`ADMIN_PLAYBOOK.md`](ADMIN_PLAYBOOK.md).

## Design

`hermes_adam_github.py` är den enda godkända autentiserade GitHub-vägen för
Adam. För varje tillåtet kommando:

1. valideras hela argumentvektorn innan auth används;
2. en eventuell gammal 9.9.2-token städas;
3. en ny repository-scoped installation-token mintas i minnet genom den
   befintliga `hermes_adam_auth.py`-implementationen, utan runtime-tokenfil;
4. exakt ett tillåtet `/usr/bin/git`- eller `/usr/bin/gh`-kommando körs utan
   shell;
5. token återkallas/rensas i `finally`, även när kommandot misslyckas.

Git får credential endast genom processmiljöns temporära config. Persistent
credential helper, prompt, global/system-gitconfig, hooks, proxyoverride och
tracevariabler stängs av. `gh` får token endast som `GH_TOKEN`, använder en tom
temporär `GH_CONFIG_DIR` och låses till `github.com`. Token skrivs aldrig till
remote URL, gitconfig på disk, `~/.git-credentials` eller adapteroutput.

Repositoryargumentet ersätts eller verifieras mot exakt
`stebolainen/gneu-content`. Okända program, subkommandon, flaggor, dubbla
flaggor, equals-former och malformed argument nekas före mint.

## Branchformat

Den tekniskt accepterade formen är:

```text
adam/genN-kort-beskrivning
```

`N` är ett kanoniskt positivt heltal utan inledande nollor. Beskrivningen är en
eller flera gemenseparerade alfanumeriska delar, exempelvis
`adam/gen12-cisa-kev`. Slash, versaler, punkt, underscore, tom beskrivning och
`gen0` nekas.

## Installation från betrodd main

Installera inga secrets med dessa kommandon. Kör från en ren checkout av exakt
verifierad `origin/main` och kopiera auth-helper och adapter tillsammans:

```bash
install -m 0700 hermes_adam_auth.py \
  "$HERMES_HOME/scripts/gneu-content-adam-auth.py"
install -m 0700 hermes_adam_github.py \
  "$HERMES_HOME/scripts/gneu-content-adam-github.py"
```

Verifiera efter kopiering att båda runtimefilerna har samma SHA-256 som filerna
på den betrodda `origin/main`-commiten. Secrets provisioneras separat enligt
Admin Playbook. Adapter och auth-helper måste ligga i samma directory; adaptern
laddar endast den betrodda siblingfilen `gneu-content-adam-auth.py` eller, i en
repositorycheckout, `hermes_adam_auth.py`.

Runtimeförutsättningar är Linuxverktygen `/usr/bin/git`, `/usr/bin/gh`, Python 3
och `openssl`. Saknad helper, osäker tokenfil, fel repositoryscope eller mintfel
ger `AUTH_REQUIRED`; det tillåtna child-kommandot startas inte.

Auth-helperns CLI tillåter i 9.9.3 endast `status` och `cleanup`. Den kan inte
skriva en ny tokenfil. Source gate kör endast `status`, som verifierar lokal
owner-only konfiguration, canonical numeriskt App ID och private-key-struktur
utan nätverk eller token-mint. Source gate kräver dessutom den installerade
adaptern och sätter endast `ready`, `auth_required` eller `error` i wake-context.

Vid riktig auth kräver adaptern installationsnamnet
`scripts/gneu-content-adam-github.py`, härleder aktivt `HERMES_HOME` från denna
path och ignorerar anroparens `HERMES_HOME`, `GNEU_ADAM_APP_SECRET_DIR` och
`GNEU_GITHUB_TOKEN_FILE`. Det hindrar byte till en annan Apps secret directory.

## Exakt invocation

Varje autentiserat Git- eller GitHub CLI-kommando måste anropas som:

```bash
/usr/bin/python3 -I "$HERMES_HOME/scripts/gneu-content-adam-github.py" -- <tillåtet kommando>
```

`-I` är obligatoriskt och adaptern nekar start utan Python isolated mode. Det
hindrar `PYTHONPATH`, user site-packages och aktuell katalog från att injicera
moduler innan policyn laddas.

Exempel:

```bash
/usr/bin/python3 -I "$ADAPTER" -- git fetch origin
/usr/bin/python3 -I "$ADAPTER" -- git ls-remote --heads origin
/usr/bin/python3 -I "$ADAPTER" -- git push --set-upstream origin \
  HEAD:refs/heads/adam/gen12-cisa-kev
/usr/bin/python3 -I "$ADAPTER" -- gh pr create \
  --repo stebolainen/gneu-content \
  --base published \
  --head adam/gen12-cisa-kev \
  --title "<titel>" \
  --body "<beskrivning>"
/usr/bin/python3 -I "$ADAPTER" -- gh pr list \
  --repo stebolainen/gneu-content \
  --head adam/gen12-cisa-kev \
  --base published \
  --state open \
  --json number,url,state,headRefName,headRefOid,baseRefName
/usr/bin/python3 -I "$ADAPTER" -- gh pr view 42 \
  --repo stebolainen/gneu-content \
  --json number,url,state,headRefOid
/usr/bin/python3 -I "$ADAPTER" -- gh pr checks 42 --repo stebolainen/gneu-content
```

Det låsta `git fetch origin` översätts till explicita force-refspecs för endast
`main` och `published`; det uppdaterar
`refs/remotes/origin/main` och `refs/remotes/origin/published` i stället för att
enbart lämna resultatet i `FETCH_HEAD`. Cold start läser policy först efter att
dessa refs har uppdaterats.

Vanlig autentiserad `git` eller `gh` är inte en fallback. `POLICY_DENIED`,
`AUTH_REQUIRED` och `ADAPTER_ERROR` ska stoppa cykeln utan ack.

## Runtime- och cronpromptkontrakt

De versionshanterade mallarna i [`../runtime/adam/`](../runtime/adam/) anger
Adams SOUL och fulla cold-start-prompt. Cronprompten ska ange adapterns absoluta,
hashverifierade path och instruera en tom session att:

- använda adaptern för varje autentiserad `git fetch`, `git ls-remote`,
  `git push` och `gh pr`-operation;
- aldrig läsa tokenfilen eller konstruera egen credentiallösning;
- aldrig använda generell `github-auth`, vanlig autentiserad `git` eller vanlig
  `gh`;
- returnera `AUTH_REQUIRED` om adapter/auth inte är redo;
- inte ack:a efter adapter-, push-, PR- eller verifieringsfel.

Runtimeinstallationen ska kopiera source gate, auth-helper och adapter från
samma verifierade `origin/main`, ersätta SOUL och jobbprompt med mallarna, ladda
endast `grounded-citations` och hålla jobbet pausat. Secrets provisioneras
separat och cron aktiveras sist efter samtliga recoverygates.

## Ack och kvarvarande bevisgräns

`--ack` påverkar endast source-state och får köras efter komplett framgångsrik
`NO_CHANGE` eller remote-verifierat giltigt PR-resultat. Det får aldrig köras
vid auth-, source-, validator-, adapter-, push-, PR- eller remote-state-fel.
Gatekommandot kan fortfarande inte kryptografiskt bevisa att den anropande
agentcykeln verkligen uppfyllde villkoren; detta är en dokumenterad kvarvarande
svaghet och ack ska därför fortsatt betraktas som en privilegierad
agentåtgärd/policykontroll tills separat proof införs.

Det finns även en separat OS-trustgräns som denna Pythonadapter inte ensam kan
lösa: om Adam kör godtycklig kod som samma OS-identitet som kan läsa Appens
private key kan processen tekniskt kringgå adaptern genom att implementera egen
GitHub App-auth. Prompten och borttagna generiska skills minskar inte denna
privilegierisk. Före secretprovisionering eller aktivering måste runtime
privilegieseparera mint/signering till en broker/identitet som Adam varken kan
läsa eller exekvera godtycklig kod som. Att dokumentera Adamprocessen som
betrodd kod är inte en tillåten ersättning för denna tekniska gräns. Utan den
verifierade trust boundaryn är både secretprovisionering och aktivering
blockerade, även om adapterns egna allowlist-tester passerar.

## Policyöversikt

Tillåtet:

- `git fetch origin`;
- `git ls-remote origin` och `git ls-remote --heads origin`;
- en enda explicit `HEAD:refs/heads/adam/genN-*`-refspec, med valfri `-u` eller
  `--set-upstream`;
- `gh pr create` med explicit exakt repo, base `published`, canonical head samt
  explicit title och body;
- begränsade read-only `gh pr list`, `view`, `checks` och `status`.

Allt annat nekas, inklusive direct/force/broad/delete/tag-push, PR mot `main`,
annan head, merge/close/edit, generell `gh api`, workflow-, secret-, variable-
och adminoperationer samt andra program.
