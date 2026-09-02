# GNEU Admin Playbook

Detta dokument är den auktoritativa tekniska drift- och recoveryproceduren för
GNEU Admin. Arkitektur och rollgränser definieras i
[`OPERATING_MODEL.md`](OPERATING_MODEL.md). Redaktionell policy ägs av
[`FORVALTARE_PLAYBOOK.md`](FORVALTARE_PLAYBOOK.md).

## Uppdrag och scope

GNEU Admin äger teknisk drift, schema, validatorer, source gate, automation,
GitHub Apps, wrappers, Publisher Gate, Actions, branchskydd, rulesets och
recovery.

Admin:

- arbetar normalt endast i `/root/gneu-admin`;
- rör aldrig Adams `/root/gneu-content` eller Förvaltarens arbetskatalog;
- arbetar aldrig direkt på `main` eller `published`;
- använder endast `admin/*` för tekniska ändringar;
- använder `gneu-admin-github` för alla autentiserade GitHub-operationer;
- läser eller återanvänder aldrig andra identiteters credentials;
- fattar normalt inte redaktionella beslut om events.

Repositoryts kod och skyddsmekanismer är source of truth. Tidigare
sessionshistorik är endast kontext, aldrig bevis för aktuell state.

## Read-only health review

Börja alltid med en read-only kontroll:

1. verifiera `pwd` och att arbetskatalogen är `/root/gneu-admin`;
2. kör `git status --short --branch` och notera befintlig state;
3. hämta med `gneu-admin-github exec -- git fetch origin`;
4. registrera exakt `origin/main` SHA;
5. läs `AGENTS.md`, `README.md`, aktuella playbooks, gatekod, workflows och
   relevanta tester från aktuell `origin/main`;
6. jämför tracked worktree mot `origin/main` utan att röra otrackade filer;
7. kör relevanta read-only tester med bytecode avstängt när en helt ren
   arbetsyta krävs;
8. rapportera vad som verifierats och vad som förblev oåtkomligt.

Om arbetsytan innehåller okända ändringar ska de inte raderas, stashas eller
tas över. Stoppa en skrivande ändring om den inte säkert kan isoleras.

## Repositorykontroller

Minsta kontrollpaket för nuvarande repository är:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 test_admin_auth_policy.py
PYTHONDONTWRITEBYTECODE=1 python3 test_hermes_source_gate.py
PYTHONDONTWRITEBYTECODE=1 python3 test_hermes_adam_auth.py
PYTHONDONTWRITEBYTECODE=1 python3 test_hermes_adam_github.py
PYTHONDONTWRITEBYTECODE=1 python3 test_publisher_gate.py
PYTHONDONTWRITEBYTECODE=1 python3 validate_content.py
```

Vid dokumentationsändringar ska Admin dessutom kontrollera:

- att endast avsedda Markdownfiler är ändrade;
- att inga runtimefiler, workflows, events eller manifest har ändrats;
- att alla relativa dokumentlänkar pekar på filer som finns;
- att dokumenten har en tydlig och unik normativ ägare;
- att `git diff --check` passerar;
- att diffen är granskad före commit.

Tester får aldrig kringgås eller ändras bara för att en ändring ska passera.

## Runtime review utan secretsexponering

Runtime review får kontrollera metadata och säkra statuskommandon men aldrig
skriva ut hemliga värden.

Kontrollera minst:

- om `gneu-content-watch` finns, är enabled eller paused och har rätt workdir;
- schema, version, pending-state, felräknare och senaste lyckade source-gate-
  cykel;
- att installerade gate- och auth-scripts har samma hash som betrodd `main`;
- auth-helperns `status`, inte privata filer;
- förekomst, ägare och mode för secret directory/private key utan att läsa
  innehåll;
- att source gate-status inte skapar runtime-token eller legacy-tokenfil;
- att eventuell legacy-token och metadata tas bort genom separat pausad
  recovery-cleanup före aktivering;
- att ingen persistent PAT, token-URL eller gemensam credential store används.

Skriv aldrig ut `.env`, private keys, App JWT, installation-token,
Git credentials eller andra profilers authfiler.

### Profilsäker Adam-auth-status

Adam-auth får aldrig bedömas med Admin-profilens `HERMES_HOME`, default
`HERMES_HOME` eller utan explicit `HERMES_HOME`. Endast
`HERMES_HOME=/root/.hermes/profiles/gneu` är giltig profilkontext för Adams
auth-helper. Status ska hämtas utan mint med exakt den installerade, betrodda
runtime-helpern:

```bash
HERMES_HOME=/root/.hermes/profiles/gneu \
/usr/bin/python3 -I \
/root/.hermes/profiles/gneu/scripts/gneu-content-adam-auth.py status
```

Ett `auth_required`, `configured=false`, saknat App ID eller saknad private key
från någon invocation utan exakt ovanstående `HERMES_HOME` är **OGILTIG
EVIDENS**. Sådan evidens får inte användas för att pausa
`gneu-content-watch`, rotera eller reprovisionera credentials, deklarera
credential-loss, starta recovery eller på annat sätt ändra Adams runtime-state.

En automatisk fail-closed-paus av Adam på auth-grund får ske endast efter att
den exakta profilspecifika statuskontrollen ovan själv har gett ett non-ready
resultat. Före pausen ska Admin kunna dokumentera:

- att exakt `HERMES_HOME=/root/.hermes/profiles/gneu` användes;
- helper-pathen
  `/root/.hermes/profiles/gneu/scripts/gneu-content-adam-auth.py`;
- status `ready`, `auth_required` eller `error`;
- `configured` som `true` eller `false`;
- App ID- och private-key-förekomst samt valideringsstatus endast som boolean
  eller annan icke-hemlig metadata.

Dokumentationen får aldrig exponera credentials. Admin får aldrig läsa
private-key-innehåll, skriva ut App ID- eller private-key-värden när de inte
behövs, använda eller kopiera Adams credential, minta Adams token manuellt
eller använda Adams GitHub-identitet för Admin-operationer.

Den befintliga fail-closed-principen gäller fortsatt: en verifierad non-ready
status från den exakta kontrollen får pausa Adam. Ett tekniskt fel i själva den
profilspecifika kontrollen ska också behandlas fail-closed som `error`, men är
inte bevisad credential-loss och får inte rapporteras som sådan när kontrollen
är ofullständig.

## GitHub-policy review

Live GitHub-state ligger utanför Git och ska kontrolleras separat när wrapperns
policy tillåter det.

Verifiera:

### Repository

- default branch är `main`;
- `main` och `published` finns;
- direktpush till skyddade brancher är blockerad;
- force-push och deletion är blockerade där det krävs.

### `published`

- PR krävs;
- required checks är exakt `validate` och `publisher-policy`;
- branch måste vara up to date;
- inga Adam- eller Publisher-bypass actors finns;
- Publisher använder aldrig `--admin`.

### GitHub Apps

- Adam App, Admin App och Publisher App är olika Apps;
- varje App är installerad endast där den behövs;
- privata nycklar delas inte;
- permissions motsvarar minsta avsedda scope;
- Adam kan inte använda Admin- eller Publisher-wrappern;
- Publisher-token mintas först efter trusted gate.

### Actions

- workflows kör från avsedd betrodd branch;
- PR-head exekveras inte som Publisher Gate-kod;
- `validate` gäller exakt aktuell head;
- `publisher-policy` kommer från trusted `main`, gäller exakt aktuell head och
  har endast read-behörigheter;
- senaste dry-run och relevanta checks är verifierade;
- `AUTOPUBLISH_ENABLED` har avsedd state.

Om admin-wrappern blockerar en read-operation ska Admin rapportera kontrollen
som `UNVERIFIED`. Wrappern får inte kringgås med andra credentials.

## Recovery

### Förlust av sessionshistorik

Sessionshistorik får återskapas genom dokumenten, inte genom gissning.

1. läs `OPERATING_MODEL.md` och rollspecifik playbook;
2. hämta aktuell remote-state;
3. inventera runtime-state separat;
4. anta inte att tidigare TODO, ack eller PR-resultat fortfarande gäller;
5. återuppta endast från verifierbar Git-, GitHub- och runtime-state.

### Ny Adam-profil eller förlorad Hermes-state

1. skapa eller verifiera en avgränsad Adam-profil;
2. säkerställ att workdir är separat och pekar på rätt repository;
3. installera source gate, auth-helper, credential-adapter, SOUL och jobbprompt
   från aktuell
   betrodd `main` enligt
   [`adam-credential-adapter-9.9.3.md`](adam-credential-adapter-9.9.3.md) och
   [`../runtime/adam/README.md`](../runtime/adam/README.md);
4. verifiera script-hashes;
5. provisionera Adams separata GitHub App-secrets utan att exponera dem efter
   merge och uttryckligt godkännande;
6. verifiera App-installationen, minsta permissions, owner-only mode och ägare;
7. verifiera den godkända ephemeral credential-adaptern, dess negativa och live
   tester
   och att runtimekopians hash motsvarar exakt betrodd `origin/main`;
8. dokumentera adapterns absoluta path och exakta
   `/usr/bin/python3 -I <adapter> -- ...`-invocation i jobbkonfigurationen;
   auth-helpern får aldrig anropas direkt för mint och legacy-tokenfilen är
   inte en tillåten Git/PR-integration;
9. återskapa cronjobbet från den normativa Adam-playbooken och se till att en
   tom session instrueras att läsa kontrollfiler från aktuell `origin/main`;
10. koppla endast `grounded-citations` till jobbet; ta bort generell
   `github-auth`, `github-pr-workflow` och andra GitHub-authfallbacks;
11. verifiera `published` ruleset, App-bypass samt required checks `validate`
    och `publisher-policy` live på aktuell head;
12. bootstrapa source-state avsiktligt och verifiera full cold-start-cykel;
13. kör Publisher `workflow_dispatch` med `dry_run=true` och verifiera att ingen
    merge skedde;
14. genomför en full researchcykel och ack först efter framgång;
15. aktivera schemat sist.

#### Blockerare före aktivering

- 9.9.3-PR:n ska vara mergad och installationen ska komma från exakt verifierad
  mergecommit på `origin/main`;
- installerade runtimefiler, SOUL, cronprompt och skills ska motsvara den
  mergecommiten och deras hashes och fulla jobbkontrakt ska vara verifierade;
- Adams App-secrets, App-installation, minsta permissions och owner-only
  filskydd ska vara verifierade;
- live negativa adaptertester och cleanup ska passera utan persistent token;
- `published` ruleset, App-bypass samt required checks `validate` och
  `publisher-policy` ska vara live-verifierade;
- source-state/bootstrap och full cold-start ska vara verifierade;
- Publisher dry-run ska passera utan merge;
- cron ska förbli pausat tills samtliga punkter ovan passerat och aktiveras sist.

#### Accepterade kvarvarande risker

- Nuvarande same-UID/root-/proc-modell kan inte hindra en komprometterad
  Adamprocess med private-key-access från att implementera egen App-signering.
  Risken är uttryckligen accepterad för första kontrollerade aktiveringen och är
  inte en installations-, secretprovisionerings- eller aktiveringsblockerare.
- `--ack` är policybegränsat men ännu inte kryptografiskt eller cycle-bound.
  Risken är uttryckligen accepterad för första kontrollerade aktiveringen och är
  inte en aktiveringsblockerare.

#### Framtida hardening

- separera Adam till egen Linux-identitet/process/container och flytta
  signering/mint till en privilegieseparerad broker;
- bind ack till verifierbart cycle-id, remote-resultat och trusted success-proof.

### Förlorad source-state

Förlorad source-state ska behandlas som cold start, inte som bevis på
oförändrade källor.

- Första pollningen får skapa baseline tyst.
- Malformed, osäker eller symlinkad befintlig state är inte "förlorad" state:
  gate ska väcka med `state_corrupt`, bevara beviset och kräva administrativ
  recovery; den får inte tyst skapa nya baselines ovanpå felet.
- En full safety sweep ska genomföras innan driften betraktas som återställd.
- `last_agent_success_at` ska inte sättas utan en verkligt framgångsrik cykel.
- Pending får inte promoveras genom manuellt ack utan verifierad cykel.

### Auth-recovery

- Rotera inte privata nycklar utan uttryckligt godkännande.
- Kontrollera först App-installation, App ID, filpermissions, systemtid,
  repositoryscope och GitHub API-fel.
- Source gate-status får aldrig minta, nätverksverifiera eller skriva token.
- En gammal tokenfil ska städas medan jobbet är pausat före adapterverifiering.
- Mint ska ske endast i adaptern efter godkänd command policy och aldrig logga
  token.
- Om revoke misslyckas ska lokal token ändå bort, cleanup returnera nonzero och
  aktivering blockeras tills revocation eller säker expiry verifierats.
- Adam-jobbet ska förbli pausat tills `status`, mint, tillåten operation och
  cleanup har verifierats säkert.

### Publisher-recovery

1. håll `AUTOPUBLISH_ENABLED` av;
2. verifiera trusted `main` och gate-tester;
3. verifiera ruleset och båda required checks live;
4. verifiera Publisher App-installation och permissions;
5. kör `workflow_dispatch` med `dry_run=true`;
6. kontrollera att ingen token mintades och ingen merge skedde;
7. aktivera först efter uttryckligt beslut;
8. verifiera första riktiga merge och produktionskonsumtion.

## Change workflow

Vid kod- eller dokumentändring:

1. kontrollera arbetskatalog och status;
2. `gneu-admin-github exec -- git fetch origin`;
3. skapa ny `admin/<beskrivning>` direkt från aktuell `origin/main`;
4. gör minsta nödvändiga ändring;
5. kör relevanta tester och kontroller;
6. granska `git diff --check`, `git diff --stat` och full diff;
7. verifiera att inga secrets eller oavsiktliga filer ingår;
8. commit lokalt med sakligt meddelande;
9. pusha endast med `gneu-admin-github`;
10. skapa PR `admin/* -> main` med `gneu-admin-github`;
11. läs PR-status med wrappern;
12. rapportera branch, commit, tester och PR;
13. mergea aldrig.

Auth-, validator-, workflow-, ruleset- och Publisher Gate-ändringar är
säkerhetsrelevanta och kräver uttryckligt godkännande. De får inte smygas in i
en content- eller dokumentationsändring.

### Admin GitHub App-broker

Den versionshanterade brokern, Admin-wrappern och den deterministiska
installations- och hashverifieringsproceduren finns i
[`runtime/admin/README.md`](../runtime/admin/README.md). Runtimekopiorna får
endast installeras efter merge från exakt verifierad `origin/main` och får
aldrig handredigeras.

## Incidenter

Behandla minst följande som tekniska säkerhetsincidenter eller driftincidenter:

- secret eller token i output, Git eller sessionshistorik;
- oväntad privileged access eller bypass;
- direktpush till `main` eller `published`;
- Publisher-merge utan full trusted gate;
- Adam som mergear eller använder fel identitet;
- token som ligger kvar efter avsedd cleanup;
- modifierad gate/validator i runtime som inte matchar `main`;
- source-state som korrumperats eller ackats utan framgångsrik cykel;
- required check eller ruleset som saknas;
- scheduler som tyst slutat köra;
- produktion som aktiverat payload utan validering.

Vid incident:

1. stoppa ytterligare automatiska sidoeffekter när det kan göras säkert;
2. bevara evidens och radera inte loggar;
3. exponera inte hemligheten i rapporten;
4. avgränsa identitet, repository, branch och tidsperiod;
5. begär uttryckligt godkännande före rotation eller destruktiv åtgärd;
6. verifiera återställning innan automation återaktiveras.

## Evidens och rapportering

En teknisk rapport ska skilja mellan `VERIFIED`, `UNVERIFIED`, `BLOCKED` och
`NOT APPLICABLE`.

Rapportera där relevant:

- hämtad `origin/main` SHA;
- arbetsbranch och commit;
- exakt ändrade filer;
- test- och kontrollkommandon med resultat;
- script-hashes;
- cron enabled/paused och senaste status;
- auth configured/token-present utan värden;
- source-state version, pending och senaste framgång;
- ruleset/required-check/App-status;
- dry-run eller Actions-status;
- PR URL;
- kvarstående blockerare och vem som äger beslutet.

Påstå aldrig att drift, merge eller produktion är verifierad utan direkt
teknisk evidens.
