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
- required check är exakt `validate`;
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
5. verifiera först att Adam kör under en avgränsad OS-identitet utan direkt
   private-key-access och att privilegieseparerad policybroker är enda mintväg;
   same-UID/root är fail-closed blockerare;
6. provisionera Adam App-secrets utan att exponera dem först när OS-gränsen är
   stängd och separat godkänd;
7. verifiera owner-only mode och ägare;
8. verifiera den godkända ephemeral credential-adaptern, dess negativa tester
   och att runtimekopians hash motsvarar exakt betrodd `origin/main`;
9. dokumentera adapterns absoluta path och exakta
   `/usr/bin/python3 -I <adapter> -- ...`-invocation i jobbkonfigurationen;
   auth-helpern får aldrig anropas direkt för mint och legacy-tokenfilen är
   inte en tillåten Git/PR-integration;
10. återskapa cronjobbet från den normativa Adam-playbooken och se till att en
   tom session instrueras att läsa kontrollfiler från aktuell `origin/main`;
11. koppla endast `grounded-citations` till jobbet; ta bort generell
   `github-auth`, `github-pr-workflow` och andra GitHub-authfallbacks;
12. bootstrapa source-state avsiktligt;
13. genomför en full researchcykel och ack först efter framgång;
14. aktivera schemat sist.

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
3. verifiera ruleset och required checks live;
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
