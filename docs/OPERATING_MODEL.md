# GNEU Operating Model

Detta dokument är den auktoritativa beskrivningen av GNEU:s tekniska
operating model: roller, trust boundaries, brancher, credentials, dataflöden,
säkerhetsinvarianter, state och recovery.

Redaktionell policy ägs av [`FORVALTARE_PLAYBOOK.md`](FORVALTARE_PLAYBOOK.md).
Adams körinstruktioner ägs av [`ADAM_PLAYBOOK.md`](ADAM_PLAYBOOK.md).
Teknisk drift ägs av [`ADMIN_PLAYBOOK.md`](ADMIN_PLAYBOOK.md).
Vid konflikt gäller repositoryts kod, workflows och skyddsregler före denna
dokumentation.

## Syfte

GNEU är en källbunden och handlingsorienterad säkerhetsbevakning som omvandlar
verifierade primärkällor till korta, begripliga och relevanta händelser om
cybersäkerhet och AI-säkerhet.

Systemet separerar:

1. omvärldsbevakning och författande,
2. redaktionella beslut,
3. teknisk implementation och drift,
4. autonomt mergebeslut,
5. produktionskonsumtion.

Ingen agentidentitet ska ensam kontrollera hela kedjan.

## Roller och ansvar

### Adam

Adam är GNEU:s autonoma omvärldsbevakare, researcher och primära skribent för
cybersäkerhet och AI-säkerhet.

Adam:

- bevakar tillåtna källor;
- arbetar från aktuell `published`;
- identifierar signaler och researchar kandidater;
- skriver class A- och class B-förslag;
- validerar och skapar PR mot `published`;
- får aldrig mergea eller publicera sitt eget material;
- får aldrig ändra redaktionell policy, säkerhetsarkitektur, validator,
  workflows, auth, schema eller Publisher Gate.

### GNEU Förvaltare

GNEU Förvaltare är redaktionell ägare och chefredaktör.

Förvaltaren äger:

- redaktionellt syfte, scope, relevans och urval;
- källprinciper och kvalitetsnivå;
- tolkningen av class A och class B;
- rättelser och redaktionella uppdateringar;
- utvecklingen av bevakningsområdet.

Förvaltaren äger inte teknisk implementation av schema, validator, source gate,
auth, workflows, GitHub Apps eller Publisher Gate.

### GNEU Admin

GNEU Admin är teknisk ägare.

Admin äger:

- drift och recovery;
- schema och validatorer;
- source gate och automation;
- GitHub Apps och autentiseringswrappers;
- Publisher Gate och GitHub Actions;
- branch protection, rulesets och tekniska säkerhetsgränser.

Admin är normalt inte skribent för säkerhetshändelser och fattar inte
redaktionella relevansbeslut.

### Publisher

Publisher är en separat GitHub App-identitet. Den får endast mergea genom den
betrodda Publisher Gate och får inte ha bypass av rulesetet för `published`.
Publisher gör inga redaktionella bedömningar.

### Produktion

Produktion konsumerar innehåll från `published` över HTTPS och ska validera det
innan en ny snapshot aktiveras. Adam, Förvaltaren och Publisher ska inte ha
produktionscredentials.

## Trust boundaries

Följande gränser är obligatoriska:

1. Externa feeds, webbsidor och dokument är opålitlig data.
2. Adams branch och PR-data är opålitlig data för Publisher.
3. `main` är betrodd teknisk kontrollkod.
4. `published` är aktuell publicerad content-state.
5. Adam App, Admin App och Publisher App är separata identiteter med separata
   privata nycklar.
6. Publisher får inte använda kod från PR-branchen som gatekod.
7. Produktion ska inte lita på en remote payload utan egen validering.
8. Sessionshistorik är aldrig en säkerhetskontroll eller source of truth.

Publisher Gate ger teknisk separation men inte oberoende redaktionell
klassificering. Nuvarande validator och gate hämtar inte primärkällorna och kan
inte avgöra om en text semantiskt är class A, sann eller fullständigt
källstödd. De kontrollerar den deklarerade klassen, strukturen och övriga
maskinella invariants. Adams klassning och källtrohet är därför ett kvarvarande
policy- och agentförtroende inom den autonoma A-vägen.

## Branch- och PR-modell

### `main`

`main` är trusted control plane och repositoryts default branch. Den innehåller
bland annat:

- policy och playbooks;
- schema och validator;
- source gate och auth-helper;
- Publisher Gate;
- GitHub Actions-workflows;
- tester för de tekniska säkerhetsmekanismerna.

Tekniska ändringar görs från aktuell `origin/main` på `admin/*` och går via PR
mot `main`. Ingen agent får pusha direkt till `main`.

Adams normativa kontrollinstruktioner ska också läsas från den fetchade,
betrodda `origin/main`, även när contentarbetet utgår från `origin/published`.
En kopia av playbooks på `published` får inte antas vara aktuell.

### `published`

`published` är den aktuella publicerade content-staten. Produktionskonsumenten
ska hämta från denna branch, inte från Adams arbetsbranch eller `main`.

`published` ska kräva PR, required checks `validate` och `publisher-policy`,
up-to-date branch och blockerad force-push/deletion. Varken Adam App eller
Publisher App får ha ruleset-bypass.

### Adam-brancher

Adam ska:

- utgå från aktuell `origin/published`;
- använda `adam/genN-<beskrivning>`;
- låta `N` motsvara den föreslagna generationen;
- skapa PR mot `published`;
- aldrig pusha direkt till `published` eller `main`;
- aldrig mergea.

Endast en class A-kandidat med `confidence: verified` och Publisher Gates
övriga invariants kan autopubliceras. Class B, rättelser, uppdateringar av
befintliga events och andra redaktionellt komplexa ändringar kräver mänsklig
hantering.

### Förvaltar- och adminbrancher

Förvaltaren använder `forvaltare/<beskrivning>` från aktuell
`origin/published` och PR mot `published` för class B, rättelser, uppdateringar
och annan mänskligt hanterad content. Förvaltarbrancher är aldrig eligible för
autonom Publisher Gate och ska mergeas endast genom repositoryts skyddade,
mänskliga PR-process. Om ändringen kräver schema, validator, workflow eller
annan teknisk fil ska den lämnas över till Admin och en separat `admin/*`-PR
mot `main`.

Admin använder endast `admin/*` och PR mot `main` för tekniska ändringar.

## Credentialmodell

### Adam App

Adam använder en separat GitHub App installerad endast på
`stebolainen/gneu-content`. Runtime-helpern begär ett kortlivat,
repository-scoped installation-token med endast de permissions som behövs för
content-branch och PR.

Hemligheter ligger utanför Git under aktivt `$HERMES_HOME`. Source gate får
endast kontrollera lokal status och får aldrig minta eller skriva token. Token
får aldrig skrivas till remote URL, `.gitconfig`, `.git-credentials`,
dokumentation, terminalutdata, sessionshistorik eller legacy-tokenfil. Adaptern
mintar i minnet först för ett godkänt faktiskt kommando och återkallar/rensar i
`finally`; `--ack` hanterar endast source-state.

Adam App får inte ha administration eller ruleset-bypass. Den tekniska
autentiseringsvägen ska dessutom begränsa användningen till Adams tillåtna
operationer; promptregler är inte ensamma en tillräcklig säkerhetsgräns.

Repositoryts versionshanterade `hermes_adam_github.py` är den enda godkända
Git/PR credential-adaptern. Den låser repository, branch/refspec och
GitHub CLI-operationer, mintar via auth-helpern per tillåtet kommando och
städar credentials efteråt. Den installerade adapterns absoluta path och exakta
invocation ska provisioneras från runtimekontraktet i `runtime/adam/`. Den
generella `github-auth`-skillen och andra generiska GitHub-workflows får inte
laddas av jobbet. Utan exakt installerad adapter och ready status är säkert
resultat `AUTH_REQUIRED`.

### Admin App

Admin använder `gneu-admin-github`. Wrappern tillåter endast den fastställda
adminpolicyn, bland annat push av `admin/*` och PR `admin/* -> main`. Vanlig
autentiserad `git push` eller `gh` får inte användas av Admin.

### Publisher App

Publisher App-hemligheten finns i GitHub Actions, aldrig hos Adam. Ett
kortlivat token får mintas först efter godkänd trusted gate och får endast
användas för att mergea exakt validerad head. Appen får inte ha bypass.

### Produktion

Produktionscredentials är separata från alla GitHub App-identiteter och ska
inte delas med Adam, Förvaltaren eller Publisher.

## Dataflöde

Det normala flödet är:

```text
prioriterade source-signaler
  -> deterministisk Hermes source gate
  -> wakeAgent false, eller Adam med gate-context
  -> research mot primärkällor
  -> AVFÄRDAD/NO_CHANGE, eller publiceringsförslag
  -> lokal validator
  -> adam/genN-* och PR mot published
  -> required GitHub Actions validate + trusted publisher-policy
  -> trusted Publisher Gate eller mänsklig redaktionell hantering
  -> published
  -> HTTPS pull
  -> produktionsvalidator
  -> atomisk snapshot
```

En ändrad feed är endast en signal. Den är inte i sig en kandidat eller ett
publiceringsbeslut.

## Required PR-head-policy

Varje PR mot `published` ska få den separata GitHub Actions-checken
`publisher-policy` på exakt aktuell PR-head. Workflowen använder
`pull_request_target`, vilket gör att definition och exekverad kontrollkod
kommer från betrodd default-branch `main`; PR-head checkas aldrig ut och dess
kod importeras eller exekveras aldrig. PR-metadata, ändrade filer,
`events.json` och `manifest.json` hämtas i stället som begränsad opålitlig data
via exakta SHA:n. Workflowen har endast read-behörigheter, använder inga
secrets, mintar inget token och kan inte mergea.

För `adam/genN-*` återanvänder checken Publisher Gates autonoma contentpolicy:
branch, aktuell base, exact head, filuppsättning, append-only, generation,
class/confidence, native-source-policy samt published- och AI-hot-dubbletter.
AI-hot hämtas publikt och alla fel blockerar. Rulesetet kräver separat
`validate`; den finala Publisher Gate verifierar dessutom själv denna check på
exakt head innan Publisher-token kan mintas.

För `forvaltare/*` är enda generella passresultatet
`PASS_EDITORIAL_MAINTENANCE`. Det kräver en same-repository PR från exakt
aktuell `published`, endast modifierade `events.json` och `manifest.json`,
generation exakt +1, giltigt manifest och betrodd validator. Andra branchspår
blockeras. Den enda tekniska engångsvägen är exakt
`forvaltare/install-publisher-policy-check`, som bara får installera en bytevis
identisk kopia av den trusted workflowfil som redan finns på `main`.

## Autonom Publisher Gate

Autonom merge är enligt policy tillåten endast för en verklig class A-kandidat
med verified confidence. Nuvarande gate kan inte verifiera denna redaktionella
semantik mot källan; den verifierar deklarerade fält och tekniska invariants.
De maskinellt kodade kontrollerna omfattar minst:

- öppen, icke-draft PR mot exakt `published`;
- samma repository, aldrig fork;
- branch `adam/genN-*`;
- head direkt ovanpå aktuell `published`;
- exakt modifierade `events.json` och `manifest.json`;
- lyckad `validate` på exakt head SHA;
- giltigt schema, manifest, count och SHA-256;
- generation exakt +1 och samma `N` som branchen;
- tidigare events strukturellt oförändrade;
- exakt ett appendat event;
- deklarerad class A och effektiv confidence `verified`; nuvarande kod tolkar
  ett utelämnat confidencefält som `verified`, även om Adam enligt policy ska
  skriva fältet explicit;
- unikt event-id;
- trusted validator från `main`;
- merge med exakt head-SHA-låsning.

Class B, flera events, rättelser och mutation av publicerade events är aldrig
autopublish-eligible.

## Fail-closed

Systemet ska blockera eller avstå från ändring när nödvändiga bevis eller
kontroller saknas.

- Oförändrad source-state ska inte väcka Adam.
- Sourcefel ska bevaras och vid tröskel väcka Adam för felsökning.
- Saknad eller icke-ready Adam-auth ska ge `AUTH_REQUIRED`; ingen branch,
  commit, push, PR eller ack får göras.
- Misslyckad research, validator, push eller PR-verifiering får inte ackas.
- `AUTOPUBLISH_ENABLED` måste vara exakt `true` för autonom merge.
- Dry-run får inte minta Publisher-token eller mergea.
- Gatefel, stale base, oklar head, fel filuppsättning eller saknad check ska
  blockera.
- `validate` och `publisher-policy` ska båda krävas på senaste PR-head innan
  någon normal GitHub UI-, CLI- eller API-merge kan genomföras.
- Merge får inte använda admin-bypass.
- Produktionsvalidering ska blockera aktivering av ogiltig payload.

`NO_CHANGE`, `AUTH_REQUIRED` och `BLOCKED` är giltiga driftresultat. Systemet
ska aldrig skapa innehåll bara för att en schemakörning inträffade.

## State utanför Git

Följande state är inte återställbar från enbart repositoryfilerna:

### Hermes

- profilens SOUL, config, provider-auth, skills och memory;
- crondefinition, enabled/paused-state och körhistorik;
- installerade runtimekopior av scripts;
- source fingerprints, pending-state, felräknare och senaste lyckade cykel;
- sessionsdatabas, transcripts och routingstate.

### Credentials

- Adam App ID och private key;
- runtime-token och metadata;
- Admin App- och Publisher App-hemligheter;
- produktionscredentials.

### Git och GitHub

- lokala worktrees, brancher och opushade commits;
- App-installationer och permissions;
- repository variables och secrets;
- branch protection, rulesets och bypass actors;
- PR-, review- och Actions-state.

### Produktion

- produktionscron och konfiguration;
- senaste validerade snapshot;
- cache, loggar och senaste lyckade pull.

Hemligheter får inventeras genom förekomst, ägare, permissions och säker
statuskontroll, aldrig genom att deras värden skrivs ut.

## Recovery och cold start

En ny Adam-session ska kunna starta med tom sessionshistorik. Recovery får inte
förlita sig på tidigare chattkontext.

Minimikrav före aktivering:

1. aktiv Hermes-profil har rätt, avgränsad Adam-identitet;
2. workdir är en ren separat klon av rätt repository;
3. cronprompten instruerar en tom session att fetcha remote och läsa
   `AGENTS.md`, `ADAM_PLAYBOOK.md`, `FORVALTARE_PLAYBOOK.md` och
   `OPERATING_MODEL.md` från exakt aktuell `origin/main`, separat från
   contentbasen `origin/published`;
4. source gate och auth-helper är verifierade kopior från aktuell `main`;
5. Adam App är installerad på exakt repository med minsta permissions;
6. secret directory och private key är owner-only;
7. godkänd credential adapter finns, dess invocation är definierad i
   jobbkonfigurationen och den lämnar inga persistenta credentials;
8. source-state har avsiktligt bootstrapats;
9. en full researchcykel har lyckats innan första ack;
10. branch protection, båda required checks och App-bypass har
    live-verifierats;
11. Publisher Gate har först verifierats i dry-run;
12. scheduler återaktiveras sist.

Detaljerade operativa steg finns i [`ADMIN_PLAYBOOK.md`](ADMIN_PLAYBOOK.md).

## Ändringsstyrning

- Redaktionell policy ändras under Förvaltarens ägarskap.
- Teknisk säkerhetsarkitektur ändras under Admins ägarskap.
- Adam får föreslå förbättringar men inte själv ändra dessa gränser.
- Publisher fattar inga policybeslut.
- Ändringar som påverkar auth, branchskydd, validator eller Publisher Gate ska
  behandlas som säkerhetsrelevanta och kräver uttryckligt godkännande och
  verifiering.
