# GNEU Förvaltare Playbook

Detta dokument är den auktoritativa redaktionella policyn för GNEU. Det ägs av
GNEU Förvaltare. Teknisk arkitektur ägs av
[`OPERATING_MODEL.md`](OPERATING_MODEL.md), och Adams konkreta körsteg finns i
[`ADAM_PLAYBOOK.md`](ADAM_PLAYBOOK.md).

## Redaktionellt syfte

GNEU är en källbunden och handlingsorienterad säkerhetsbevakning som omvandlar
verifierade primärkällor till korta, begripliga och relevanta händelser om
cybersäkerhet och AI-säkerhet.

Varje publicering ska hjälpa läsaren förstå, i den mån källorna medger:

- vad som har hänt;
- vad som är nytt;
- vilka som berörs;
- säkerhetskonsekvensen;
- eventuell konkret åtgärd eller tidsfrist;
- källäget och relevant osäkerhet.

## Vad GNEU inte är

GNEU ska inte vara:

- en allmän tekniknyhetstjänst;
- en spegling av alla feeds;
- leverantörsmarknadsföring;
- ett spekulationsflöde;
- en offensiv säkerhetshandbok;
- en automatisk hotnivåmotor.

Nyhet, popularitet eller feedförekomst är inte tillräckligt för publicering.

## Bevakningsområden

### Cybersäkerhet

Bevakningen omfattar bland annat:

- aktivt exploaterade sårbarheter och zero-days;
- materiellt relevanta produkt- och tjänstesårbarheter;
- supply-chain-angrepp;
- större incidenter;
- identitet, cloud, nätverk, endpoint och e-post;
- OT/ICS när konsekvensen är relevant för målgruppen;
- ransomware när uppgifterna är verifierade och materiella;
- varningar från CERT och myndigheter;
- säkerhetsrelevanta hotkampanjer;
- materiella ändringar i exploateringsstatus, patchstatus och tidsfrister.

### AI-säkerhet

AI-säkerhet är ett självständigt bevakningsområde, inte en underkategori för
allmänna AI-nyheter. Det omfattar bland annat:

- LLM- och agentsäkerhet;
- tool use och behörighetsgränser;
- prompt injection;
- RAG, minne och externa datakopplingar;
- model poisoning och data poisoning;
- AI supply chain;
- säkerhet i modeller, checkpoints, paket och inferensplattformar;
- sårbarheter i AI-tjänster och modellservrar;
- informationsläckage och tenant-isolering;
- konkret verifierat AI-missbruk i cyberangrepp;
- praktiskt relevant säkerhetsforskning;
- större AI-säkerhetsincidenter;
- myndighetsvarningar;
- proveniens och attestering;
- incidentrespons och forensik för AI-system.

Följande ska inte publiceras utan en direkt och materiell säkerhetskonsekvens:

- generella AI-produktlanseringar;
- benchmarkresultat;
- affärer och finansiering;
- upphovsrättsfrågor;
- allmän AI-policy.

## Redaktionell livscykel

```text
SIGNAL
  -> KANDIDAT
  -> AVFÄRDAD
  eller
  -> PUBLICERINGSBAR
  -> PR
  -> PUBLICERAD
  -> eventuell UPPDATERING eller RÄTTELSE
```

### Signal

En signal är en indikation på att något kan ha ändrats. Exempel är en ändrad
feed, en ny advisory, ett ändrat dokument eller en notifiering.

En ändrad feed är bara en signal. Den ska aldrig automatiskt bli ett event.

### Kandidat

En kandidat har identifierbar säkerhetsrelevans och tillräcklig substans för
research. Innan den blir publiceringsbar ska researchen fastställa:

- exakt primärkälla;
- vad som faktiskt är nytt;
- berörda produkter, tjänster, system eller målgrupper;
- verifierad säkerhetskonsekvens;
- patch, mitigation eller deadline när sådan uttryckligen finns;
- datum, revisionsdatum och aktualitet;
- om GNEU redan täcker samma sak;
- kvarstående osäkerhet eller motstridiga uppgifter;
- om innehållet är class A eller class B.

### Avfärdad

En kandidat ska avfärdas när den exempelvis:

- saknar materiell säkerhetskonsekvens;
- bara upprepar redan publicerad information;
- inte kan verifieras mot tillräcklig källa;
- är spekulativ eller marknadsföringsdriven;
- är för generell för GNEU:s syfte;
- gäller AI utan direkt säkerhetskonsekvens;
- främst skulle ge offensiva instruktioner;
- inte tillför en materiell uppdatering till ett befintligt event.

`NO_CHANGE` är ett fullvärdigt och önskvärt resultat när inget material når
publiceringsnivå.

### Publiceringsbar

En kandidat är publiceringsbar först när:

- den ligger inom GNEU:s scope;
- nyheten eller ändringen är tydligt identifierad;
- centrala sakpåståenden är källstödda;
- titel, summary och action inte går längre än evidensen;
- datum och länkar är verifierade;
- dubblettkontroll är gjord;
- osäkerhet är synlig;
- class A/B är korrekt;
- repositoryts validator kan godkänna den strukturerade representationen.

Validatorpassning är nödvändig men inte tillräcklig för redaktionell kvalitet.

## Källpolicy

### Primärkällor först

Använd i första hand den aktör som ansvarar för uppgiften eller systemet:

- leverantörens exakta advisory;
- officiell myndighets- eller CERT-varning;
- officiellt säkerhetsbulletin eller incidentmeddelande;
- maintainer- eller projektadvisory;
- publicerad originalforskning när forskningen är själva händelsen.

Länka till exakt advisory eller dokument, inte en generell startsida när en
mer precis URL finns.

### Aggregatorer och sekundärkällor

Aggregatorer och sekundärkällor får normalt användas för discovery och som
signal. De ska inte ersätta en tillgänglig primärkälla. En sekundärkälla får
bara bära ett publicerat sakpåstående när det är redaktionellt motiverat,
osäkerheten framgår och repositoryts tillåtna källmodell medger det.

### Stöd för påståenden

Varje publicerat sakpåstående ska stödjas av angivna källor. Kontrollera särskilt:

- berörd produkt och version;
- exploateringsstatus;
- CVE och severity;
- patch- eller mitigationstatus;
- incidentomfattning;
- datum och tidsfrister;
- tillskrivning och påstådd angripare;
- AI-specifika påståenden om modeller, data, tool use eller tenantpåverkan.

Marknadsföringsspråk ska neutraliseras. Motstridiga uppgifter får inte döljas.
Osäkerhet ska uttryckas utan att fyllas ut med spekulation.

### Datum och aktualitet

Verifiera både ursprungligt publiceringsdatum och senaste materiella revision.
En uppdaterad sidtimestamp är inte ensam bevis för en materiell ändring. Använd
inte gamla advisories som nya händelser utan en tydligt identifierad nyhet.

## Class A

Class A är direkt källextraktion eller en trogen sammanfattning.

Class A får inte innehålla:

- egen slutsats;
- egen riskprioritering;
- egen betydelseförklaring;
- egen målgruppsanpassad rekommendation.

`summary` och `action` får finnas när innehållet uttryckligen stöds av
primärkällan. `action` får till exempel återge leverantörens eller myndighetens
uttryckliga mitigation, patchinstruktion eller deadline.

Endast class A med `confidence: verified` kan vara eligible för autonom
Publisher Gate. Eligibility är inte samma sak som ett redaktionellt krav att
publicera.

## Class B

Class B är redaktionell syntes och omfattar en eller flera av:

- sammanvägning av flera uppgifter;
- egen betydelseförklaring;
- målgruppsanpassad rekommendation;
- relevans- eller konsekvensbedömning;
- hantering av motstridiga eller osäkra uppgifter.

Adam får researcha och skriva class B-förslag. Class B får aldrig
autopubliceras. Den kräver mänsklig redaktionell bedömning och hantering.

En text blir inte class A bara för att varje enskilt fakta har en källa. Om
GNEU själv drar slutsatsen om betydelse, prioritet eller målgruppsåtgärd är den
class B.

## Relevansbedömning

Bedöm relevans utifrån den verifierade säkerhetskonsekvensen, inte enbart CVSS,
leverantörens rubrik eller social uppmärksamhet. Relevans kan bland annat
påverkas av:

- aktiv exploatering;
- spridning och exponering;
- sannolik påverkan på svenska eller nordiska organisationer;
- identitets-, data- eller systempåverkan;
- tillgänglig patch eller konkret mitigation;
- deadline eller omedelbar incidentrisk;
- om förändringen väsentligt ändrar tidigare råd;
- om AI-systemets behörigheter eller integrationer förstärker konsekvensen.

Relevansbedömning som uttrycks i själva eventet gör normalt eventet till class B.

## Kvalitetskrav

Ett event ska vara:

- korrekt och källbundet;
- kort utan att tappa avgörande villkor;
- begripligt för en tekniskt ansvarig läsare;
- neutralt och fritt från rädslo- eller marknadsföringsspråk;
- tydligt om vad som är nytt;
- tydligt om osäkerhet;
- handlingsorienterat endast i den mån class och källstöd medger;
- fritt från exekverbart innehåll, credentials och personliga e-postadresser.

Titel, summary och action ska följa validatorns aktuella längd- och
formatgränser.

## Dubbletter

Kontrollera dubbletter mot både event-id och händelsens semantiska innehåll.
Två källor om samma CVE, incident eller kampanj är inte automatiskt två events.

Skapa inte ett nytt event när en ny signal bara:

- återger samma sak med annan rubrik;
- tillför en sekundärkälla utan materiell ny uppgift;
- ändrar oväsentlig metadata;
- upprepar en redan publicerad mitigation.

En materiell ändring kan däremot motivera uppdatering eller ett nytt event när
den redaktionella relationen tydligt framgår och modellen medger det.

## Uppdateringar och rättelser

### Uppdatering

En uppdatering används när tidigare innehåll var korrekt men källäget har
ändrats materiellt, exempelvis:

- exploateringsstatus har ändrats;
- patch eller mitigation har tillkommit;
- deadline har ändrats;
- incidentens verifierade omfattning har förändrats;
- relevant ny primärkälla har löst tidigare osäkerhet.

Ändring av ett redan publicerat event är inte eligible för autonom Publisher
Gate och kräver mänsklig hantering.

### Rättelse

En rättelse krävs när publicerat innehåll är felaktigt eller missvisande.
Rättelsen ska:

- prioritera korrekt sakuppgift framför kosmetisk kontinuitet;
- identifiera vad som var fel;
- stödjas av primärkälla;
- inte döljas genom att bara skapa ett orelaterat nytt event;
- hanteras av Förvaltaren med tekniskt stöd från Admin när schema eller
  publiceringsmekanik berörs.

## Eskalering

Adam ska eskalera till Förvaltaren när:

- class A/B är osäker;
- relevansen kräver redaktionell bedömning;
- källor motsäger varandra;
- en rättelse eller mutation av publicerat event krävs;
- flera events behöver samordnas;
- osäkerheten inte kan uttryckas säkert i nuvarande schema;
- en källa är viktig men inte tillåten av validatorn;
- AI-säkerhetsfrågan riskerar att bli allmän policy eller produktnyhet.

Förvaltaren ska eskalera till Admin när:

- schema eller validator hindrar en beslutad redaktionell modell;
- source gate behöver ny teknisk källa eller signal;
- auth, workflow, branchskydd eller Publisher Gate berörs;
- en teknisk säkerhetsinvariant behöver ändras.

Förvaltaren får besluta vad GNEU ska säga. Admin beslutar hur den tekniska
plattformen säkert kan representera och publicera det.
