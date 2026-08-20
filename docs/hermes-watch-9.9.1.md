# gneu-content 9.9.1 — economical Hermes watch

> **Releasehistorik.** Detta dokument beskriver införandet av 9.9.1 och är inte
> normativ installations- eller recoveryinstruktion. Profil- och
> installationsanvisningar nedan är superseded av 9.9.2 och de aktuella
> [`OPERATING_MODEL.md`](OPERATING_MODEL.md),
> [`ADMIN_PLAYBOOK.md`](ADMIN_PLAYBOOK.md) och
> [`ADAM_PLAYBOOK.md`](ADAM_PLAYBOOK.md). Dokumentet bevaras för spårbarhet.

## Mål

Adam ska inte konsumera en full LLM-körning vid varje pollingintervall.

9.9.1 använder Hermes pre-run script + `wakeAgent`:

```
20-min cron
   ↓
deterministisk source gate (0 LLM tokens)
   ↓
oförändrat ──→ wakeAgent:false ──→ stopp
   ↓ förändring / persistent source error / 6h safety sweep
wakeAgent:true
   ↓
Adam remote-first cycle
   ↓
NO_CHANGE eller PR
   ↓
ack gate
```

## Prioriterade maskinläsbara signaler

Gate 9.9.1 kontrollerar:

- CISA KEV JSON
- CERT-SE Atom
- Microsoft MSRC Security Update Guide RSS

Dessa är endast **wake-signaler**. När Adam väcks gör han fortfarande den fulla
bevakningscykeln enligt `AGENTS.md` och får använda alla källor som validatorn tillåter.

## Säkerhet

- inga GitHub-, Loopia- eller modellcredentials används av gate-scriptet
- externa bodies exekveras aldrig
- scriptet jämför endast SHA-256 + HTTP-cachemetadata
- högst 8 MiB läses per källa
- state ligger utanför repot under Hermes privata `scripts`-katalog
- ändrad fingerprint är `pending` tills Adam uttryckligen ackar en lyckad cykel
- om Adam/provider misslyckas försvinner alltså inte förändringssignalen

## Rate limits / fel

- ETag och Last-Modified används när upstream stödjer dem
- ett enstaka nätfel väcker inte agenten
- tre konsekutiva fel för samma källa väcker agenten för felsökning
- minst var sjätte timme väcks Adam för en full safety sweep även om
  prioriterade feeds inte ändrats

## Historisk Hermes-installation (superseded)

Kopiera:

`hermes_source_gate.py`

till:

`~/.hermes/scripts/gneu-content-source-gate.py`

Hermes-jobbet `gneu-content-watch` ska därefter:
- köras `every 20m`
- ha source gate-scriptet som pre-run `script`
- fortsatt använda `/root/gneu-content` som workdir
- fortsatt leverera lokalt
- bara anropa LLM när scriptet returnerar `wakeAgent:true`

Efter en framgångsrik agentcykel ska Adam köra:

`python3 ~/.hermes/scripts/gneu-content-source-gate.py --ack`

Detta promoverar pending fingerprints så samma förändring inte väcker igen.
