# AnalizzatoreSuricata2

Tool C che converte un file PCAP e un insieme di regole Suricata in un database di pattern Hyperscan ottimizzato per il pre-filtraggio XDP/eBPF in-kernel.

---

## Indice

1. [Contesto del progetto](#1-contesto-del-progetto)
2. [Architettura](#2-architettura)
3. [Build e utilizzo](#3-build-e-utilizzo)
4. [Pipeline a 6 fasi](#4-pipeline-a-6-fasi)
5. [Formato patterns.hs](#5-formato-patternshs)
6. [Sistema di prefissi per sticky buffer](#6-sistema-di-prefissi-per-sticky-buffer)
7. [Problemi risolti](#7-problemi-risolti)
8. [Limitazioni note](#8-limitazioni-note)
9. [File di output](#9-file-di-output)

---

## 1. Contesto del progetto

Il sistema accelera Suricata IDS tramite un programma XDP che gira nel kernel Linux. La logica è la seguente:

```
Pacchetto di rete
        │
        ▼
   Programma XDP
   (xdp_prog_kern_test.c)
        │
        ├─ protocollo monitorato? (app_map)
        │         │ SÌ
        │         ▼
        │   Hyperscan scan → database "cattivi" (ID 4321)
        │         │
        │    match trovato ──→ XDP_PASS → Suricata lo analizza
        │         │
        │    nessun match ──→ bpf_redirect(0,0) → Suricata NON lo vede
        │
        └─ protocollo NON monitorato → XDP_PASS
```

**L'obiettivo di questo tool** è costruire il database "cattivi" a partire dal file delle regole Suricata. Un pattern nel database deve essere:

- **Selettivo** (pochi falsi positivi): un match deve significare "il pacchetto è probabilmente malevolo → mandalo a Suricata"
- **Corretto** (pochi falsi negativi): i pattern devono effettivamente coprire il traffico d'attacco descritto dalle regole Suricata

Se un pattern è troppo generico (corrisponde a traffico normale), il traffico legittimo viene bloccato prima di raggiungere Suricata — che non potrà quindi emettere alert per quei flussi.

---

## 2. Architettura

### Moduli C

| File | Ruolo |
|------|-------|
| `main.c` | Orchestrazione delle 6 fasi, output statistiche |
| `pcap_analyzer.c` | Lettura PCAP con libpcap, conteggio protocolli e flussi |
| `protocol_detector.c` | Classificazione protocollo applicativo per porta/DPI |
| `rules_parser.c` | Parser del formato testo Suricata `.rules` |
| `pattern_extractor.c` | Estrazione `fast_pattern`, gestione sticky buffer, prefissi |
| `hyperscan_formatter.c` | Conversione `Pattern` → riga Hyperscan (`id:/regex/flags{ext}`) |

### Strutture dati chiave

```c
/* pattern_extractor.h */
typedef struct {
    char content[MAX_CONTENT]; /* valore content: in notazione Suricata  */
    char prefix[MAX_PREFIX];   /* prefisso regex Hyperscan (già in forma regex) */
    int  nocase;               /* flag 'i' per Hyperscan                  */
    int  offset;               /* -1 = non impostato                      */
    int  depth;                /* -1 = non impostato                      */
    int  startswith;           /* genera min_offset=N,max_offset=N        */
} Pattern;
```

---

## 3. Build e utilizzo

### Requisiti

- `gcc`
- `libpcap` (`sudo apt install libpcap-dev`)

### Build

```bash
cd AnalizzatoreSuricata2
make
```

### Esecuzione

```bash
./analyzer input.pcap suricata.rules
```

Output prodotti:
- `patterns.hs` — database pattern per Hyperscan
- `filtered.rules` — regole Suricata effettivamente usate (solo accettate)
- `filtered2.rules` — regole accettate + regole con protocollo non nel traffico

### Pulizia

```bash
make clean
```

---

## 4. Pipeline a 6 fasi

### Fase 1 — Analisi PCAP

Legge il file `.pcap` con libpcap e conta i pacchetti per protocollo applicativo (identificato via porta: 80→HTTP, 443→TLS, 53→DNS, ecc.) e per flusso TCP (5-tuple).

Output a terminale:
```
[*] HTTP             72.09%
[*] TLS               8.31%
...
```

### Fase 2 — Selezione protocolli

Seleziona i protocolli che coprono ≥ 50% del traffico totale. Se un singolo protocollo supera il 50% viene usato solo quello; altrimenti si combinano i più rilevanti in ordine decrescente fino a raggiungere la soglia.

### Fase 3 — Parsing regole Suricata

Carica il file `.rules` e classifica ogni regola in una delle seguenti categorie (tramite `FilterReason`):

| Motivo scarto | Descrizione |
|---|---|
| `FILTER_STATEFUL` | Contiene `flowbits`, `threshold`, `detection_filter`, `flowint`, `limit` |
| `FILTER_PROTO_MISMATCH` | Il protocollo della regola non è nel traffico rilevato |
| `FILTER_NO_CONTENT` | Nessun keyword `content:` nella regola |
| `FILTER_MULTI_CONTENT_NO_FP` | Più `content:` ma nessun `fast_pattern` esplicito |
| `FILTER_CONTENT_EXTRACT_FAIL` | Il parsing del `fast_pattern` ha fallito |
| `FILTER_EMPTY_CONTENT` | Il contenuto estratto è vuoto |
| `FILTER_OK` | Regola accettata, pattern generato |

### Fase 4 — Estrazione pattern

Per ogni regola accettata, `extract_pattern()` in `pattern_extractor.c` esegue:

1. **Scelta del content**:
   - Se la regola ha `fast_pattern` esplicito → usa quel `content:`
   - Se ha un solo `content:` → lo usa come fast_pattern implicito (comportamento Suricata)
   - Se ha più `content:` senza `fast_pattern` → regola scartata

2. **Pulizia modificatori sticky buffer**:  
   Se prima del `content:` selezionato appare una keyword sticky buffer (vedi sezione 6), i modificatori `offset`, `depth`, `startswith` vengono azzerati perché sono relativi al campo applicativo, non al payload grezzo TCP che XDP scansiona.

3. **Fallback al content più lungo** (se il pattern è troppo corto):  
   Se il content estratto è < 6 byte decodificati (`MIN_PATTERN_BYTES`) E non ha un prefisso sticky buffer, viene cercato il content non-negato più lungo in tutta la regola e usato come sostituto (l'operazione viene contata come `upgraded`).  
   **Nota**: se il pattern ha un prefisso sticky buffer, il fallback non viene fatto — la combinazione prefisso+content è già selettiva.

4. **Assegnazione prefisso sticky buffer** (vedi sezione 6).

### Fase 5 — Generazione patterns.hs

`hs_write_pattern()` in `hyperscan_formatter.c` converte la struct `Pattern` in una riga del formato Hyperscan:

```
<id>:/<prefix><regex>/<flags>{<ext_params>}
```

Conversione del campo `content` (notazione Suricata → regex Hyperscan):
- Testo ASCII: i caratteri speciali regex (`.`, `*`, `/`, `(`, ecc.) vengono preceduti da `\`
- Sequenze binarie `|HH HH|` → `\xHH\xHH`

Conversione parametri estesi:
- `offset:O` + lunghezza content `C` → `min_offset=O+C`
- `depth:D` + offset `O` → `max_offset=O+D`
- `startswith` → `min_offset=C,max_offset=C` (match solo alla posizione 0)

### Fase 6 — Generazione regole filtrate

Scrive `filtered.rules` (solo regole `FILTER_OK`) e `filtered2.rules` (regole `FILTER_OK` + `FILTER_PROTO_MISMATCH`).

---

## 5. Formato patterns.hs

Ogni riga ha la forma:

```
<id>:/<prefix><regex>/<flags>{<ext>}
```

Esempi concreti dopo le ottimizzazioni:

```
# http.user_agent — prefisso header
13104:/\x0d\x0aUser-Agent: masscan\//

# http.uri — prefisso con alternazione metodi HTTP
14086:/(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) \x0D\x0A/

# http.method — startswith (posizione 0 del payload)
5540:/POST/{min_offset=4,max_offset=4}

# http.request_body — prefisso separatore header/body
123:/\x0d\x0a\x0d\x0ajs=DhIhAwgjKRs.../

# http.stat_code — prefisso riga di stato HTTP
571:/HTTP\/1\.[01] .../

# pattern senza sticky buffer (no prefisso)
1001:/\.exe/i{min_offset=10,max_offset=100}
```

---

## 6. Sistema di prefissi per sticky buffer

### Il problema

Suricata usa **sticky buffer keyword** (es. `http.user_agent`, `http.uri`) per restringere la ricerca di un `content:` a un campo specifico del protocollo applicativo. Quando Suricata valuta:

```
http.user_agent; content:"masscan/"; startswith;
```

il pattern `masscan/` viene cercato solo nel valore dell'header `User-Agent` estratto dal parser HTTP. XDP invece scansiona l'intero payload grezzo TCP — dove `masscan/` appare dopo `\r\nUser-Agent: `, non all'inizio.

Senza un prefisso, pattern corti come `/GET/`, `/POST/`, `/\x0d\x0a/` (CRLF) corrispondono a quasi ogni pacchetto HTTP, portando a un tasso di falsi positivi prossimo al 100% (CNT_BAD/CNT_COND ≈ 99.9% nel benchmark iniziale).

### La soluzione: prefissi contestuali

Per ogni sticky buffer, si prepone al pattern Hyperscan il testo che nel payload grezzo TCP precede il valore del campo:

| Sticky buffer Suricata | Prefisso Hyperscan regex | Ragionamento |
|---|---|---|
| `http.uri` | `(GET\|POST\|PUT\|DELETE\|HEAD\|OPTIONS\|PATCH\|CONNECT\|TRACE) ` | Il metodo HTTP precede sempre l'URI |
| `http.user_agent` | `\x0d\x0aUser-Agent: ` | Header sempre formato `\r\nUser-Agent: valore` |
| `http.host` | `\x0d\x0aHost: ` | Header `\r\nHost: valore` |
| `http.server` | `\x0d\x0aServer: ` | Header risposta `\r\nServer: valore` |
| `http.referer` | `\x0d\x0aReferer: ` | Header `\r\nReferer: url` |
| `http.cookie` | `\x0d\x0aCookie: ` | Header `\r\nCookie: k=v` |
| `http.location` | `\x0d\x0aLocation: ` | Header risposta redirect |
| `http.connection` | `\x0d\x0aConnection: ` | Header `\r\nConnection: keep-alive` |
| `http.content_type` | `\x0d\x0aContent-Type: ` | Header `\r\nContent-Type: ...` |
| `http.accept` | `\x0d\x0aAccept: ` | Header `\r\nAccept: ...` |
| `http.accept_enc` | `\x0d\x0aAccept-Encoding: ` | Header `\r\nAccept-Encoding: ...` |
| `http.accept_lang` | `\x0d\x0aAccept-Language: ` | Header `\r\nAccept-Language: ...` |
| `http.content_len` | `\x0d\x0aContent-Length: ` | Header `\r\nContent-Length: N` |
| `http.stat_code` | `HTTP\/1\.[01] ` | Riga di stato `HTTP/1.1 NNN ...` |
| `http.request_body` | `\x0d\x0a\x0d\x0a` | Il body inizia dopo il separatore header |
| `http.response_body` | `\x0d\x0a\x0d\x0a` | Uguale per le risposte |
| `http.method` | *(nessun prefisso, usa startswith)* | Il metodo è ai byte 0-N del payload |

Per `http.method` non si prepone testo: il metodo HTTP si trova già alla posizione 0 del payload TCP. Si applica invece il constraint `{min_offset=N,max_offset=N}` tramite il flag `startswith` — così il pattern corrisponde solo se il keyword HTTP appare all'inizio del pacchetto, non nel body.

Sticky buffer senza prefisso definito (es. `file.data`, `tls.sni`, `dns.query`) lasciano il pattern senza prefisso. Il content da solo deve essere selettivo.

### Implementazione tecnica

La funzione `get_hs_prefix_before(rule_start, content_pos)` in `pattern_extractor.c`:

1. **Passo 1**: scansiona l'intero array `STICKY_BUFS[]` per trovare il keyword sticky buffer **più a destra** (più vicino al `content:` selezionato) nel testo della regola. Usa `STICKY_BUFS[]` e non direttamente `STICKY_PREFIX_MAP` per evitare che un sticky buffer distante dalla mappa sovrascriva uno più vicino non mappato (es. `file.data` che compare tra `http.stat_code` e il fast_pattern).

2. **Passo 2**: cerca il keyword trovato in `STICKY_PREFIX_MAP` e restituisce il prefisso corrispondente, o `NULL` se non è mappato.

```
Esempio regola:
  http.stat_code; content:"200"; file.data; content:"/evil"; fast_pattern;
                                                             ↑
                                                       content_pos

Passo 1: keyword più vicino a content_pos → "file.data"
Passo 2: "file.data" non è in STICKY_PREFIX_MAP → return NULL
Risultato: pattern /\/evil/ senza prefisso (corretto)
```

```
Esempio regola:
  http.user_agent; content:"masscan/"; startswith;
                            ↑
                      content_pos

Passo 1: keyword più vicino → "http.user_agent"
Passo 2: trovato in mappa → "\x0d\x0aUser-Agent: "
Risultato: pattern /\x0d\x0aUser-Agent: masscan\//
```

### Effetto sui pattern più problematici

Prima dei prefissi, la scansione del benchmark produceva:

- **CNT_COND** (pacchetti HTTP scansionati): 1.385.049
- **CNT_BAD** (match Hyperscan → XDP_PASS): 1.207.209 (**87% falsi positivi**)
- **CNT_GOOD** (nessun match → redirect): 1.353 (**0.1%**)

I pattern responsabili della maggior parte dei falsi positivi:

| Pattern originale | Cause del problema | Pattern dopo il fix |
|---|---|---|
| `/\x0d\x0a/` | Ogni pacchetto HTTP ha CRLF negli header | `/(GET\|POST\|...) \x0d\x0a/` |
| `/GET/` | Appare in ogni richiesta GET | eliminato (fallback a content più lungo) |
| `/POST/` × 20 regole | Appare in ogni richiesta POST | `\x0d\x0a\x0d\x0aic=...` oppure `/POST/{min_offset=4,max_offset=4}` |
| `/HTTP/` | Appare in ogni riga di stato/richiesta | prefisso `HTTP\/1\.[01] ` o eliminato |
| `/200/` | Codice di risposta comune | `HTTP\/1\.[01] 200` |
| `/z/` | Lettera singola | fallback a content più lungo nella regola |
| `/-/` | Trattino — compare ovunque | fallback a content più lungo |

---

## 7. Problemi risolti

### Problema 1 — Offset errati per sticky buffer (bug)

**Causa**: `startswith` per pattern in sticky buffer generava `{min_offset=N,max_offset=N}` calcolati sul payload grezzo, non sul campo applicativo. `http.user_agent; content:"masscan/"; startswith;` produceva `{min_offset=8,max_offset=8}` (match solo se "masscan/" finisce al byte 8 del payload grezzo), impossibile da soddisfare in traffico reale.

**Fix** (`pattern_extractor.c`): la funzione `sticky_before_content()` rileva se un keyword sticky buffer precede il `content:` corrente. Se sì, azzera `startswith`, `offset`, `depth` prima che il formatter generi i parametri estesi.

**Impatto**: 2.489 pattern avevano vincoli impossibili (da 3.271 con `min_offset` a 782 dopo il fix, dove i rimanenti sono legittimi per pattern raw senza sticky buffer).

---

### Problema 2 — SYN/FIN/RST con padding Ethernet reindirizzati (bug)

**Causa**: Ethernet richiede frame di minimo 64 byte. I pacchetti di controllo TCP (SYN, ACK, FIN) hanno payload nullo ma ricevono padding di zero dal NIC/switch. Dal punto di vista XDP, `payload_len` è non-zero (es. 6 byte di padding), quindi il pacchetto non veniva bloccato dalla guardia `payload_len == 0` e veniva scansionato. Nessun pattern nel DB corrispondeva ai byte di padding → `bpf_redirect(0,0)` → Suricata non vedeva il TCP handshake → le regole con `flow:established` non potevano funzionare.

**Fix** (`xdp_prog_kern_test.c`): controllo esplicito dei flag TCP **prima** della scansione Hyperscan:

```c
if (tcp->syn || tcp->fin || tcp->rst)
    return XDP_PASS;
```

I pacchetti di controllo raggiungono sempre Suricata, indipendentemente dal padding.

**Impatto**: SID 2017616 (masscan/) dipende da `flow:established,to_server`. Senza questo fix, Suricata non vedeva il SYN e non poteva stabilire la sessione TCP → alert mancato anche con il pattern corretto nel DB.

---

### Problema 3 — Fast_pattern troppo corto (ottimizzazione)

**Causa**: Suricata sceglie il `fast_pattern` per il suo matcher Aho-Corasick multi-pattern (MPAM), che può essere efficiente anche con pattern corti. Per XDP/Hyperscan, un pattern di 2-3 byte corrisponde a quasi ogni pacchetto.

**Fix** (`pattern_extractor.c`): se il content estratto è < `MIN_PATTERN_BYTES` (6 byte) E non ha un prefisso sticky buffer, si cerca il content non-negato più lungo in tutta la regola e lo si usa come sostituto. Il contatore `upgraded` traccia quante regole hanno subito questa sostituzione.

**Nota importante**: il fallback **non viene fatto** se il pattern ha già un prefisso sticky buffer, perché:
- La combinazione prefisso+content è già selettiva (es. `\r\nUser-Agent: ic=` ha 14+3=17 byte di contesto)
- Il fallback potrebbe sostituire il content con uno da un campo applicativo diverso (es. sostituire "ic=" in `http.request_body` con "POST" in `http.method`), perdendo il prefisso corretto

---

### Problema 4 — Pattern falsi positivi da sticky buffer (bug principale)

**Causa**: il sistema di prefissi non era implementato. Tutti i pattern venivano scansionati sul payload grezzo senza contesto del campo applicativo. Pattern come `/\x0d\x0a/`, `/GET/`, `/POST/` corrispondevano a praticamente ogni pacchetto HTTP.

**Fix**: implementazione del sistema di prefissi descritto nella sezione 6.

**Risultato** (da 149 pattern false-positive originali):
- 0 pattern tra quelli originalmente problematici rimasti senza prefisso
- 4.134 pattern con prefisso URI (metodo HTTP)
- 6.265 pattern con prefisso header HTTP
- 2.139 pattern con prefisso body HTTP

---

## 8. Limitazioni note

### Regole su risposta HTTP non rilevabili (limite architetturale)

Alcune regole si attivano su dati nella **risposta** HTTP (`flow:established,to_client`). Il pattern Hyperscan per questi è corretto, ma la sequenza degli eventi rompe il contesto:

```
1. HTTP GET request → cond=1, scan cattivi
   nessun pattern matcha → bpf_redirect(0,0)
   Suricata NON vede la richiesta

2. HTTP response (con "AmazonS3") → cond=1, scan cattivi
   pattern matcha → XDP_PASS
   Suricata riceve la risposta
   ma non ha visto la richiesta → no contesto HTTP → alert non scatta
```

**Soluzione futura**: flow tracking nella mappa BPF. Registrare per ogni 5-tuple se il flow è già stato "passato" a Suricata. Se sì, tutti i pacchetti successivi vanno a Suricata (XDP_PASS), anche se non matchano.

### Pattern da protocolli non-HTTP

I 102 pattern rimanenti senza prefisso e con content < 6 byte appartengono a protocolli non-HTTP (FTP: `STAT`, `CWD`, `RETR`; IRC: `NICK`; RTSP: `SETUP`). Questi protocolli non erano nel traffico del benchmark PCAP usato. Se il sistema venisse deployato su traffico misto, questi pattern potrebbero causare falsi positivi sui rispettivi protocolli.

### Sticky buffer senza prefisso

I seguenti sticky buffer non hanno un prefisso definito e i pattern corrispondenti vengono usati senza contesto:

- `file.data` — contenuto di file (offset nel payload molto variabile)
- `http.header` / `http.raw_header` — header generico (nome variabile)
- `tls.sni`, `tls.cert_*` — campi TLS (formato binario TLS)
- `dns.query`, `dns.answer` — formato wire DNS
- `ssh.protoversion`, `ssh.softwareversion` — formato SSH

---

## 9. File di output

| File | Contenuto |
|------|-----------|
| `patterns.hs` | Pattern Hyperscan nel formato `id:/prefix+regex/flags{ext}` |
| `filtered.rules` | Regole Suricata accettate (una per riga del patterns.hs) |
| `filtered2.rules` | Come filtered.rules + regole con protocollo non rilevato nel PCAP |

### Deploy del patterns.hs nel sistema XDP

```bash
# Copiare il patterns.hs nella directory XDP
cp patterns.hs ../evalNet/xdp-tutorial/test/patterns.hs

# Compilare in database Hyperscan binario e caricare nel kernel module
cd ../evalNet/xdp-tutorial/test
sudo bash init.sh patterns.hs
```

`init.sh` usa `hscollider` (Hyperscan kernel port) per compilare i pattern in un database binario serializzato, poi lo inietta nel kernel module tramite il configfs:

```
/sys/kernel/config/rex/cattivi/database   ← database ID 4321
/sys/kernel/config/rex/buoni/database     ← database ID 1234
```

Il programma XDP legge il database ID tramite `bpf_xdp_scan_bytes(ctx, 0, payload_len, &attr, payload_offset)` dove `attr.database_id` seleziona quale database usare.
