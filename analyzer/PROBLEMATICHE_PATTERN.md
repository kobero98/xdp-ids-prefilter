# Problematiche rilevate nel generatore di pattern Hyperscan

## Contesto

Il sistema accelera Suricata tramite un programma XDP che, per ogni pacchetto TCP/UDP di un protocollo monitorato (es. HTTP sulla porta 80), esegue una scansione Hyperscan contro un database di "pattern cattivi" (`cattivi`, ID 4321):

- **match trovato** → `XDP_PASS`: il pacchetto viene inviato a Suricata per l'analisi completa
- **nessun match** → `bpf_redirect(0,0)`: il pacchetto viene reindirizzato, Suricata non lo vede

I pattern Hyperscan vengono generati da `AnalizzatoreSuricata2/analyzer` a partire dal file delle regole Suricata (`suricata.rules`) e scritti in `patterns.hs`. Il formato di ogni riga è:

```
<id>:/<regex>/<flags>{min_offset=N,max_offset=M}
```

dove `min_offset` e `max_offset` sono posizioni **di fine match** nel payload grezzo del pacchetto (a partire dall'inizio del payload applicativo TCP/UDP, dopo gli header Ethernet/IP/TCP).

---

## Problema 1 — Offset errati per sticky buffer keyword (bug nel codice)

### Descrizione

In Suricata, alcune keyword definiscono un **sticky buffer**: restringono la ricerca del `content:` a un campo specifico del protocollo applicativo. Esempi:

```
http.user_agent; content:"masscan/"; startswith;
```

Qui `startswith` significa: il contenuto "masscan/" deve trovarsi all'**inizio del valore dell'header User-Agent**. Questo offset è relativo al campo HTTP, non al payload grezzo del pacchetto TCP.

Il codice in `hyperscan_formatter.c` traduceva `startswith` in:

```c
snprintf(tmp, sizeof(tmp), "min_offset=%d,max_offset=%d", clen, clen);
```

Per "masscan/" (8 byte) generava `{min_offset=8,max_offset=8}`, cioè: "il pattern deve finire esattamente al byte 8 del payload grezzo". Ma in un pacchetto HTTP reale il payload grezzo inizia con:

```
GET / HTTP/1.1\r\n
Host: target.com\r\n
User-Agent: masscan/1.0 ...\r\n
```

Il valore dell'User-Agent si trova a decine di byte dall'inizio del payload, mai al byte 0. Il vincolo `max_offset=8` rendeva il pattern **impossibile da soddisfire** in traffico reale.

### Impatto misurato

Il confronto tra i risultati di Suricata con e senza il modulo XDP attivo ha evidenziato la scomparsa dell'alert per SID 2017616 (*ET SCAN NETWORK Incoming Masscan detected*), che usa esattamente `http.user_agent; content:"masscan/"; startswith`.

Totale pattern coinvolti: su 15.234 pattern generati, **2.489 avevano vincoli di offset errati** (da 3.271 con `min_offset` prima del fix a 782 dopo, dove i rimanenti sono legittimi in contesti raw non-sticky-buffer).

Le sticky buffer keyword Suricata interessate includono (ma non solo):
`http.uri`, `http.user_agent`, `http.host`, `http.server`, `http.stat_code`,
`http.method`, `http.header`, `http.header_names`, `http.request_header`,
`http.response_header`, `http.request_body`, `http.response_body`,
`http.cookie`, `http.referer`, `http.location`, `http.protocol`,
`http.content_type`, `http.request_line`, `http.response_line`, `http.start`,
`file.data`, `dns.query`, `tls.sni`, ecc.

### Fix applicato

In `pattern_extractor.c` è stata aggiunta la funzione `sticky_before_content()`, che cerca nel testo della regola (prima del `content:` corrente) una qualsiasi sticky buffer keyword. Se trovata, i modificatori `startswith`, `offset` e `depth` vengono azzerati prima che il formatter li traduca in vincoli Hyperscan.

```
# Prima del fix (ERRATO):
13105:/masscan\//{min_offset=8,max_offset=8}

# Dopo il fix (CORRETTO):
13105:/masscan\//
```

Il pattern senza vincoli di posizione viene trovato da Hyperscan ovunque nel payload grezzo, replicando fedelmente il comportamento del fast-path di Suricata.

---

## Problema 2 — Regole su risposta HTTP non rilevabili (limite architetturale)

### Descrizione

Alcune regole Suricata si attivano su dati presenti nella **risposta HTTP** (direzione server→client), non nella richiesta:

| SID | Descrizione | Keyword |
|-----|-------------|---------|
| 2013414 | ET INFO Executable served from Amazon S3 | `flow:established,to_client; http.server; content:"AmazonS3"` |
| 2101201 | GPL WEB_SERVER 403 Forbidden | `flow:established,to_client; http.stat_code; content:"403"` |

I pattern Hyperscan per queste regole sono **scritti correttamente** nel `patterns.hs` (nessun vincolo di offset errato):

```
5621:/AmazonS3/
14281:/403/
```

Tuttavia, questi alert **non vengono generati** quando il modulo XDP è attivo. La causa è la seguente sequenza di eventi:

```
1. TCP SYN / SYN-ACK / ACK  →  XDP_PASS  ✓  (payload vuoto)
2. HTTP GET request           →  cond=1, scan cattivi
                                  nessun pattern matcha la GET request
                                  → bpf_redirect(0,0)  ✗
                                  Suricata NON vede la request
3. HTTP response (con "403")  →  cond=1, scan cattivi
                                  "/403/" matcha!
                                  → XDP_PASS  ✓
                                  Suricata RICEVE la response
                                  ma non ha visto la request
                                  → impossibile stabilire contesto HTTP
                                  → l'alert non scatta
```

Il nodo critico è il passo 2: la GET request non contiene nessun pattern "cattivo", viene reindirizzata, e Suricata perde il contesto TCP/HTTP necessario affinché le regole con `flow:established,to_client` e le sticky buffer HTTP (che richiedono parsing applicativo) possano funzionare.

### Perché il Problema 1 e il Problema 2 hanno cause diverse

| | Problema 1 (masscan/) | Problema 2 (AmazonS3, 403) |
|---|---|---|
| Pattern nel DB | Presente ma con offset sbagliato | Presente e corretto |
| Match Hyperscan | **Non avviene mai** (vincolo impossibile) | Avviene sulla response |
| Motivo del mancato alert | Il pattern non matcha → redirect | La request è già stata reindirizzata → no contesto HTTP |

### Possibile soluzione futura

Implementare un **tracking per-flow** nella mappa BPF. Logica proposta:

1. Aggiungere una mappa `flow_state_map` (hash dei 5-tuple: src_ip, dst_ip, src_port, dst_port, proto) con valori `{redirect: 0/1}`.
2. Alla prima ricezione di un pacchetto con payload per un flow HTTP:
   - Se Hyperscan **matcha** → `XDP_PASS` + segnare il flow come "pass-through"
   - Se **non matcha** → `bpf_redirect` + segnare il flow come "redirected"
3. Per i pacchetti successivi dello stesso flow, seguire la decisione già presa (senza riscansire).
4. Alla chiusura del flow (FIN/RST), rimuovere la entry dalla mappa.

Questo garantisce che Suricata veda **tutti i pacchetti di un flow** non appena uno di essi ha generato un match, ripristinando il contesto necessario per le regole `flow:established`.

La modifica richiederebbe interventi su `xdp_prog_kern_test.c` e potenzialmente su `map_use.py` per gestire il ciclo di vita delle entry nella nuova mappa.

---

## Problema 3 — Pacchetti SYN/FIN/RST con padding Ethernet reindirizzati (bug nel codice XDP)

### Descrizione

In Ethernet, un frame ha una dimensione minima di 64 byte. I pacchetti TCP di controllo (SYN, SYN-ACK, ACK, FIN, RST) spesso hanno un payload applicativo nullo, ma lo switch/NIC aggiunge **padding di zeri** per raggiungere i 64 byte. Dal punto di vista del driver XDP, questi byte extra appaiono come payload del pacchetto.

Il codice in `xdp_prog_kern_test.c` aveva questa guardia:

```c
if (payload_len == 0)
    return XDP_PASS;
```

Questa guardia è **insufficiente** quando il padding è presente: per un pacchetto SYN con header TCP di 20 byte su un frame Ethernet corto, `payload_len` può valere 6 (i 6 byte di padding), non 0.

### Impatto misurato

Analisi PCAP del flow masscan (SID 2017616):

```
Pkt#648146  61.240.144.66:60000 → 192.168.0.2:80   SYN       payload=6b  (6 byte di padding Ethernet)
Pkt#648147  192.168.0.2:80 → 61.240.144.66:60000    SYN-ACK   payload=2b
Pkt#648148  61.240.144.66:60000 → 192.168.0.2:80   ACK       payload=10b
Pkt#648150  61.240.144.66:60000 → 192.168.0.2:80   PSH+ACK   payload=103b (GET HTTP/1.0 masscan/1.0)
```

Sequenza degli eventi con il bug:

1. SYN (payload=6): `cond=1`, Hyperscan scansiona 6 byte di zero → nessun match → `bpf_redirect(0,0)` ✗
2. Suricata **non vede il TCP SYN** → non può stabilire la sessione TCP
3. PSH+ACK (payload=103): Hyperscan trova `masscan/` → `XDP_PASS` ✓
4. Suricata riceve i dati ma non ha mai visto il SYN → `flow:established,to_server` **fallisce** → alert non scatta

Questo bug annulla completamente il beneficio del fix del Problema 1: il pattern `masscan/` è ora corretto nel DB, ma Suricata non può usarlo perché non ha mai visto il handshake TCP.

### Fix applicato

In `xdp_prog_kern_test.c`, nel blocco TCP, è stato aggiunto un controllo esplicito dei flag TCP **prima** della scansione Hyperscan:

```c
// CORRETTO: usa tcp->doff
payload_offset += tcp->doff * 4;

/* SYN/FIN/RST packets must always reach Suricata for TCP session
 * tracking. Ethernet padding can make payload_len non-zero even
 * for pure handshake packets, so the payload_len==0 guard below
 * is not sufficient. Check flags here, before any Hyperscan scan. */
if (tcp->syn || tcp->fin || tcp->rst)
    return XDP_PASS;
```

Questo garantisce che i pacchetti di controllo TCP raggiungano sempre Suricata, indipendentemente dal padding Ethernet.

### Regole impattate

Tutte le regole Suricata con `flow:established` su traffico TCP: senza il TCP handshake completo, Suricata non può soddisfare il requisito di sessione stabilita. Nel benchmark, SID 2017616 (masscan/) dipende da `flow:established,to_server`.

---

## Riepilogo

| # | Tipo | Regola esempio | Causa | Stato |
|---|------|---------------|-------|-------|
| 1 | Bug codice | SID 2017616 masscan/ | `startswith` su sticky buffer → offset Hyperscan errato | **Risolto** in `pattern_extractor.c` |
| 2 | Bug codice | SID 2017616 masscan/ e tutte `flow:established` | SYN/FIN/RST con padding Ethernet → `payload_len≠0` → redirect → Suricata perde il TCP handshake | **Risolto** in `xdp_prog_kern_test.c` |
| 3 | Limite architetturale | SID 2013414 AmazonS3, SID 2101201 403 | Request HTTP reindirizzata → no contesto per regole `to_client` | **Da implementare** (flow tracking in XDP) |

---

## Come applicare tutti i fix

```bash
# ── Fix 1: pattern con offset errati ──────────────────────────────────────────
# 1. Ricompilare l'analizzatore
cd AnalizzatoreSuricata2
make

# 2. Rigenerare i pattern con il PCAP e le regole del benchmark
./analyzer dataset/netresec/output_NF_2015_03.pcap dataset/suricata.rules

# 3. Copiare il patterns.hs aggiornato nella directory XDP
cp patterns.hs ../evalNet/xdp-tutorial/test/patterns.hs

# 4. Ricaricare i database Hyperscan nel modulo kernel
cd ../evalNet/xdp-tutorial/test
sudo bash init.sh patterns.hs

# ── Fix 2: SYN/FIN/RST con padding Ethernet ───────────────────────────────────
# 5. Ricompilare il programma XDP (già applicato in xdp_prog_kern_test.c)
cd evalNet/xdp-tutorial/test
bash compile_user.sh

# 6. Ricaricare il programma XDP sulla NIC
bash setup_xdp.sh
python3 map_use.py tcp 80
```
