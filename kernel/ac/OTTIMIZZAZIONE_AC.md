# Da Aho-Corasick tradizionale al filtro XDP ottimizzato

Documento di sintesi del percorso di ottimizzazione del prefiltro Aho-Corasick
in kernel (XDP), con le motivazioni di ogni scelta. Caso di riferimento:
traccia *mixed* (HTTP/80, 18.628 pattern Suricata), 2500 Mbps, MAX_SCAN=1500.

---

## 0. Punto di partenza — Aho-Corasick "da manuale"

Aho-Corasick costruisce un DFA in cui ogni stato ha una tabella completa di
transizioni: `next[256]` (un indice di stato per ogni possibile byte). Dopo
`fill_dfa()` la tabella è **densa** — nessuna transizione mancante.

| Metrica | Valore |
|---|---|
| Stati | 165.802 |
| Byte per stato | `next[256]×u32 + output` = 1028 B |
| **Tabella totale** | **~163 MB** |
| Tempo scan / 1500 B | **7,22 µs** |
| Pacchetti persi @2500 Mbps | **~5,6 milioni** (rx_missed) |

### Il problema di fondo

Il loop di scansione è una **catena di load dipendenti**:

```c
state = next[state][c];   // per sapere dove andare al byte i+1
                          // devo avere finito il load del byte i
```

Ogni byte costa la latenza di un accesso in memoria, e le latenze **si
sommano**: 1500 byte × ~4,8 ns = i 7,2 µs osservati. Non è un problema di
banda (la CPU potrebbe fare più load in parallelo), ma di **dipendenza
seriale**: ogni load dipende dal risultato del precedente. In più la tabella
da 163 MB non entra in cache (L3 = 64 MB), quindi ogni accesso è un miss in RAM.

A quel ritmo un singolo core regge ~138 kpps; a 2500 Mbps con pacchetti grandi
arrivano ~208 kpps → overflow della coda NIC → pacchetti persi.

---

## 1. Ottimizzazioni tentate e scartate

Prima di trovare la strada giusta, tre approcci sono stati misurati e
**abbandonati** perché inefficaci — documentati qui per non ripeterli.

### 1a. State compression (default + eccezioni) — FALLITA
Idea: memorizzare per ogni stato solo la transizione "di default" (la moda dei
256 valori) più le eccezioni. Funziona sui trie sparsi, **non** su un DFA AC:
dopo `fill_dfa()` i failure-link riempiono la tabella e la rendono densa.
Misura reale: **38,1 milioni di eccezioni su 42,4 milioni** di transizioni
(90%). Nessuna compressione. Il working set restava ~150 MB e la scan
diventava più lenta (ricerca lineare per byte).

### 1b. Minimizzazione DFA (Hopcroft / partition refinement) — INSUFFICIENTE
Unifica gli stati equivalenti: 165.802 → 119.162 stati (**−28%**). Utile ma da
sola non basta: ~117 MB, ancora fuori cache. Resta comunque abilitata perché
si combina bene con le ottimizzazioni successive.

### 1c. Separazione dell'array `output[]` — NESSUN GUADAGNO
Spostare i flag terminali in un array compatto separato (L3-warm) non ha
prodotto alcun beneficio misurabile: l'esecuzione out-of-order della CPU già
nascondeva quel secondo miss. Il collo resta la tabella `next[][]`.

---

## 2. ACDB v2 — ridurre il working set

Tre trasformazioni combinate, tutte a monte (nel builder `ac_build`):

1. **Troncamento pattern** (`-t 12`): si indicizzano solo i primi 12 byte di
   ogni pattern. Da prefiltro è lecito — un match parziale genera al più un
   falso positivo che Suricata verifica, **mai un falso negativo**. Riduce
   drasticamente gli stati (i suffissi lunghi non condivisi sono la maggioranza
   dei nodi).
2. **Entry a 16 bit**: con < 65.536 stati, ogni transizione passa da `u32` a
   `u16` → riga di stato dimezzata.
3. **Compressione dell'alfabeto**: due byte che hanno colonne di transizione
   identiche su tutti gli stati sono equivalenti. Si mappano i 256 byte in
   ~230 classi (`class_map`, con il case-folding già incorporato → niente
   `tolower()` a runtime). Il lookup diventa `next[(state<<shift) + class[c]]`.

| Metrica | AC tradizionale | ACDB v2 (t12) |
|---|---|---|
| Stati | 165.802 | 56.114 |
| Tabella | 163 MB | **28 MB** |
| Tempo scan / 1500 B | 7,22 µs | **4,61 µs** |

Da notare: a t8 (16 MB) il tempo **non** migliora ulteriormente → si era
raggiunto il pavimento della catena seriale, non della dimensione tabella.
Serviva un'idea diversa.

---

## 3. Prefiltro n-gram — la svolta

**Osservazione chiave**: il costo non è "quanti dati", è "quanti load
*dipendenti*". Bisognava un test che rispondesse a *"questo pacchetto potrebbe
contenere un pattern?"* con **load indipendenti**, così che la CPU li possa
sovrapporre invece di sommarne le latenze.

### Come funziona

In fase di build si costruiscono bitmap dai prefissi dei pattern:
- **T1** (1 MB): bit `hash(primi 4 byte)` di *tutti* i pattern;
- **T2** (1 MB): bit `hash(byte 4–7)` dei pattern ≥ 8 byte;
- **TS4…TS7** (128 KB ×4): hash dell'intero pattern per quelli corti (4–7 B).

In fase di scan, per ogni posizione `i` del payload:

```c
candidato = T1[hash(buf[i..i+3])] && T2[hash(buf[i+4..i+7])]
```

Se **nessuna** posizione è candidata → il pacchetto è pulito, il DFA **non
parte affatto**. Solo sui candidati (~7% dei pacchetti) si esegue l'AC
completo per la conferma.

### Perché è veloce

`hash(buf[i..i+3])` **non dipende da nessuno stato**: sono 1500 lookup
*indipendenti* che la CPU out-of-order tiene in volo a decine → le latenze si
**sovrappongono** invece di sommarsi. Le bitmap (~2,5 MB) stanno in L2. Solo
aritmetica intera: **zero FPU** (a differenza di Hyperscan, che nel kernel
pagherebbe `kernel_fpu_begin/end`).

Il doppio test `T1 && T2` abbatte i falsi trigger: la probabilità che una
posizione pulita sembri candidata scende a ~4×10⁻⁶ → solo lo ~0,6% dei
pacchetti puliti fa partire il DFA per sbaglio. Per costruzione **nessun falso
negativo**: se un pattern è presente, i suoi n-grammi accendono le bitmap.

| Metrica | ACDB v2 | + Prefiltro n-gram |
|---|---|---|
| Tempo scan / 1500 B | 4,61 µs | **2,66 µs** |
| Pacchetti persi @2500 Mbps | 3,5 M | **≈ 0** (803 su 16,7 M) |

Percorso completo: **7,22 → 4,61 → 2,66 µs (−63%)**, da 5,6 M perdite a zero.

---

## 4. Il fix del padding Ethernet

Durante la validazione dell'equivalenza è emerso un bug: il payload veniva
calcolato dalla lunghezza del **frame** (`data_end − data`). Sul filo i frame
corti (ACK puri, 54 B) vengono paddati a 60 B: quei 6 byte di padding venivano
scansionati come "payload", non trovavano match, e l'ACK veniva **droppato** —
spezzando lo stream TCP che Suricata deve ricostruire per le regole app-layer.

Fix (3 righe): calcolare la lunghezza da `ip->tot_len`, che il padding non
include.

```c
__u32 ip_len  = sizeof(struct ethhdr) + bswap16(ip->tot_len);
__u32 pkt_len = ip_len < frame_len ? ip_len : frame_len;
```

Senza questo fix la traccia mixed perdeva 4 alert; con il fix, equivalenza piena.

---

## 5. Verifica di equivalenza

È stato costruito un tool offline che **replica bit-per-bit** la decisione
dell'XDP (`ac_simfilter`, validato: drop-count offline == live al pacchetto) e
un comparatore (`ac_equiv`) che confronta gli alert di Suricata su pcap pieno
vs pcap filtrato, classificando ogni differenza.

| Traccia | Alert full | Alert filtrato | Persi | Offload |
|---|---|---|---|---|
| mixed (HTTP) | 362 | 362 | **0** | 28% pkt / 50% byte |
| good (SSH cifrato) | 0 | 0 | **0** | 35% |
| NF (HTTP) | 248 | 252 | **0** | ~56% |

- **Nessun alert perso** su nessuna traccia con MAX_SCAN=1500.
- I 4 alert *extra* di NF sono "Packed Executable Download" su download PE
  realmente presenti: il reassembly alterato dai drop fa scattare la regola
  `content:"MZ";startswith` che il pieno non genera. Sono eventi veri, non
  falsi positivi — il filtro **non perde** detection, semmai ne aggiunge.

---

## 6. Bilancio

Partendo da un Aho-Corasick da manuale (163 MB, 7,2 µs, perdite massicce), la
soluzione attuale:

- **2,66 µs** per scansione completa a 1500 byte (−63%);
- **zero perdite** a 2500 Mbps;
- **50% dei byte** sottratti a Suricata a parità di alert;
- **equivalenza dimostrata** su tre tracce reali;
- **niente FPU**, working set in cache, tutto in kernel via XDP.

La leva decisiva non è stata comprimere di più il DFA, ma **spezzare la catena
seriale** con un prefiltro a load indipendenti — la stessa intuizione dell'FDR
di Hyperscan, ma in versione scalare intera, adatta al contesto kernel/XDP.
