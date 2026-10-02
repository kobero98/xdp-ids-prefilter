# Il prefiltro n-gram: collocazione nella letteratura scientifica

Questo documento inquadra il prefiltro a bitmap n-gram introdotto nel filtro
XDP rispetto al lavoro accademico esistente, spiegando a quali filoni si
richiama e in cosa consiste il suo contributo specifico.

---

## 1. Che cos'è, in una frase

È un **pre-screening a livello di pacchetto, in-kernel (XDP), a sola aritmetica
intera**, che fattorizza i pattern in n-grammi ancorati (i primi 4 byte e i
byte 4–7 di ogni pattern), li memorizza in bitmap tipo Bloom, e le interroga
con lookup *indipendenti dallo stato* per far scattare l'Aho-Corasick completo
solo sui pacchetti candidati.

Appartiene alla famiglia dei **filtri "condizione necessaria ma non
sufficiente"**: un test rapido che non produce falsi negativi e scarta in
blocco il traffico che non può contenere alcun pattern, delegando la conferma
esatta a un secondo stadio.

---

## 2. I filoni a cui si richiama

### 2.1 Filtraggio con q-grammi (approximate & exact string matching)
L'idea che *"se un pattern occorre, allora tutti i suoi q-grammi occorrono"* è
il cuore del **q-gram filtering**, formalizzato da Ukkonen (1992) e trattato
sistematicamente da Navarro & Raffinot (*Flexible Pattern Matching in Strings*,
2002). Le nostre bitmap T1/T2 sono esattamente un test di q-grammi (4-grammi)
usato come condizione necessaria. La differenza: qui i q-grammi non sono presi
a ogni posizione del pattern, ma **ancorati** all'inizio (offset 0 e 4), il che
li rende un *fingerprint del prefisso* del pattern.

### 2.2 Multi-pattern matching con shift/hash su blocchi
- **Wu–Manber (1994)** usa blocchi di caratteri (hash di q-grammi) per decidere
  quanto saltare — un filtro su q-grammi in chiave bad-character shift.
- **Karp–Rabin (1987)** esteso al multi-pattern: si confronta l'hash di una
  finestra scorrevole contro un *insieme* di hash dei pattern. Il nostro
  filtro è concettualmente un Rabin–Karp multi-pattern in cui l'insieme degli
  hash è rappresentato da una **bitmap** invece che da una hash table, e la
  finestra è di 4 byte.

### 2.3 Bloom filter per Deep Packet Inspection — il parente più diretto
Il riferimento più vicino è **Dharmapurikar, Krishnamurthy, Sproull & Lockwood,
"Deep Packet Inspection using Parallel Bloom Filters" (Hot Interconnects 2003 /
IEEE Micro 2004)**: un motore hardware che cerca migliaia di firme cercando
sottostringhe di lunghezza fissa con Bloom filter paralleli, uno per lunghezza,
e conferma i match con un analizzatore esatto.

Le nostre T1/T2/TS*_ sono Bloom filter (con una funzione hash ciascuno) su
n-grammi di lunghezza fissa; il nostro secondo stadio (il DFA AC) è
l'analizzatore esatto. La differenza è il contesto: **software in XDP/eBPF nel
kernel Linux**, non hardware FPGA — ma la struttura logica è la stessa.

### 2.4 Fingerprint prefiltering di Hyperscan (FDR / Teddy)
**Wang et al., "Hyperscan: A Fast Multi-pattern Regex Matcher in Software"
(NSDI 2019)** descrive l'approccio di Intel: i pattern vengono fattorizzati in
stringhe corte ("fingerprint"), cercate con algoritmi SIMD (FDR = shift-or
fattorizzato con bucket; Teddy = shuffle SSE/AVX su prefissi corti), e i
candidati sono confermati dal matcher completo.

Il nostro prefiltro è **la stessa idea — fattorizzazione in n-grammi corti +
verifica — ma resa scalare**: niente SIMD, perché il codice gira in contesto
softirq/XDP dove usare i registri vettoriali richiederebbe
`kernel_fpu_begin/end` (costoso e non sempre lecito). Al posto del parallelismo
SIMD sfruttiamo il **parallelismo a livello di istruzione (ILP)**: i lookup
n-gram sono indipendenti dallo stato, quindi il motore out-of-order della CPU
ne tiene in volo molti contemporaneamente e ne sovrappone le latenze di memoria
— ottenendo l'effetto "vettoriale" senza istruzioni vettoriali.

### 2.5 Filtro congiuntivo a due hash (T1 ∧ T2)
Richiedere che *due* bitmap indipendenti diano hit sulla stessa posizione
(prefisso a offset 0 **e** a offset 4) è un **partitioned / conjunctive
hashing**: abbatte il tasso di falsi positivi al prodotto dei due tassi
(~0,2% × 0,2% ≈ 4×10⁻⁶ per posizione), come nei bloom multi-hash e nei
segmented fingerprint di Hyperscan.

---

## 3. Dove si colloca rispetto a Snort/Suricata

I NIDS moderni hanno già un prefiltro interno: il **MPM ("multi-pattern
matcher") / fast_pattern** di Snort e Suricata estrae da ogni regola un content
rappresentativo e lo cerca con Aho-Corasick o Hyperscan; solo se quel content
matcha, la regola completa (con PCRE, distanze, keyword) viene valutata.

Il nostro filtro è **un prefiltro *a monte* di quel prefiltro**: gira in XDP,
prima che il pacchetto raggiunga Suricata, e decide se il pacchetto merita di
essere consegnato allo stack e all'MPM. In sostanza:

```
Traffico → [XDP: prefiltro n-gram + AC troncato]  ← il nostro contributo
                     │ solo candidati
                     ▼
           [Suricata: MPM/fast_pattern → regole complete]
```

È un'istanza di **early filtering / load shedding in-kernel**, nello spirito di
lavori come "Snort Offloader" e degli acceleratori XDP/eBPF per IDS
(es. Molero et al., e i più recenti prefilter eBPF), ma con un motore di
matching (AC + n-gram) interamente in kernel-space.

---

## 4. Che cosa c'è di specifico in questo lavoro

Nessuno dei mattoni è nuovo di per sé (Bloom 1970, Aho-Corasick 1975,
Karp-Rabin 1987, q-gram filtering anni '90, parallel-bloom DPI 2003, Hyperscan
2019). L'elemento distintivo è la **combinazione**:

1. **Fingerprint prefiltering di tipo Hyperscan portato in XDP/eBPF**, dove le
   istruzioni SIMD non sono praticabili;
2. sostituzione del parallelismo SIMD con lo sfruttamento esplicito dell'**ILP
   scalare** (lookup indipendenti dallo stato → out-of-order → latenze
   sovrapposte) — è la ragione per cui il prefiltro rompe la catena seriale
   dell'Aho-Corasick e scende sotto il limite di latenza del DFA puro;
3. **n-grammi ancorati al prefisso** (offset 0 e 4) anziché a ogni posizione,
   che li lega direttamente ai pattern troncati usati dal DFA di secondo stadio,
   garantendo per costruzione **zero falsi negativi**;
4. integrazione con un **Aho-Corasick compresso** (alfabeto ridotto, entry a 16
   bit, pattern troncati) come verificatore esatto, il tutto residente in cache.

In termini di tassonomia: è un **two-stage, filter-then-verify multi-pattern
matcher**, con primo stadio *Bloom/fingerprint n-gram integer-only in kernel* e
secondo stadio *DFA Aho-Corasick compresso*, ottimizzato per **latenza per
pacchetto** su hardware commodity senza acceleratori.

---

## 5. Riferimenti essenziali

- B. Bloom, *Space/Time Trade-offs in Hash Coding with Allowable Errors*, CACM 1970.
- A. Aho, M. Corasick, *Efficient String Matching: An Aid to Bibliographic Search*, CACM 1975.
- R. Karp, M. Rabin, *Efficient Randomized Pattern-Matching Algorithms*, IBM J. Res. Dev. 1987.
- S. Wu, U. Manber, *A Fast Algorithm for Multi-Pattern Searching*, Tech. Report 1994.
- E. Ukkonen, *Approximate String Matching with q-grams and Maximal Matches*, TCS 1992.
- G. Navarro, M. Raffinot, *Flexible Pattern Matching in Strings*, Cambridge Univ. Press 2002.
- S. Dharmapurikar et al., *Deep Packet Inspection using Parallel Bloom Filters*, IEEE Micro 2004.
- X. Wang et al., *Hyperscan: A Fast Multi-pattern Regex Matcher in Software*, USENIX NSDI 2019.
