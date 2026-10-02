# 🧠 Specifica per la generazione di un tool C: PCAP + Suricata Rules → Hyperscan DB

## 🎯 Obiettivo

Scrivere un programma in C che:

1. Analizza staticamente un file `.pcap`
2. Analizza un file di regole Suricata `.rules`
3. Estrae pattern rilevanti (`fast_pattern`)
4. Genera:

   * un file compatibile con `hscollider` (Hyperscan)
   * un file `.rules` contenente solo le regole effettivamente utilizzate

---

## 📥 Input

Il programma deve accettare:

* `input.pcap` → file di traffico di rete
* `suricata.rules` → file contenente regole Suricata

---

## 🔍 FASE 1 — Analisi del PCAP

### Requisiti

Effettuare parsing del file `.pcap` (usare librerie come `libpcap`).

### Metriche richieste

1. **Protocolli applicativi** (con percentuali):

   * HTTP
   * HTTPS
   * DNS
   * altri se identificabili

   Output esempio:

   ```
   HTTP: 60%
   DNS: 20%
   HTTPS: 10%
   OTHER: 10%
   ```

2. **Statistiche di rete**:

   * Numero di flussi TCP
   * Numero di pacchetti UDP
   * Numero di pacchetti IP totali

### Note tecniche

* Identificazione protocolli via:

  * porte (80, 443, 53)
  * DPI base (opzionale ma consigliato)
* Flussi TCP identificati tramite 5-tuple:

  ```
  src_ip, dst_ip, src_port, dst_port, protocol
  ```

---

## 🧠 FASE 2 — Selezione protocolli rilevanti

### Regola

* Selezionare i protocolli che rappresentano **≥ 50% del traffico totale**
* Se un singolo protocollo supera il 50%, usare solo quello
* Altrimenti combinare i più rilevanti fino a raggiungere ≥ 50%

---

## 📜 FASE 3 — Parsing regole Suricata

### Obiettivo

Estrarre solo le regole rilevanti per i protocolli selezionati.

### Filtri da applicare

1. **Protocollo compatibile**:

   * Se protocollo target è HTTP:

     * includere regole:

       * `http`
       * `tcp`
       * `ip`

2. **Solo regole con `fast_pattern`**

3. **Escludere regole con contatori/stateful**, ad esempio:

   * `threshold`
   * `limit`
   * `detection_filter`
   * `flowbits`
   * `flowint`

---

## 🧩 FASE 4 — Estrazione Pattern

Per ogni regola valida:

### Estrarre:

* `content`
* flag:

  * `nocase`
  * `offset`
  * `depth`
  * `distance`
  * `within`

### Nota

* Se più `content`, scegliere quello marcato come `fast_pattern`
* Se non specificato esplicitamente, ignorare la regola

---
## ⚙️ FASE 5 — Generazione file per Hyperscan

### Obiettivo

Generare un file `patterns.hs` compatibile con gli strumenti Hyperscan (es. `hscollider`), dove ogni riga rappresenta **un pattern derivato da una regola Suricata**.

---

## 📌 Formato obbligatorio

Ogni riga deve rispettare ESATTAMENTE il formato:

```
<id>:/<regex>/<flags>{<extended_parameters>}
```

### Esempio valido:

```
1:/GET \/index\.html/i
2:/\x16\x03\x01/
3:/POST/i{min_offset=0,max_offset=100}
```

---

## ⚠️ Vincoli fondamentali

* Ogni regola → **1 solo pattern**
* Deve essere usato **solo il `content` marcato `fast_pattern`**
* Se:

  * non esiste `fast_pattern`
  * oppure non è convertibile
    → **scartare la regola**

---

## 🔄 Conversione Suricata → Hyperscan

### 1. Estrazione `content`

#### ASCII

Suricata:

```
content:"GET /index.html"
```

Output regex:

```
GET \/index\.html
```

#### Regole:

* Escape caratteri regex:

  ```
  . * + ? ( ) [ ] { } | ^ $ \ /
  ```
* NON racchiudere tra virgolette

---

#### Binario

Suricata:

```
content:"|16 03 01|"
```

Output:

```
\x16\x03\x01
```

---

### 2. Flag

Convertire SOLO i flag supportati:

| Suricata | Hyperscan flag     | Output |
| -------- | ------------------ | ------ |
| `nocase` | `HS_FLAG_CASELESS` | `i`    |

#### Nota:

* Se nessun flag → `/pattern/` (senza flag)
* NON aggiungere flag non necessari

---

### 3. Extended Parameters

Formato:

```
{key=value,key=value}
```

#### Mapping obbligatorio:

| Suricata     | Hyperscan      | Note              |
| ------------ | -------------- | ----------------- |
| `offset:X`   | `min_offset=X` | posizione minima  |
| `depth:Y`    | `max_offset=Y` | posizione massima |
| `startswith` | `min_offset=0` | match dall’inizio |

#### NON supportati → IGNORARE:

* `distance`
* `within`
* `relative`
* `pcre` options avanzate

---

### 4. Costruzione finale

Ordine:

```
<id>:/<regex>/<flags>{parametri}
```

#### Esempio completo

Suricata:

```
alert http any any -> any any (content:"GET"; nocase; fast_pattern; offset:0; depth:10;)
```

Output:

```
1:/GET/i{min_offset=0,max_offset=10}
```

---

## 🚫 Regole da scartare

Scartare se:

* manca `fast_pattern`
* contiene solo `pcre` senza `content`
* pattern vuoto
* parsing fallisce
* opzioni incompatibili con Hyperscan

---

## 🔢 Gestione ID

* ID intero incrementale
* Unico per ogni pattern
* Partenza da `1`


## 📄 Output finale

File: `patterns.hs`

* una riga per pattern
* solo pattern validi
* conforme al formato ufficiale Hyperscan

---

## 🔚 Fine FASE 5
---

## 📄 FASE 6 — Generazione regole filtrate

### Output file: `filtered.rules`

Contiene:

* solo le regole effettivamente usate
* stesso formato Suricata originale

---

## 🧱 Architettura suggerita

### Moduli

* `pcap_analyzer.c`
* `protocol_detector.c`
* `rules_parser.c`
* `pattern_extractor.c`
* `hyperscan_formatter.c`
* `main.c`

---

## 📚 Librerie consigliate

* `libpcap`
* parser manuale per Suricata (no dependency esterne)

---

## ⚠️ Edge Cases

* PCAP vuoto → errore
* Nessun protocollo ≥50% → fallback sui top N
* Regole malformate → skip
* Pattern binari → gestire correttamente encoding

---

## 🚀 Output finale

Il programma deve produrre:

1. `patterns.hs`
2. `filtered.rules`
3. stampa a terminale statistiche traffico

---

## 💡 Extra (opzionale ma consigliato)

* CLI arguments:

  ```
  ./analyzer input.pcap suricata.rules
  ```

* Logging verbose

* Supporto JSON output

---

## 🔚 Fine specifica

Generare codice C completo, modulare, compilabile con `gcc` tramite Makefile.

