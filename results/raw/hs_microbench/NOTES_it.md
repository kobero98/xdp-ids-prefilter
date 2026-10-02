# Microbenchmark Hyperscan in-kernel — 2026-07-09

## Protocollo
- Modulo `xdp_regex_module.ko bench=1`: 5 timestamp `ktime_get_ns` per scan in
  `bpf_scan_bytes` → fasi {lookup IDR/RCU/scratch, kernel_fpu_begin, hs_scan,
  kernel_fpu_end}, per-CPU, bucket per lunghezza payload, split match/clean,
  istogramma log2, min/max. Lettura/reset: `/sys/kernel/debug/rex_bench`.
- Overhead clock calibrato a insmod: **48.4 ns/chiamata** (kvm-clock) — già
  sottratto nei numeri qui sotto (1 lettura per fase, 4 sul totale).
- XDP `xdp_prog_kern_timing.c` (+`hs_timing` key3=sum_bytes): totale BPF-side
  attorno alla kfunc → overhead kfunc per differenza.
- DB: block-mode dai 18615 `patterns_empirical.hs` (stessi dell'ACDB), hscollider,
  2.1 MB, AVX2. Policy cattivi id 4321, app_map tcp/80.
- Traffico: mixed_output.pcap (1.437.980 pkt) via tcpreplay --pps dallo slave.
  Run: 2× 5000 pps + 1× 20000 pps, loop 1. Statistiche AZZERATE a ogni run.
- Orchestratore: `evalNet/hs_timing_test.py`. Dati raw in questa directory.

## Qualità della misura
- Popolazione bit-esatta su tutti i run: 748.666 scan (490.464 con payload ≥64 B,
  match 7,3%); rx_missed 0, FPU busy 0.
- Run gemelli 5 kpps: medie entro l'1,5% → riproducibile.
- Outlier max (fino a ~2 ms) = vCPU steal della VM; coda istogramma sottile
  (mediana nella classe 2–4 µs).

## Perché i vecchi numeri (25/6, ~35–54 µs) erano sbagliati
`dat/test_timing`: cpu0-2 davano 1,9–2,6 µs (plausibili), cpu3 54 µs.
Tra il run a 500 e quello a 1000 Mbps cpu3 ha aggiunto solo 1.609 scan su 450k:
la mappa **non veniva mai azzerata** — il 97% del contenuto di cpu3 era spazzatura
storica accumulata da esperimenti precedenti, e l'aggregato (35,5 µs nel run 500)
era dominato da quella. In più: sender pre-fix, macchina satura (rx_missed 0,2–1,1 M),
misura solo BPF-side. Con reset per-run e traffico lento il problema sparisce.

## Risultati (payload reale ≥64 B, corretti dal costo clock)
| | 5 kpps (isolato) | 20 kpps (cache più calda) |
|---|---|---|
| totale medio per scan | 5,9 µs | 5,3 µs |
| hs_scan (fase dominante) | 5,6 µs (95%) | 5,0 µs |
| hs_scan clean-only (avg 1024 B) | 4,4–4,5 µs | 4,1 µs |
| hs_scan matched-only (7,3% scan) | **20 µs** | 15,7 µs |
| costo fisso lookup+FPU | ~270 ns | ~285 ns |
| overhead kfunc+bpf_xdp_pointer | ~210 ns | ~190 ns |
| startup block-scan (scan da 6 B) | ~940 ns | ~610 ns |

Per bucket (5 kpps, clean-only, ns/byte): 64-127B→20; 128-255→22; 256-511→23(!);
512-1023→5,0; 1024-1535→3,9. Marginale sui grandi al netto dello startup: ~3,2 ns/B.
Il bucket 256-511 è caro perché ricco di header HTTP (match rate 33%, molti
candidati da confermare).

## Lettura per il paper (engine selection AC vs HS)
1. **kernel_fpu_begin/end NON è il problema**: 60–130 ns per lato, ~2% del costo.
   L'argomento strutturale va ridimensionato di conseguenza.
2. La struttura del costo HS è: **startup ~0,6–0,9 µs per scan block-mode** +
   marginale basso (~3–4 ns/B su traffico reale; 1,1 ns/B su testo casuale, smoke
   test) + **conferma match molto cara** (matched 15–20 µs vs clean 4–4,5 µs,
   pattern completi + enumerazione di tutti i match, handler_flags=0 come nel
   deployment).
3. Confronto AC (stessi pattern, stesso pcap): ACDB v2+prefiltro 4,71 µs@1500B /
   1,0 µs@256B. A MTU piena HS clean (5,2–5,5 µs) ≈ AC; sui pacchetti piccoli AC
   vince (zero startup); il divario grosso è sul costo per-match e sul contenuto
   match-heavy. Sul TRAFFICO misto reale il vantaggio FDR teorico non ribalta il
   quadro: il collo diventa la fase di conferma, non la scansione.
4. Nota metodologica: questo XDP timing prog NON ha il fix padding tot_len → i
   258k scan da ~6 B (padding ACK) sono misurati a parte nel bucket 0 e danno
   gratis la stima dello startup; escluderli per confronti con l'AC (che li
   escludeva).
