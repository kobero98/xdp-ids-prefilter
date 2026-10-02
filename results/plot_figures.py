#!/usr/bin/env python3
"""Rebuild the paper figures from data/summary.csv (no raw logs needed).

  figures/system_loss.{pdf,png}         Fig. "drop": system loss vs offered rate,
                                   NF / mixed / good, DPDK replayer, 20-400 kpps
  figures/mispredict_dpdk.pdf      Fig. "mispredict": mixed traffic, baseline vs
                                   correct (port 80) vs mispredicted (SSH DB, port 22)
  figures/mispredict_tcpreplay.pdf same experiment with the tcpreplay generator

Usage: python3 results/plot_figures.py   (requires matplotlib)
"""
import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
SUMMARY = os.path.join(HERE, "data", "summary.csv")
OUT = os.path.join(HERE, "figures")

HI_RATES = [20000, 40000, 80000, 120000, 160000, 200000, 240000,
            280000, 320000, 350000, 400000]
LO_RATES = [10000, 20000, 40000, 80000, 120000, 160000, 200000, 250000]
C_PLAIN, C_AC, C_MIS = "#dd181f", "#0060ad", "#555555"


def load():
    with open(SUMMARY) as f:
        return {(r["test"], r["variant"], int(r["rate_pps"])): r
                for r in csv.DictReader(f)}


def series(data, test, variant, rates):
    xs, mean, lo, hi = [], [], [], []
    for rate in rates:
        r = data.get((test, variant, rate))
        if not r or r["system_loss_pct_mean"] == "":
            continue
        xs.append(rate / 1000)
        mean.append(float(r["system_loss_pct_mean"]))
        lo.append(float(r["system_loss_pct_min"]))
        hi.append(float(r["system_loss_pct_max"]))
    err = [[m - l for m, l in zip(mean, lo)], [h - m for m, h in zip(mean, hi)]]
    return xs, mean, err


def style(ax, ylabel=True):
    ax.grid(True, ls="--", lw=0.5, color="#b0b0b0", alpha=0.8)
    ax.set_xlabel("Offered load [kpps]")
    if ylabel:
        ax.set_ylabel("System packet loss [%]")
    ax.set_ylim(bottom=0)


def plot_line(ax, data, test, variant, rates, color, marker, label, ls="-"):
    xs, mean, err = series(data, test, variant, rates)
    ax.errorbar(xs, mean, yerr=err, marker=marker, ms=6.5, lw=1.4, ls=ls,
                color=color, label=label, capsize=2.5, elinewidth=0.9)


def fig_system_loss(data):
    fig, axes = plt.subplots(1, 3, figsize=(11.5, 3.4), sharey=True)
    for i, (ax, (test, title)) in enumerate(zip(axes, [
            ("highrate_NF_dpdk", "NF"), ("highrate_mixed_dpdk", "mixed"),
            ("highrate_good_dpdk", "good (SSH)")])):
        plot_line(ax, data, test, "plain", HI_RATES, C_PLAIN, "o", "Suricata (baseline)")
        plot_line(ax, data, test, "ac", HI_RATES, C_AC, "s", "Suricata + XDP AC filter")
        ax.set_title(title, fontsize=11)
        style(ax, ylabel=(i == 0))
    axes[0].legend(fontsize=9, edgecolor="black", fancybox=False)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "system_loss.pdf"))
    fig.savefig(os.path.join(OUT, "system_loss.png"), dpi=130)


def fig_mispredict(data, base, mis, rates, name):
    fig, ax = plt.subplots(figsize=(5.6, 3.4))
    plot_line(ax, data, base, "plain", rates, C_PLAIN, "o", "Suricata (baseline)")
    plot_line(ax, data, mis, "ac", rates, C_MIS, "^",
              "AC filter, mispredicted (good DB, port 22)", ls="--")
    plot_line(ax, data, base, "ac", rates, C_AC, "s",
              "AC filter, correct prediction (mixed DB, port 80)")
    ax.set_title("mixed traffic", fontsize=11)
    style(ax)
    ax.legend(fontsize=8, loc="upper left", edgecolor="black", fancybox=False)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, name))
    fig.savefig(os.path.join(OUT, name.replace(".pdf", ".png")), dpi=130)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    d = load()
    fig_system_loss(d)
    fig_mispredict(d, "highrate_mixed_dpdk", "mispredict_good_on_mixed_dpdk",
                   HI_RATES, "mispredict_dpdk.pdf")
    fig_mispredict(d, "lowrate4_mixed", "mispredict_good_on_mixed",
                   LO_RATES, "mispredict_tcpreplay.pdf")
    print(f"figures written to {OUT}")
