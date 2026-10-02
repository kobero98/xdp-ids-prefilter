#ifndef HYPERSCAN_FORMATTER_H
#define HYPERSCAN_FORMATTER_H

#include "pattern_extractor.h"
#include <stdio.h>

/* Convert a Suricata Pattern into one Hyperscan line written to fp.
   id is the incremental pattern id.
   Returns 0 on success, -1 if pattern could not be converted. */
int hs_write_pattern(FILE *fp, int id, const Pattern *pat);

#endif
