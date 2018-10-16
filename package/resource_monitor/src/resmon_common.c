/*
 * Copyright (C) 2018 Swift Navigation Inc.
 * Contact: Swift Navigation <dev@swiftnav.com>
 *
 * This source is subject to the license found in the file 'LICENSE' which must
 * be distributed together with this source. All other rights reserved.
 *
 * THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
 */

#define _GNU_SOURCE

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libpiksi/logging.h>
#include <libpiksi/util.h>

#include "resmon_common.h"

#define PROC_MEMINFO "/proc/meminfo"

bool parse_ps_line(const char *line, int start_state, int final_state, line_spec_t *line_specs)
{
  int state = start_state;
  char *tab_ctx = NULL;
  char *line_a = strdupa(line);

  for (char *field = strtok_r(line_a, "\t", &tab_ctx); field != NULL;
       field = strtok_r(NULL, "\t", &tab_ctx)) {

    if (state == final_state) {
      piksi_log(LOG_ERR,
                "%s: found too many fields (in state: %s): %s",
                __FUNCTION__,
                line_specs[state].desc,
                field);
      return false;
    }

    switch (line_specs[state].type) {
    case FT_U16: {
      unsigned long ul_value = 0;
      if (!strtoul_all(10, field, &ul_value)) {
        piksi_log(LOG_ERR,
                  "%s: failed to parse %s value: %s",
                  __FUNCTION__,
                  line_specs[state].desc,
                  field);
        return false;
      }
      *line_specs[state].dst.u16 = (u16)ul_value;
      state = line_specs[state].next;
    } break;

    case FT_U32: {
      unsigned long ul_value = 0;
      if (!strtoul_all(10, field, &ul_value)) {
        piksi_log(LOG_ERR,
                  "%s: failed to parse %s value: %s",
                  __FUNCTION__,
                  line_specs[state].desc,
                  field);
        return false;
      }
      *line_specs[state].dst.u32 = (u32)ul_value;
      state = line_specs[state].next;
    } break;

    case FT_F64: {
      double f64_value = 0;
      if (!strtod_all(field, &f64_value)) {
        piksi_log(LOG_ERR,
                  "%s: failed to parse %s value: %s",
                  __FUNCTION__,
                  line_specs[state].desc,
                  field);
        return false;
      }
      *line_specs[state].dst.f64 = f64_value;
      state = line_specs[state].next;
    } break;

    case FT_STR: {
      strncpy(line_specs[state].dst.str, field, line_specs[state].buflen);
      state = line_specs[state].next;
    } break;

    default: piksi_log(LOG_ERR, "%s: invalid field type", __FUNCTION__); return false;
    }
  }

  if (state != final_state) {
    piksi_log(LOG_ERR,
              "%s: did not find enough fields (last state: %s)",
              __FUNCTION__,
              line_specs[state].desc);
    return false;
  }

  return true;
}

int count_lines(const char *file_path)
{
  FILE *fp = fopen(file_path, "r");

  if (fp == NULL) {
    piksi_log(LOG_ERR, "%s: error opening file: %s", __FUNCTION__, strerror(errno));
    return -1;
  }

  int count = 0;

  for (;;) {
    int ret = fgetc(fp);
    if (ret == EOF) break;
    if (ret == '\n') count++;
  }

  fclose(fp);
  return count;
}

unsigned long fetch_mem_total(void)
{
  char *mem_total_sz = NULL;

  FILE *fp = fopen(PROC_MEMINFO, "r");
  if (fp == NULL) {
    piksi_log(LOG_ERR,
              "%s: unable to open %s: %s (%s:%d)",
              __FUNCTION__,
              PROC_MEMINFO,
              strerror(errno),
              __FILE__,
              __LINE__);
    goto error;
  }

  int rc = fscanf(fp, "MemTotal: %ms", &mem_total_sz);

  if (rc <= 0) {
    piksi_log(LOG_ERR,
              "%s: error reading %s: %s (%s:%d)",
              __FUNCTION__,
              PROC_MEMINFO,
              strerror(errno),
              __FILE__,
              __LINE__);
    goto error;
  }

  unsigned long mem_total = 0;

  if (!strtoul_all(10, mem_total_sz, &mem_total)) {
    piksi_log(LOG_ERR,
              "%s: error reading %s: %s (%s:%d)",
              __FUNCTION__,
              PROC_MEMINFO,
              strerror(errno),
              __FILE__,
              __LINE__);
    goto error;
  }

  fclose(fp);
  free(mem_total_sz);

  return mem_total;

error:
  fclose(fp);
  if (mem_total_sz != NULL) {
    free(mem_total_sz);
  }

  return 0;
}