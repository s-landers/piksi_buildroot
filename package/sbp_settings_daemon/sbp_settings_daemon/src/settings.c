/*
 * Copyright (C) 2016 Swift Navigation Inc.
 * Contact: Gareth McMullin <gareth@swiftnav.com>
 *
 * This source is subject to the license found in the file 'LICENSE' which must
 * be be distributed together with this source. All other rights reserved.
 *
 * THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libpiksi/logging.h>
#include <libpiksi/min_ini.h>

#include <libsbp/settings.h>

#include <libsettings/settings.h>
#include <libsettings/settings_util.h>

#include "settings.h"

#define SETTINGS_FILE "/persistent/config.ini"
#define BUFSIZE 256

struct setting {
  char section[BUFSIZE];
  char name[BUFSIZE];
  char type[BUFSIZE];
  char value[BUFSIZE];
  struct setting *next;
  bool dirty;
};

static struct setting *settings_head;

/* Register a new setting in our linked list */
void setting_register(struct setting *setting)
{
  struct setting *s;

  if (!settings_head) {
    settings_head = setting;
  } else {
    for (s = settings_head; s->next; s = s->next) {
      if ((strcmp(s->section, setting->section) == 0)
          && (strcmp(s->next->section, setting->section) != 0))
        break;
    }
    setting->next = s->next;
    s->next = setting;
  }

  const char *default_value = "{2F9D26FF-F64C-4F9F-94FE-AE9F57758835}";
  char buf[BUFSIZE];

  ini_gets(setting->section, setting->name, default_value, buf, sizeof(buf), SETTINGS_FILE);

  if (strcmp(buf, default_value) != 0) {
    /* Use value from config file */
    strncpy(setting->value, buf, BUFSIZE);
    setting->dirty = true;
  }
}

/* Lookup setting in our linked list */
static struct setting *settings_lookup(const char *section, const char *setting)
{
  for (struct setting *s = settings_head; s; s = s->next)
    if ((strcmp(s->section, section) == 0) && (strcmp(s->name, setting) == 0)) return s;
  return NULL;
}

static void settings_send(sbp_tx_ctx_t *tx_ctx,
                          struct setting *sdata,
                          bool type,
                          bool sbp_sender_id,
                          u16 msg_type,
                          char *buf,
                          u8 offset,
                          size_t blen)
{
  if (sdata == NULL) {
    sdata = &(struct setting){0};
  }

  char l_buf[BUFSIZE] = {0};
  if (buf == NULL) {
    buf = l_buf;
    blen = sizeof(l_buf);
  }

  int res = settings_format(sdata->section,
                            sdata->name,
                            sdata->value,
                            type ? sdata->type : NULL,
                            buf + offset,
                            blen - offset);

  if (res <= 0) {
    piksi_log(LOG_ERR, "Setting %s.%s failed to format", sdata->section, sdata->name);
    return;
  }

  if (sbp_sender_id) {
    sbp_tx_send_from(tx_ctx, msg_type, res + offset, (u8 *)buf, SBP_SENDER_ID);
  } else {
    sbp_tx_send(tx_ctx, msg_type, res + offset, (u8 *)buf);
  }
}

static void setting_register_callback(u16 sender_id, u8 len, u8 msg[], void *context)
{
  (void)sender_id;

  sbp_tx_ctx_t *tx_ctx = (sbp_tx_ctx_t *)context;

  const char *section = NULL, *name = NULL, *value = NULL, *type = NULL;
  /* Expect to find at least section, name and value */
  if (settings_parse(msg, len, &section, &name, &value, &type) < SETTINGS_TOKENS_VALUE) {
    piksi_log(LOG_WARNING, "Error in register message");
  }

  struct setting *sdata = settings_lookup(section, name);
  /* Only register setting if it doesn't already exist */
  if (sdata == NULL) {
    sdata = calloc(1, sizeof(*sdata));
    strncpy(sdata->section, section, BUFSIZE);
    strncpy(sdata->name, name, BUFSIZE);
    strncpy(sdata->value, value, BUFSIZE);

    if (type != NULL) {
      strncpy(sdata->type, type, BUFSIZE);
    }

    setting_register(sdata);
  } else {
    piksi_log(LOG_WARNING, "Setting %s.%s already registered", sdata->section, sdata->name);
  }

  /* Reply with write message with our value */
  settings_send(tx_ctx, sdata, false, true, SBP_MSG_SETTINGS_WRITE, NULL, 0, 0);
}

static void settings_write_reply_callback(u16 sender_id, u8 len, u8 msg_[], void *context)
{
  (void)sender_id;
  (void)context;
  msg_settings_write_resp_t *msg = (void *)msg_;

  if (msg->status != 0) {
    return;
  }

  const char *section = NULL, *name = NULL, *value = NULL;
  /* Expect to find at least section, name and value */
  if (settings_parse(msg->setting, len - sizeof(msg->status), &section, &name, &value, NULL)
      < SETTINGS_TOKENS_VALUE) {
    piksi_log(LOG_WARNING, "Error in write reply message");
    return;
  }

  struct setting *sdata = settings_lookup(section, name);
  if (sdata == NULL) {
    piksi_log(LOG_WARNING, "Write reply for non-existent setting");
    return;
  }

  if (strcmp(sdata->value, value) == 0) {
    /* Setting unchanged */
    return;
  }

  /* This is an assignment, call notify function */
  strncpy(sdata->value, value, BUFSIZE);
  sdata->dirty = true;

  return;
}

static void settings_read_callback(u16 sender_id, u8 len, u8 msg[], void *context)
{
  sbp_tx_ctx_t *tx_ctx = (sbp_tx_ctx_t *)context;

  if (sender_id != SBP_SENDER_ID) {
    piksi_log(LOG_WARNING, "Invalid sender");
    return;
  }
  
  /* Expect to find at least section and name */
  const char *section = NULL, *name = NULL;
  if (settings_parse(msg, len, &section, &name, NULL, NULL) < SETTINGS_TOKENS_NAME) {
    piksi_log(LOG_WARNING, "Error in write reply message");
    return;
  }

  struct setting *sdata = settings_lookup(section, name);
  if (sdata == NULL) {
    piksi_log(LOG_WARNING,
              "Bad settings read request: setting not found (%s.%s)",
              section,
              name);
    return;
  }

  settings_send(tx_ctx, sdata, false, false, SBP_MSG_SETTINGS_READ_RESP, NULL, 0, 0);
}

static void settings_read_by_index_callback(u16 sender_id, u8 len, u8 msg[], void *context)
{
  sbp_tx_ctx_t *tx_ctx = (sbp_tx_ctx_t *)context;

  if (sender_id != SBP_SENDER_ID) {
    piksi_log(LOG_WARNING, "Invalid sender");
    return;
  }

  struct setting *s = settings_head;
  char buf[256];
  u8 buflen = 0;

  if (len != 2) {
    piksi_log(LOG_WARNING, "Invalid length for settings read by index!");
    return;
  }
  u16 index = (msg[1] << 8) | msg[0];

  for (int i = 0; (i < index) && s; i++, s = s->next)
    ;

  if (s == NULL) {
    sbp_tx_send(tx_ctx, SBP_MSG_SETTINGS_READ_BY_INDEX_DONE, 0, NULL);
    return;
  }

  /* build and send reply */
  buf[buflen++] = msg[0];
  buf[buflen++] = msg[1];
  settings_send(tx_ctx, s, true, false, SBP_MSG_SETTINGS_READ_BY_INDEX_RESP, buf, buflen, sizeof(buf));
}

static void settings_save_callback(u16 sender_id, u8 len, u8 msg[], void *context)
{
  (void)sender_id;
  (void)context;
  (void)len;
  (void)msg;

  FILE *f = fopen(SETTINGS_FILE, "w");
  const char *sec = NULL;

  if (f == NULL) {
    piksi_log(LOG_ERR, "Error opening config file!");
    return;
  }

  for (struct setting *s = settings_head; s; s = s->next) {
    /* Skip unchanged parameters */
    if (!s->dirty) continue;

    if ((sec == NULL) || (strcmp(s->section, sec) != 0)) {
      /* New section, write section header */
      sec = s->section;
      fprintf(f, "[%s]\n", sec);
    }

    /* Write setting */
    fprintf(f, "%s=%s\n", s->name, s->value);
  }

  fclose(f);
}

static void settings_write_reject(sbp_tx_ctx_t *tx_ctx, const char *section, const char *name, const char *value)
{
  if (section != NULL && name != NULL) {
    piksi_log(LOG_ERR, "Setting %s.%s write rejected", section, name);
  } else {
    piksi_log(LOG_ERR, "Setting write rejected");
  }

  /* Reply with write response rejecting this setting */
  int buflen = 0;
  char buf[BUFSIZE] = {0};
  buf[buflen++] = SETTINGS_WR_SETTING_REJECTED;

  int res = settings_format(section,
                            name,
                            value,
                            NULL,
                            buf + buflen,
                            BUFSIZE - buflen);

  if (res <= 0) {
    piksi_log(LOG_WARNING, "Write reject response formatting failed");
  } else {
    buflen += res;
  }

  sbp_tx_send_from(tx_ctx, SBP_MSG_SETTINGS_WRITE_RESP, buflen, buf, SBP_SENDER_ID);
}

static void settings_write_callback(u16 sender_id, u8 len, u8 msg[], void *context)
{
  (void)sender_id;

  sbp_tx_ctx_t *tx_ctx = (sbp_tx_ctx_t *)context;

  const char *section = NULL, *name = NULL, *value = NULL, *type = NULL;
  /* Expect to find at least section, name and value */
  if (settings_parse(msg, len, &section, &name, &value, &type) < SETTINGS_TOKENS_VALUE) {
    settings_write_reject(tx_ctx, section, name, value);
    return;
  }

  struct setting *sdata = settings_lookup(section, name);
  if (sdata == NULL) {
    settings_write_reject(tx_ctx, section, name, value);
    return;
  }

  /* This setting looks good; we'll leave it to the owner to complain if
   * there's a problem with the value. */
  return;
}

void settings_setup(sbp_rx_ctx_t *rx_ctx, sbp_tx_ctx_t *tx_ctx)
{
  sbp_rx_callback_register(rx_ctx, SBP_MSG_SETTINGS_SAVE, settings_save_callback, tx_ctx, NULL);
  sbp_rx_callback_register(rx_ctx, SBP_MSG_SETTINGS_WRITE, settings_write_callback, tx_ctx, NULL);
  sbp_rx_callback_register(rx_ctx,
                           SBP_MSG_SETTINGS_WRITE_RESP,
                           settings_write_reply_callback,
                           tx_ctx,
                           NULL);
  sbp_rx_callback_register(rx_ctx, SBP_MSG_SETTINGS_READ_REQ, settings_read_callback, tx_ctx, NULL);
  sbp_rx_callback_register(rx_ctx,
                           SBP_MSG_SETTINGS_READ_BY_INDEX_REQ,
                           settings_read_by_index_callback,
                           tx_ctx,
                           NULL);
  sbp_rx_callback_register(rx_ctx,
                           SBP_MSG_SETTINGS_REGISTER,
                           setting_register_callback,
                           tx_ctx,
                           NULL);
}

void settings_reset_defaults(void)
{
  unlink(SETTINGS_FILE);
}
