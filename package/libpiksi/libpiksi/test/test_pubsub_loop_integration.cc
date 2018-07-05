/*
 * Copyright (C) 2018 Swift Navigation Inc.
 * Contact: Swift Dev <dev@swiftnav.com>
 *
 * This source is subject to the license found in the file 'LICENSE' which must
 * be be distributed together with this source. All other rights reserved.
 *
 * THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <gtest/gtest.h>

#include <libpiksi/util.h>
#include <test_pubsub_loop_integration.h>

struct snd_ctx_s {
  pk_endpoint_t *ept;
  int sent;
};

struct recv_ctx_s {
  pk_endpoint_t *ept;
  int recvd;
  size_t size;
};

#define SEND_BUF_SIZE 4
#define SEND_FLUSH_MS 1

#define SIMPLE_RECV_MSG  "123456789"
#define SIMPLE_RECV_SIZE (100u)

static int test_simple_recv_cb(const u8 *data, const size_t length, void *context)
{
  struct recv_ctx_s *recv_ctx = (struct recv_ctx_s *)context;
  // use expect here because ASSERT fails to compile
  int rc = memcmp(data,
                  SIMPLE_RECV_MSG + (SEND_BUF_SIZE * recv_ctx->recvd),
                  SWFT_MIN(recv_ctx->size, SEND_BUF_SIZE));
  EXPECT_EQ(rc, 0);

  recv_ctx->recvd++;
  recv_ctx->size -= SEND_BUF_SIZE;

  return 0;
}

static void test_timeout_cb(pk_loop_t *loop, void *handle, void *context)
{
  (void)loop;
  (void)handle;
  struct snd_ctx_s *snd_ctx = (struct snd_ctx_s *)context;
  const char *simple_message = SIMPLE_RECV_MSG;
  size_t msg_len = strlen(simple_message);
  // use expect here so that we exit gracefully after the timer expires
  int result = -1;
  size_t offset = 0;
  EXPECT_GT(msg_len, SEND_BUF_SIZE);
  while (msg_len > 0) {
    result = pk_endpoint_send(snd_ctx->ept, (u8 *)&simple_message[offset], SWFT_MIN(msg_len, SEND_BUF_SIZE));
    msg_len -= SWFT_MIN(msg_len, SEND_BUF_SIZE);
    offset += SEND_BUF_SIZE;
    ASSERT_EQ(result, 0);
    if (result == 0) snd_ctx->sent++;
  }
}

static void test_poll_cb(pk_loop_t *loop, void *handle, void *context)
{
  (void)handle;
  struct recv_ctx_s *recv_ctx = (struct recv_ctx_s *)context;

  // use expect here so that we exit gracefully after the timer expires
  EXPECT_EQ(pk_endpoint_receive(recv_ctx->ept, test_simple_recv_cb, recv_ctx), 0);
  if (recv_ctx->recvd > 1) {
    pk_loop_stop(loop);
  }
}

TEST_F(PubsubLoopIntegrationTests, pubsubLoopIntegrationTest)
{
  // this is cleaned up in TearDown
  loop = pk_loop_create();
  ASSERT_NE(loop, nullptr);

  // this is cleaned up in TearDown
  sub_ept = pk_endpoint_create("tcp://127.0.0.1:49010", PK_ENDPOINT_SUB_SERVER);
  ASSERT_NE(sub_ept, nullptr);

  // this is cleaned up in TearDown
  pub_ept = pk_endpoint_create("tcp://127.0.0.1:49010", PK_ENDPOINT_PUB);
  ASSERT_NE(pub_ept, nullptr);

  pk_endpoint_buffer_sends(pub_ept, loop, SEND_FLUSH_MS, SEND_BUF_SIZE);

  struct snd_ctx_s snd_ctx = { .ept = pub_ept, .sent = 0 };
  ASSERT_NE(pk_loop_timer_add(loop, 100, test_timeout_cb, &snd_ctx), nullptr);

  struct recv_ctx_s recv_ctx = { .ept = sub_ept, .recvd = 0, .size = strlen(SIMPLE_RECV_MSG) };
  ASSERT_NE(pk_loop_endpoint_reader_add(loop, recv_ctx.ept, test_poll_cb, &recv_ctx), nullptr);

  pk_loop_run_simple_with_timeout(loop, 1000);

  pk_endpoint_destroy(&pub_ept);
  pk_endpoint_destroy(&sub_ept);

  pk_loop_destroy(&loop);

  ASSERT_GT(recv_ctx.recvd, 0);
  ASSERT_GE(snd_ctx.sent, recv_ctx.recvd);
}

#undef SIMPLE_RECV_MSG
#undef SIMPLE_RECV_SIZE
