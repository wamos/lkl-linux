#pragma once

int printf(const char *f, ...);

typedef unsigned long long ticks_t;

static inline ticks_t rdtsc(void) {
  ticks_t a, d;
  __asm__ volatile ("rdtsc" : "=a" (a), "=d" (d));
  return (d<<32) | a;
}

struct trace_context {
  const char *function;
  const char *filename;
  const unsigned line;
  unsigned long frequency;
  unsigned long counter;
  ticks_t start_cycles;
};

struct trace_data {
  struct trace_context *ctx;
  unsigned long cycles;
  unsigned long frequency;
};

static void trace_time_print(struct trace_data *t) {
  struct trace_context *ctx = t->ctx;

  if (ctx->counter % ctx->frequency == 0) {
    printf("%s() at %s:%d: cycles: %lld\n", ctx->function, ctx->filename,
           ctx->line, rdtsc() - t->cycles);
  }
  // FIXME: not thread-safe
  ctx->counter++;
}

static void trace_calls_print(struct trace_data *t) {
  struct trace_context *ctx = t->ctx;
  ticks_t diff;
  ticks_t cycles = rdtsc();

  if (!ctx->start_cycles) {
    ctx->start_cycles = rdtsc();
    return;
  }

  diff = cycles - ctx->start_cycles;

  if (diff > ctx->frequency) {
    printf("%s() at %s:%d: calls/cycles: %lu/%lu\n", ctx->function, ctx->filename, ctx->line, ctx->counter, diff);
    ctx->start_cycles = cycles;
    ctx->counter = 0;
  }

  // FIXME: not thread-safe
  ctx->counter++;
}

#define TRACE_TIME(freq) \
  static struct trace_context __trace_ctx = { \
    .start_cycles = 0, \
    .counter = 0, \
    .frequency = (freq), \
    .function = __func__, \
    .filename = __FILE__, \
    .line = __LINE__, \
  }; \
  struct trace_data __attribute__((__cleanup__(trace_time_print))) __trace_data = { \
    .ctx = &__trace_ctx, \
    .cycles = rdtsc(), \
  };

#define TRACE_CALL_PER_CYCLE(freq) { \
    static struct trace_context __trace_ctx_2 = { \
      .start_cycles = 0, \
      .counter = 1,  \
      .frequency = (freq), \
      .function = __func__, \
      .filename = __FILE__, \
      .line = __LINE__, \
    }; \
    struct trace_data __attribute__((__cleanup__(trace_calls_print))) __trace_data = { \
      .ctx = &__trace_ctx_2, \
      .cycles = 0, \
    }; \
  }
