#pragma once

int printf(const char* f,...);

static inline int64_t rdtsc_s(void)
{
  unsigned a, d; 
  asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
  asm volatile("rdtsc" : "=a" (a), "=d" (d)); 
  return ((unsigned long)a) | (((unsigned long)d) << 32); 
}

static inline int64_t rdtsc_e(void)
{
  unsigned a, d; 
  asm volatile("rdtscp" : "=a" (a), "=d" (d)); 
  asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
  return ((unsigned long)a) | (((unsigned long)d) << 32); 
}

struct trace_context {
  unsigned long trace_counter;
  unsigned long frequency;
  const char *function;
  const char *filename;
  int line;
};

struct trace_data {
  struct trace_context *ctx;
  unsigned long cycles;
  unsigned long frequency;
};

static void trace_print(struct trace_data *t) {
  struct trace_context *ctx = t->ctx;

  if (ctx->trace_counter % t->frequency == 0) {
    printf("%s() at %s:%d: cycles: %lld\n", ctx->function, ctx->filename,
           ctx->line, rdtsc_e() - t->cycles);
  }
  // FIXME: not thread-safe
  ctx->trace_counter++;
}

#define TRACE_FUNC(freq) \
  static struct trace_context __trace_ctx = { \
    .trace_counter = 0,  \
    .frequency = (freq), \
    .function = __func__, \
    .filename = __FILE__, \
    .line = __LINE__, \
  }; \
  struct trace_data __attribute__((__cleanup__(trace_print))) __trace_data = { \
    .ctx = &__trace_ctx, \
    .cycles = rdtsc_s(), \
    .frequency = (freq), \
  };
