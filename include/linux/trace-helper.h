#pragma once

#include <cpuid.h>

int printf(const char *f, ...);

#define INTEL_FAM6_CORE_YONAH		0x0E

#define INTEL_FAM6_CORE2_MEROM		0x0F
#define INTEL_FAM6_CORE2_MEROM_L	0x16
#define INTEL_FAM6_CORE2_PENRYN		0x17
#define INTEL_FAM6_CORE2_DUNNINGTON	0x1D

#define INTEL_FAM6_NEHALEM		0x1E
#define INTEL_FAM6_NEHALEM_G		0x1F /* Auburndale / Havendale */
#define INTEL_FAM6_NEHALEM_EP		0x1A
#define INTEL_FAM6_NEHALEM_EX		0x2E

#define INTEL_FAM6_WESTMERE		0x25
#define INTEL_FAM6_WESTMERE_EP		0x2C
#define INTEL_FAM6_WESTMERE_EX		0x2F

#define INTEL_FAM6_SANDYBRIDGE		0x2A
#define INTEL_FAM6_SANDYBRIDGE_X	0x2D
#define INTEL_FAM6_IVYBRIDGE		0x3A
#define INTEL_FAM6_IVYBRIDGE_X		0x3E

#define INTEL_FAM6_HASWELL		0x3C
#define INTEL_FAM6_HASWELL_X		0x3F
#define INTEL_FAM6_HASWELL_L		0x45
#define INTEL_FAM6_HASWELL_G		0x46

#define INTEL_FAM6_BROADWELL		0x3D
#define INTEL_FAM6_BROADWELL_G		0x47
#define INTEL_FAM6_BROADWELL_X		0x4F
#define INTEL_FAM6_BROADWELL_D		0x56

#define INTEL_FAM6_SKYLAKE_L		0x4E
#define INTEL_FAM6_SKYLAKE		0x5E
#define INTEL_FAM6_SKYLAKE_X		0x55
#define INTEL_FAM6_KABYLAKE_L		0x8E
#define INTEL_FAM6_KABYLAKE		0x9E

#define INTEL_FAM6_CANNONLAKE_L		0x66

#define INTEL_FAM6_ICELAKE_X		0x6A
#define INTEL_FAM6_ICELAKE_D		0x6C
#define INTEL_FAM6_ICELAKE		0x7D
#define INTEL_FAM6_ICELAKE_L		0x7E
#define INTEL_FAM6_ICELAKE_NNPI		0x9D

#define INTEL_FAM6_TIGERLAKE_L		0x8C
#define INTEL_FAM6_TIGERLAKE		0x8D

#define INTEL_FAM6_COMETLAKE		0xA5
#define INTEL_FAM6_COMETLAKE_L		0xA6

/* "Small Core" Processors (Atom) */

#define INTEL_FAM6_ATOM_BONNELL		0x1C /* Diamondville, Pineview */
#define INTEL_FAM6_ATOM_BONNELL_MID	0x26 /* Silverthorne, Lincroft */

#define INTEL_FAM6_ATOM_SALTWELL	0x36 /* Cedarview */
#define INTEL_FAM6_ATOM_SALTWELL_MID	0x27 /* Penwell */
#define INTEL_FAM6_ATOM_SALTWELL_TABLET	0x35 /* Cloverview */

#define INTEL_FAM6_ATOM_SILVERMONT	0x37 /* Bay Trail, Valleyview */
#define INTEL_FAM6_ATOM_SILVERMONT_D	0x4D /* Avaton, Rangely */
#define INTEL_FAM6_ATOM_SILVERMONT_MID	0x4A /* Merriefield */

#define INTEL_FAM6_ATOM_AIRMONT		0x4C /* Cherry Trail, Braswell */
#define INTEL_FAM6_ATOM_AIRMONT_MID	0x5A /* Moorefield */
#define INTEL_FAM6_ATOM_AIRMONT_NP	0x75 /* Lightning Mountain */

#define INTEL_FAM6_ATOM_GOLDMONT	0x5C /* Apollo Lake */
#define INTEL_FAM6_ATOM_GOLDMONT_D	0x5F /* Denverton */

/* Note: the micro-architecture is "Goldmont Plus" */
#define INTEL_FAM6_ATOM_GOLDMONT_PLUS	0x7A /* Gemini Lake */

#define INTEL_FAM6_ATOM_TREMONT_D	0x86 /* Jacobsville */
#define INTEL_FAM6_ATOM_TREMONT 0x96         /* Elkhart Lake */
#define INTEL_FAM6_ATOM_TREMONT_L	0x9C /* Jasper Lake */

/* Xeon Phi */

#define INTEL_FAM6_XEON_PHI_KNL		0x57 /* Knights Landing */
#define INTEL_FAM6_XEON_PHI_KNM		0x85 /* Knights Mill */

static unsigned int intel_model_duplicates(unsigned int model)
{
	switch (model) {
	case INTEL_FAM6_NEHALEM_EP: /* Core i7, Xeon 5500 series - Bloomfield, Gainstown NHM-EP */
	case INTEL_FAM6_NEHALEM: /* Core i7 and i5 Processor - Clarksfield, Lynnfield, Jasper Forest */
	case 0x1F: /* Core i7 and i5 Processor - Nehalem */
	case INTEL_FAM6_WESTMERE: /* Westmere Client - Clarkdale, Arrandale */
	case INTEL_FAM6_WESTMERE_EP: /* Westmere EP - Gulftown */
		return INTEL_FAM6_NEHALEM;

	case INTEL_FAM6_NEHALEM_EX: /* Nehalem-EX Xeon - Beckton */
	case INTEL_FAM6_WESTMERE_EX: /* Westmere-EX Xeon - Eagleton */
		return INTEL_FAM6_NEHALEM_EX;

	case INTEL_FAM6_XEON_PHI_KNM:
		return INTEL_FAM6_XEON_PHI_KNL;

	case INTEL_FAM6_BROADWELL_X:
	case INTEL_FAM6_BROADWELL_D: /* BDX-DE */
		return INTEL_FAM6_BROADWELL_X;

	case INTEL_FAM6_SKYLAKE_L:
	case INTEL_FAM6_SKYLAKE:
	case INTEL_FAM6_KABYLAKE_L:
	case INTEL_FAM6_KABYLAKE:
	case INTEL_FAM6_COMETLAKE_L:
	case INTEL_FAM6_COMETLAKE:
		return INTEL_FAM6_SKYLAKE_L;

	case INTEL_FAM6_ICELAKE_L:
	case INTEL_FAM6_ICELAKE_NNPI:
	case INTEL_FAM6_TIGERLAKE_L:
	case INTEL_FAM6_TIGERLAKE:
		return INTEL_FAM6_CANNONLAKE_L;

	case INTEL_FAM6_ATOM_TREMONT_D:
		return INTEL_FAM6_ATOM_GOLDMONT_D;

	case INTEL_FAM6_ATOM_TREMONT_L:
		return INTEL_FAM6_ATOM_TREMONT;

	case INTEL_FAM6_ICELAKE_X:
		return INTEL_FAM6_SKYLAKE_X;
	}
	return model;
}

// extracted from https://github.com/torvalds/linux/blob/b95fffb9b4afa8b9aa4a389ec7a0c578811eaf42/tools/power/x86/turbostat/turbostat.c
static unsigned long long get_tsc_hz(void)
{
	unsigned int eax_crystal = 0;
	unsigned int ebx_tsc = 0;
	unsigned int crystal_hz = 0;
	unsigned int edx = 0;
	__cpuid(0x15, eax_crystal, ebx_tsc, crystal_hz, edx);
	if (ebx_tsc == 0) {
		return 0;
	}
	unsigned int fms, family, model, ebx, ecx;
	__cpuid(1, fms, ebx, ecx, edx);
	family = (fms >> 8) & 0xf;
	model = (fms >> 4) & 0xf;
	if (family == 0xf)
		family += (fms >> 20) & 0xff;
	if (family >= 6)
		model += ((fms >> 16) & 0xf) << 4;

	model = intel_model_duplicates(model);
	if (crystal_hz == 0) {
		switch (model) {
		case INTEL_FAM6_SKYLAKE_L: /* SKL */
			crystal_hz = 24000000; /* 24.0 MHz */
			break;
		case INTEL_FAM6_ATOM_GOLDMONT_D: /* DNV */
			crystal_hz = 25000000; /* 25.0 MHz */
			break;
		case INTEL_FAM6_ATOM_GOLDMONT: /* BXT */
		case INTEL_FAM6_ATOM_GOLDMONT_PLUS:
			crystal_hz = 19200000; /* 19.2 MHz */
			break;
		default:
			crystal_hz = 0;
		}
	}
	return (unsigned long long)crystal_hz * ebx_tsc / eax_crystal;
}

typedef unsigned long long ticks_t;

static inline ticks_t rdtsc_s(void)
{
	ticks_t a, d;
	asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
	asm volatile("rdtsc" : "=a"(a), "=d"(d));
  return (d<<32) | a;
}

static inline ticks_t rdtsc_e(void)
{
	ticks_t a, d;
	asm volatile("rdtscp" : "=a"(a), "=d"(d));
	asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
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
           ctx->line, rdtsc_e() - t->cycles);
  }
  // FIXME: not thread-safe
  ctx->counter++;
}

static void trace_calls_print(struct trace_data *t) {
  struct trace_context *ctx = t->ctx;
  ticks_t diff;
  ticks_t cycles = rdtsc_e();

  if (!ctx->start_cycles) {
    ctx->start_cycles = rdtsc_s();
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
    .cycles = rdtsc_s(), \
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
