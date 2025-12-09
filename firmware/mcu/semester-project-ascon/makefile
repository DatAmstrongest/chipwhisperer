TARGET = simpleserial-ascon

SRC += simpleserial-ascon.c
SRC += ascon.c

EXTRA_OPTS = NO_EXTRA_OPTS
CFLAGS += -D$(EXTRA_OPTS)

ifeq ($(PLATFORM),)
  $(info No PLATFORM provided - defaulting to CW308_STM32F3)
  PLATFORM = CW308_STM32F3
endif

$(info Building for platform $(PLATFORM))

include ../simpleserial/Makefile.simpleserial

FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc
