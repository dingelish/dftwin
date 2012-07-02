#
# NSL DFT library (libdft tools)
#
# Columbia University, Department of Computer Science
# Network Security Lab
#
# Vasileios P. Kemerlis (vpk@cs.columbia.edu)
#

# variable definitions
CXXFLAGS	+= -Wall -c -fomit-frame-pointer -std=c++0x -O3	\
		   -fno-strict-aliasing -fno-stack-protector	\
		   -DBIGARRAY_MULTIPLIER=1 -DUSING_XED		\
		   -DTARGET_IA32 -DHOST_IA32 -DTARGET_LINUX	\
		   # -DHUGE_TLB -mtune=core2
CXXFLAGS_SO	+= -Wl,--hash-style=sysv -Wl,-Bsymbolic -shared \
		   -Wl,--version-script=$(PIN_HOME)/source/include/pintool.ver
LIBS		+= -ldft -lpin -lxed -ldwarf -lelf -ldl # -liberty
H_INCLUDE	+= -I../src -I. -I$(PIN_HOME)/source/include	\
		   -I$(PIN_HOME)/source/include/gen		\
		   -I$(PIN_HOME)/extras/xed2-ia32/include	\
		   -I$(PIN_HOME)/extras/components/include
L_INCLUDE	+= -L../src					\
		   -L$(PIN_HOME)/extras/xed2-ia32/lib		\
		   -L$(PIN_HOME)/ia32/lib -L$(PIN_HOME)/ia32/lib-ext
OBJS		= nullpin.o libdft.o libdft-dta.o
SOBJS		= $(OBJS:.o=.so)

# phony targets
.PHONY: all sanity tools clean

# get system information
OS=$(shell uname -o | grep Linux$$)			# OS
ARCH=$(shell uname -m | grep 86$$)			# arch

# default target (build libdft only)
all: sanity tools

# sanity checks (i.e., PIN_HOME, OS, architecture)
sanity:
# check if PIN_HOME variable is defined
ifndef PIN_HOME
	$(error "PIN_HOME environment variable is not set")
endif
# check the OS (must be Linux)
ifeq ($(strip $(OS)),)
	$(error "This version of libdft is for Linux only")
endif
# check the architecture (must be x86, i386, i486, i686, ...)
ifeq ($(strip $(ARCH)),)
	$(error "This version of libdft is for x86 only")
endif


# tools (nullpin, libdft, libdft-dta)
tools: $(SOBJS)

# nullpin
nullpin.so: nullpin.o
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o) $(LIBS)
	strip -s $(@)
nullpin.o: nullpin.c ../src/branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# libdft
libdft.so: libdft.o
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o) $(LIBS)
	strip -s $(@)
libdft.o: libdft.c ../src/branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# libdft-dta
libdft-dta.so: libdft-dta.o
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o) $(LIBS)
	strip -s $(@)
libdft-dta.o: libdft-dta.c ../src/branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# clean (tools)
clean:
	rm -rf $(OBJS) $(SOBJS)
