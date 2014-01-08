FLAGS = -g -Wall -Wextra -pedantic -pipe -Wno-unused-parameter -D_GNU_SOURCE -std=c99 -pthread -DBUILDING_GJOLL -DORDO_STATIC_LIB

BINDIR = bin
OBJDIR = obj
INCLUDE = include
SRCDIR = src

LIBUV_INCLUDE = libuv/include
ORDO_INCLUDE = ordo/include
LIBUV_LIB = libuv/.libs/libuv.a
ORDO_LIB = ordo/build/libordo_s.a

LD_FLAGS = -pthread $(LIBUV_LIB) $(ORDO_LIB)

SRC = $(wildcard $(SRCDIR)/*.c)
OBJ = $(notdir $(SRC:.c=.o))
OBJ := $(addprefix $(OBJDIR)/, $(OBJ))

ifeq ($(shared), 1)
    LIB = bin/libgjoll.so
    FLAGS += -fpic
else
    LIB = bin/libgjoll.a
    AR ?= ar
endif

OBJDIR_D = obj/daemon
SRCDIR_D = src/daemon
SRC_D = $(wildcard $(SRCDIR_D)/*.c)
OBJ_D = $(notdir $(SRC_D:.c=.o))
OBJ_D := $(addprefix $(OBJDIR_D)/, $(OBJ_D))
EXEC_D = $(BINDIR)/gjoll

all: libuv ordo lib daemon

lib: $(LIB)

daemon: $(EXEC_D)

test: lib
	cd test && make

$(OBJDIR):
	mkdir -p $@

$(OBJDIR_D):
	mkdir -p $@

$(BINDIR):
	mkdir $@

$(LIBDIR):
	mkdir $@

libuv: $(LIBUV_LIB)

$(LIBUV_LIB):
	cd libuv; sh autogen.sh; ./configure; make

ordo: $(ORDO_LIB)

$(ORDO_LIB):
	cd ordo/build && cmake .. $(ORDO_CONFIG) && make

bin/libgjoll.a: $(BINDIR) $(OBJDIR) $(OBJ)
	$(AR) rcs $@ $(OBJ)

bin/libgjoll.so: $(BINDIR) $(OBJDIR) $(OBJ)
	$(CC) -shared -o $@ $(OBJ) $(LD_FLAGS) $(LD_FLAGS)

$(EXEC_D): $(BINDIR) $(OBJDIR_D) $(OBJ_D) $(LIB)
	$(CC) -o $(EXEC_D) $(OBJ_D) $(FLAGS) $(LD_FLAGS) $(LIB)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -c $< $(FLAGS) -I$(INCLUDE) -I$(LIBUV_INCLUDE) -I$(ORDO_INCLUDE) -o $@

$(OBJDIR_D)/%.o: $(SRCDIR_D)/%.c
	$(CC) -c $< $(FLAGS) -I$(INCLUDE) -I$(LIBUV_INCLUDE) -I$(ORDO_INCLUDE) -o $@

.PHONY: clean
clean:
	rm -fr $(OBJDIR_D)
	rm -fr $(OBJDIR)
	rm -fr $(BINDIR)
	cd test && make clean

.PHONY: cleanall
cleanall: clean
	cd libuv; make clean
	cd ordo/build; make clean
