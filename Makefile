FLAGS = -g -Wall -Wextra -pedantic -pipe -Wno-unused-parameter -Wdeclaration-after-statement -D_GNU_SOURCE -std=c99 -pthread -lm -DBUILDING_GJOLL -DORDO_STATIC_LIB

BINDIR = bin
OBJDIR = obj
INCLUDE = include
SRCDIR = src

LIBUV_INCLUDE = libuv/include
ORDO_INCLUDE = ordo/include
UTHASH_INCLUDE = uthash/src
LUA_INCLUDE = lua-5.2.3/src

LIBUV_LIB = libuv/.libs/libuv.a
ORDO_LIB = ordo/build/libordo_s.a
LUA_LIB = lua-5.2.3/src/liblua.a

LD_FLAGS = $(LIBUV_LIB) $(ORDO_LIB) $(LUA_LIB)

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

OBJDIR_D = obj/gjoll
SRCDIR_D = src/gjoll
SRC_D = $(wildcard $(SRCDIR_D)/*.c)
OBJ_D = $(notdir $(SRC_D:.c=.o))
OBJ_D := $(addprefix $(OBJDIR_D)/, $(OBJ_D))
EXEC_D = $(BINDIR)/gjoll

all: lib daemon

lib: libuv ordo lua $(LIB)

daemon: lib $(EXEC_D)

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

lua: $(LUA_LIB)

$(LUA_LIB):
	#cd lua-5.2.3 && make platform
	@echo 'error, lua is not build'
	@echo 'do: $ cd lua-5.2.3 && make platform'
	exit 1

bin/libgjoll.a: $(BINDIR) $(OBJDIR) $(OBJ)
	$(AR) rcs $@ $(OBJ)

bin/libgjoll.so: $(BINDIR) $(OBJDIR) $(OBJ)
	$(CC) -shared -o $@ $(OBJ) $(LD_FLAGS) $(LD_FLAGS)

$(EXEC_D): $(BINDIR) $(OBJDIR_D) $(OBJ_D) $(LIB)
	$(CC) -o $(EXEC_D) $(OBJ_D) $(FLAGS) $(LIB) $(LD_FLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -c $< $(FLAGS) -I$(INCLUDE) -I$(LIBUV_INCLUDE) -I$(ORDO_INCLUDE) -I$(UTHASH_INCLUDE) -I$(LUA_INCLUDE) -o $@

$(OBJDIR_D)/%.o: $(SRCDIR_D)/%.c
	$(CC) -c $< $(FLAGS) -I$(INCLUDE) -I$(LIBUV_INCLUDE) -I$(ORDO_INCLUDE) -I$(UTHASH_INCLUDE) -I$(LUA_INCLUDE) -o $@

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
	cd lua-5.2.3/src; make clean
