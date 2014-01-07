FLAGS = -g -Wall -Wextra -pedantic -pipe -Wno-unused-parameter -D_GNU_SOURCE -std=c89 -pthread
BIN = bin
OBJDIR = obj
INCLUDE = include
SRCDIR = src
SRC = $(wildcard $(SRCDIR)/*.c)
OBJ = $(notdir $(SRC:.c=.o))
OBJ := $(addprefix $(OBJDIR)/, $(OBJ))
LIB = libgjoll.a

OBJDIR_D = obj/daemon
SRCDIR_D = src/daemon
SRC_D = $(wildcard $(SRCDIR_D)/*.c)
OBJ_D = $(notdir $(SRC_D:.c=.o))
OBJ_D := $(addprefix $(OBJDIR_D)/, $(OBJ_D))
EXEC_D = $(BIN)/gjoll

all: lib daemon

lib: $(LIB)

daemon: $(EXEC_D)

$(OBJDIR):
	mkdir -p $@

$(OBJDIR_D):
	mkdir -p $@

$(BIN):
	mkdir $@

$(LIBDIR):
	mkdir $@

_libuv: libuv/.libs/libuv.a

libuv/.libs/libuv.a:
	cd libuv; sh autogen.sh; ./configure; make

_ordo: ordo/build/libordo_s.a

ordo/build/libordo_s.a:
	cd ordo/build && cmake .. -DARCH=amd64 && make

$(LIB): $(OBJDIR) _libuv _ordo $(OBJ)
	ar rcs $@ $(OBJ)

$(EXEC_D): $(OBJDIR_D) $(OBJ_D) $(BIN) $(LIB)
	gcc -o $(EXEC_D) $(OBJ_D) $(FLAGS) libuv/.libs/libuv.a ordo/build/libordo_s.a $(LIB)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	gcc -c $< $(FLAGS) -I$(INCLUDE) -Ilibuv/include -Iordo/include -o $@

$(OBJDIR_D)/%.o: $(SRCDIR_D)/%.c
	gcc -c $< $(FLAGS) -I$(INCLUDE) -Ilibuv/include -Iordo/include -o $@

clean:
	rm -fr $(OBJDIR_D)
	rm -fr $(OBJDIR)
	rm -fr $(BIN)
	rm -fr $(LIB)

cleanall: clean
	cd libuv; make clean
	cd ordo/build; make clean
