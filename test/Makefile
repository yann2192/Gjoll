FLAGS = -g -Wall -Wextra -pedantic -pipe -Wno-unused-parameter -Wdeclaration-after-statement -D_GNU_SOURCE -std=c99 -pthread -DBUILDING_GJOLL -DORDO_STATIC_LIB

LD_FLAGS = -pthread $(LIBUV_LIB) $(ORDO_LIB) $(LUA_LIB)

OBJDIR = obj
INCLUDE = ../include

LIBUV_INCLUDE = ../libuv/include
ORDO_INCLUDE = ../ordo/include
UTHASH_INCLUDE = ../uthash/src
LUA_INCLUDE = ../lua-5.2.3/src

LIBUV_LIB = ../libuv/.libs/libuv.a
ORDO_LIB = ../ordo/build/libordo_s.a
LUA_LIB = ../lua-5.2.3/src/liblua.a

SRCDIR = src
SRC = $(wildcard $(SRCDIR)/*.c)
OBJ = $(notdir $(SRC:.c=.o))
OBJ := $(addprefix $(OBJDIR)/, $(OBJ))
LIB = ../bin/libgjoll.a
BIN = gjoll_test

all: test

test: $(BIN) run

run: $(BIN)
	./$(BIN)

$(OBJDIR):
	mkdir -p $@

$(BIN): $(OBJDIR) $(OBJ) $(LIB)
	$(CC) -o $(BIN) $(OBJ) $(FLAGS) $(LIB) $(LD_FLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -c $< $(FLAGS) -I$(INCLUDE) -I$(LIBUV_INCLUDE) -I$(ORDO_INCLUDE) -I$(UTHASH_INCLUDE) -I$(LUA_INCLUDE) -o $@

clean:
	rm -fr $(OBJDIR)
	rm -fr $(BIN)
