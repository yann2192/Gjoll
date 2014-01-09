FLAGS = -g -Wall -Wextra -pedantic -pipe -Wno-unused-parameter -D_GNU_SOURCE -std=c99 -pthread -DBUILDING_GJOLL -DORDO_STATIC_LIB

LD_FLAGS = -pthread $(LIBUV_LIB) $(ORDO_LIB)

OBJDIR = obj
INCLUDE = ../include
LIBUV_INCLUDE = ../libuv/include
ORDO_INCLUDE = ../ordo/include
LIBUV_LIB = ../libuv/.libs/libuv.a
ORDO_LIB = ../ordo/build/libordo_s.a
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
	#$(CC) -o $(BIN) $(OBJ) $(FLAGS) $(LD_FLAGS) $(LIB)
	$(CC) -o $(BIN) $(OBJ) $(FLAGS) $(LIB) $(LD_FLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -c $< $(FLAGS) -I$(INCLUDE) -I$(LIBUV_INCLUDE) -I$(ORDO_INCLUDE) -o $@

clean:
	rm -fr $(OBJDIR)
	rm -fr $(BIN)
