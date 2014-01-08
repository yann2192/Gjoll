FLAGS = -g -Wall -Wextra -pedantic -pipe -Wno-unused-parameter -D_GNU_SOURCE -std=c99 -pthread
OBJDIR = obj
INCLUDE = ../include
SRCDIR = src
SRC = $(wildcard $(SRCDIR)/*.c)
OBJ = $(notdir $(SRC:.c=.o))
OBJ := $(addprefix $(OBJDIR)/, $(OBJ))
LIB = ../libgjoll.a
BIN = gjoll_test

all: test

test: $(BIN)

$(OBJDIR):
	mkdir -p $@

$(BIN): $(OBJDIR) $(OBJ) $(LIB)
	gcc -o $(BIN) $(OBJ) $(FLAGS) ../libuv/.libs/libuv.a ../ordo/build/libordo_s.a $(LIB)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	gcc -c $< $(FLAGS) -I$(INCLUDE) -Ilibuv/include -Iordo/include -o $@

clean:
	rm -fr $(OBJDIR)
	rm -fr $(BIN)
