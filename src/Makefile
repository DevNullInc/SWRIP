CC      = gcc
PROF    = 
NOCRYPT =
# Uncomment for MCCP support
# DBUGFLG = -DMCCP
C_FLAGS = -g3 -Wall $(PROF) $(NOCRYPT) $(DBUGFLG)
L_FLAGS = $(PROF) -lcrypt -lz

O_FILES = act_comm.o act_info.o act_move.o act_obj.o act_wiz.o boards.o \
          build.o clans.o comm.o comments.o const.o db.o fight.o \
          handler.o hashstr.o id.o interp.o magic.o makeobjs.o \
          misc.o mud_comm.o mud_prog.o krearena.o player.o requests.o \
          reset.o save.o shops.o skills.o special.o tables.o track.o update.o \
          space.o space2.o bounty.o swskills.o alias.o grub.o mapper.o templateparse.o trivia.o

H_FILES = mud.h bet.h

all: swrip
	@mkdir -p ../bin
	@mv swrip ../bin/swrip

swrip: $(O_FILES)
	$(CC) -o swrip $(O_FILES) $(L_FLAGS) -lm

%.o: %.c $(H_FILES)
	$(CC) -c $(C_FLAGS) $<

clean:
	rm -f $(O_FILES)
