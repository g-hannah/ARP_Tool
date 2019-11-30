CC := gcc
WFLAGS := -Wall -Werror
DEBUG := 0

SOURCE_FILES := \
	arptool.c

OBJECT_FILES := ${SOURCE_FILES:.c=.o}

arptool: $(OBJECT_FILES)
	@echo Linking object files
	$(CC) $(WFLAGS) $^ -o arptool

$(OBJECT_FILES): $(SOURCE_FILES)
	@echo Compiling source files
	$(CC) -c $(WFLAGS) $^ -o $@
