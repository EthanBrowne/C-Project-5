/**
@file hash
@author Ethan Browne, efbrowne
This file contains the main method and is the highest level of the program
*/

#include "sha256.h"
#include <stddef.h>

/** Number of inputs if no file is given*/
#define NOFILE 1

/** Number of inputs if file is given*/
#define YESFILE 2


/**
The main method
@param argc number of arguements
@param argv list of all of the input
@return if the program was sucessful
*/
int main (int argc, char* argv[])
{
    FILE *fp = NULL;
    if (argc != NOFILE && argc != YESFILE) {
        fprintf(stderr, "usage: hash [input_file]\n");
        exit(EXIT_FAILURE);
    } else if (argc == YESFILE){
        fp = fopen(argv[INDEX1], "rb");
        if (fp == NULL) {
            perror(argv[INDEX1]);
            exit(EXIT_FAILURE);
        }
    } else {
        freopen( NULL, "rb", stdin );
        fp = stdin;
    }
    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    rewind(fp);
    
    SHAState *state = makeState();
    word hash[ HASH_WORDS ];

    byte *list = (byte *)malloc( fileSize * sizeof( byte ) );
    fread(list, sizeof(byte), fileSize, fp);

    update(state, list, fileSize);
    digest(state, hash);
    for (int i = 0; i < HASH_WORDS; i++) {
        printf("%08x", hash[i]);
    }
    printf("\n");
    free(list);
    fclose(fp);
    freeState(state);
    return EXIT_SUCCESS;
}