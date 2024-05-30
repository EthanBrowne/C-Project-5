/**
@file sha256
@author Ethan Browne, efbrowne
This file deals with the main functionality of the program. It deals with the hashing and compression
*/

#include "sha256.h"

/**
Rotates the given val right by the given number of bits and returns the result
@param val the value to rotate
@param bits the number of bits to rotate by
@return the result of the rotation
*/
word rotate( word val, int bits )
{ 
    return ((val >> bits) | (val << ((sizeof(word) * BBITS) - bits)));
}

/**
Computes a series of rotations and exclusive ors with param a
@param a the word the function is being computed with
@return the result of the operation
*/
word Sigma0( word a )
{
    return (rotate(a, S0C1) ^ rotate(a, S0C2) ^ rotate(a, S0C3));
}


/**
Computes a series of rotations and exclusive ors with param e
@param e the word the function is being computed with
@return the result of the operation
*/
word Sigma1( word e )
{
    return (rotate(e, S1C1) ^ rotate(e, S1C2) ^ rotate(e, S1C3));
}

/**
Computes a series of bitwise ands, ors, and complements and returns the result
@param e word that is used in the comutation
@param f word that is used in the comutation
@param g word that is used in the comutation
@return the result of the computation
*/
word ChFunction( word e, word f, word g )
{
    return ((e & f) ^ ((~e) & g));
}

/**
Computes a series of bitwise ands and ors and returns the result
@param a word that is used in the comutation
@param b word that is used in the comutation
@param c word that is used in the comutation
@return the result of the computation
*/
word MaFunction( word a, word b, word c )
{
    return ((a & b) ^ (a & c) ^ (b & c));
}

/**
Extends the 64-byte block given in the parameter pending array and stores the 64-word result in the parameter w[] array.
@param pending the block to extend
@param w the list to store the result in
*/
void extendMessage( byte const pending[ BLOCK_SIZE ], word w[ BLOCK_SIZE ] )
{
    // Occurs 16 times (index 0 - 15)
    for (int i = 0; i < BLOCK_SIZE; i+=INDEX4){
        w[i/INDEX4] = pending[i] << (BBITS * INDEX3) | pending[i + INDEX1] << (BBITS * INDEX2) | pending[i + INDEX2] << BBITS | pending[i + INDEX3];
    }
    for (int i = INDEX16; i < BLOCK_SIZE; i++){
        w[i] = w[i - INDEX16] + (w[i - INDEX7] + ((rotate(w[i - INDEX15], INDEX7) ^ rotate(w[i - INDEX15], INDEX18) ^ w[i - INDEX15] >> INDEX3) + (rotate(w[i - INDEX2], INDEX17) ^ rotate(w[i - INDEX2], INDEX19) ^ w[i - INDEX2] >> INDEX10)));
    }
}

/**
Processes a 64 byte blocks in the pending array of state, updating the h[] values in state.
Called by update() as it completes 64-byte blocks for processing. Called once or twice by the digest() function as it adds padding to the end of the input.
@param state what is being updated
*/
void compression( SHAState *state )
{
    word hCopy[ HASH_WORDS ];
    for (int i = 0; i < HASH_WORDS; i++){
        hCopy[i] = state->h[i];
    }

    word w[ BLOCK_SIZE ];
    extendMessage(state->pending, w);
    for (int i = 0; i < BLOCK_SIZE; i++) {
        word newA = Sigma1(state->h[INDEX4]) + ChFunction(state->h[INDEX4], state->h[INDEX5], state->h[INDEX6]) + state->h[INDEX7] + w[i] + constant_k[i];
        state->h[INDEX3] += newA;
        newA += Sigma0(state->h[0]) + MaFunction(state->h[0], state->h[INDEX1], state->h[INDEX2]);
        for (int i = BBITS - 1; i > 0 ; i--){
            state->h[i] = state->h[i - INDEX1];
        }
        state->h[0] = newA;
    }

    for (int i = 0; i < HASH_WORDS; i++){
        state->h[i] += hCopy[i];
    }
}

/**
Allocates an instance of SHAState on the heap and initializes its fields
@return the newly allocated struct
*/
SHAState *makeState()
{
    SHAState *state = malloc(sizeof(SHAState));
    for (int i = 0; i < BBITS; i++){
        state->h[i] = initial_h[i];
    }
    for (int i = 0; i < BLOCK_SIZE; i++){
        state->pending[i] = 0;
    }
    state->pcount = 0;
    state->total = 0;
    return state;
}

/**
Frees the SHAState struct when it is no longer needed
@param state the struct that is to be freed
*/
void freeState( SHAState *state )
{
    free(state);
}

/**
Called when new input data is available to be processed.
Function collects input data into 64-byte blocks and processes each block via the compress function
@param state where the updated data goes
@param data the new input data
@param len how many bytes are in the array
*/
void update( SHAState *state, const byte data[], int len )
{
    state->total += len;
    for (int i = 0; i < len; i++){
        state->pending[state->pcount++] = data[i];
        if (state->pcount == BLOCK_SIZE){
            compression(state);
            state->pcount = 0;
        }
    }
}

/**
Called once, after all data has been read from the input and processed by the update() function
Adds padding to the input and processes the last block or two of the input and copies the final hash value to the given hash[] array
@param state the input that is processed from
@param where the final hash value is stored
*/
void digest( SHAState *state, word hash[ HASH_WORDS ] )
{
    state->pending[state->pcount++] = ENDINPUT;
    //Need to compress twice
    if (state->pcount > BLOCK_SIZE - HASH_WORDS) {
        while (state->pcount < BLOCK_SIZE) {
            state->pending[state->pcount] = 0;
            state->pcount++;
        }
        compression(state);
        state->pcount = 0;
    }

    while (state->pcount < BLOCK_SIZE - BBITS) {
        state->pending[state->pcount] = 0;
        state->pcount++;
    }
    for (int i = BBITS-1; state->pcount < BLOCK_SIZE; state->pcount++) {
        state->pending[state->pcount] = ((state->total * BBITS) >> (i * BBITS)) & FULLBYTE;
        i--;
    }
    compression(state);
    for (int i = 0; i < HASH_WORDS; i++){
        hash[i] = state->h[i];
    } 
}