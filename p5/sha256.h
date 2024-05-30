/**
@file sha256
@author Ethan Browne, efbrowne
This header file contains all of the prototypes for the sha256.h file. Also contains the SHAState struct
*/

#ifndef SHA256_H
#define SHA256_H

#include "sha256constants.h"
#include <stdlib.h>
#include <stdio.h>

/** Type used to represent a byte. */
typedef unsigned char byte;

/** Type used to represent a 64-bit value. */
typedef unsigned long word64;

/** Number of bits in a byte. */
#define BBITS 8

/** Size of an input block in bytes. */
#define BLOCK_SIZE 64

/** Size of the hash, in words. */
#define HASH_WORDS 8

/** Sigma0 Constant 1*/
#define S0C1 2

/** Sigma0 Constant 2*/
#define S0C2 13

/** Sigma0 Constant 3*/
#define S0C3 22

/** Sigma1 Constant 1*/
#define S1C1 6

/** Sigma1 Constant 2*/
#define S1C2 11

/** Sigma1 Constant 3*/
#define S1C3 25

/** extendMessage Constant for index 1*/
#define INDEX1 1

/** extendMessage Constant for index 2*/
#define INDEX2 2

/** extendMessage Constant for index 3*/
#define INDEX3 3

/** extendMessage and compression Constant for word index*/
#define INDEX4 4

/** extendMessage Constant for Index 16*/
#define INDEX16 16

/** extendMessage and compression Constant for Index 7*/
#define INDEX7 7

/** extendMessage Constant for Index 15*/
#define INDEX15 15

/** extendMessage Constant for Index 18*/
#define INDEX18 18

/** extendMessage Constant for Index 10*/
#define INDEX10 10

/** extendMessage Constant for Index 19*/
#define INDEX19 19

/** extendMessage Constant for Index 17*/
#define INDEX17 17

/** compression Constant for Index 5*/
#define INDEX5 5

/** compression Constant for Index 6*/
#define INDEX6 6

/** digest Constant for end of input*/
#define ENDINPUT 0x80

/** digest Constant for a full byte*/
#define FULLBYTE 0xFF

/** State of the SHA256 algorithm, including bytes of input data
    waiting to be hashed. */
typedef struct {
  /** Input data not yet hashed. */
  byte pending[ BLOCK_SIZE ];

  /** Number of bytes currently in the pending array. */
  int pcount;

  unsigned long total;

  /** Current hash value. */
  word h[ HASH_WORDS ];
} SHAState;

/**
Rotates the given val right by the given number of bits and returns the result
@param val the value to rotate
@param bits the number of bits to rotate by
@return the result of the rotation
*/
word rotate( word val, int bits );

/**
Computes a series of rotations and exclusive ors with param a
@param a the word the function is being computed with
@return the result of the operation
*/
word Sigma0( word a );

/**
Computes a series of rotations and exclusive ors with param e
@param e the word the function is being computed with
@return the result of the operation
*/
word Sigma1( word e );

/**
Computes a series of bitwise ands, ors, and complements and returns the result
@param e word that is used in the comutation
@param f word that is used in the comutation
@param g word that is used in the comutation
@return the result of the computation
*/
word ChFunction( word e, word f, word g );

/**
Computes a series of bitwise ands and ors and returns the result
@param a word that is used in the comutation
@param b word that is used in the comutation
@param c word that is used in the comutation
@return the result of the computation
*/
word MaFunction( word a, word b, word c );

/**
Allocates an instance of SHAState on the heap and initializes its fields
@return the newly allocated struct
*/
SHAState *makeState();

/**
Frees the SHAState struct when it is no longer needed
@param state the struct that is to be freed
*/
void freeState( SHAState *state );

/**
Extends the 64-byte block given in the parameter pending array and stores the 64-word result in the parameter w[] array.
@param pending the block to extend
@param w the list to store the result in
*/
void extendMessage( byte const pending[ BLOCK_SIZE ], word w[ BLOCK_SIZE ] );

/**
Processes a 64 byte blocks in the pending array of state, updating the h[] values in state.
Called by update() as it completes 64-byte blocks for processing. Called once or twice by the digest() function as it adds padding to the end of the input.
@param state what is being updated
*/
void compression( SHAState *state );

/**
Called when new input data is available to be processed.
Function collects input data into 64-byte blocks and processes each block via the compress function
@param state where the updated data goes
@param data the new input data
@param len how many bytes are in the array
*/
void update( SHAState *state, const byte data[], int len );

/**
Called once, after all data has been read from the input and processed by the update() function
Adds padding to the input and processes the last block or two of the input and copies the final hash value to the given hash[] array
@param state the input that is processed from
@param where the final hash value is stored
*/
void digest( SHAState *state, word hash[ HASH_WORDS ] );

#endif
