#ifndef __ATTACK_H
#define __ATTACK_H

#include  <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <complex.h>
#include <gmp.h>

#include  <signal.h>
#include  <unistd.h>
#include  <fcntl.h>

#include <openssl/aes.h>

uint8_t mul_const(uint8_t t, int x);

uint8_t getByteVal(double* cor, double *max );

void printTrace(uint8_t* state);

void printState(const uint8_t state[16]);

void collectMeasurements(uint8_t* m, uint8_t* c, uint8_t* traces);

void increaseSample(uint8_t* m, uint8_t* c, uint8_t* traces);

void testKey(const uint8_t* m, const uint8_t* c, const uint8_t k[16]);

void computeCorelation(uint8_t* ham, uint8_t* traces, double* cor);

void calculateV(int index, uint8_t* v, const uint8_t* m);

void getHammingWeights(uint8_t* ham, const uint8_t* v);

int hammingWeight(uint8_t x);

double corelation(const uint8_t* x, const uint8_t* y);

#endif
