#include "attack.h"

#define minSampleSize   10
#define sampleIncrease  10
#define maxSampleSize   500
#define tSize           1500


FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream
pid_t pid        = 0;    // process ID (of either parent or child) from fork
int   target_raw[ 2 ];   // unbuffered communication: attacker -> attack target
int   attack_raw[ 2 ];   // unbuffered communication: attack target -> attacker
int interactions = 0;
int keyFound = 0;
int keyTries = 0;
int currentSampleSize = 0;

unsigned char s[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
 };

uint8_t mul_const(uint8_t t, int x);
uint8_t getByteVal(double* cor, double *max );
void printTrace(uint8_t* state);

void printState(uint8_t state[16]);
void collectMeasurements(uint8_t* m, uint8_t* c, uint8_t* traces);
void increaseSample(uint8_t* m, uint8_t* c, uint8_t* traces);
void testKey(uint8_t* m, uint8_t* c, uint8_t k[16]);
void computeCorelation(uint8_t* ham, uint8_t* traces, double* cor);
void calculateV(int index, uint8_t* v, uint8_t* m);
void getHammingWeights(uint8_t* ham, uint8_t* v);

double corelation(uint8_t* x, uint8_t* y);
int hammingWeight(uint8_t x);

// use exhausting search to find the remaining bytes
void exhaustSearch(uint8_t key[16], uint8_t wrongBytes[16], uint8_t* c, uint8_t* m){
  for(int i=0; i<16; i++){
    if(wrongBytes[i] == 1){
      wrongBytes[i] = 0;
      for(int j=0; j<256; j++){
        key[i] = j;
        testKey(m, c, key);
        exhaustSearch(key, wrongBytes, c, m);
      }
      wrongBytes[i] = 1;
    }
  }
}

void attack() {
  currentSampleSize = minSampleSize;
  uint8_t key[16];

  uint8_t* m      =  (uint8_t*) malloc(sizeof(uint8_t*)*maxSampleSize*16);
  uint8_t* c      =  (uint8_t*) malloc(sizeof(uint8_t*)*maxSampleSize*16);
  uint8_t* traces =  (uint8_t*) malloc(sizeof(uint8_t*)*maxSampleSize*tSize);

  uint8_t* v      = (uint8_t*) malloc(sizeof(uint8_t*)*256*maxSampleSize);
  uint8_t* ham    = (uint8_t*) malloc(sizeof(uint8_t*)*256*maxSampleSize);
  double* cor      = (double*) malloc(sizeof(double*)*256*tSize);

  uint8_t wrongBytes[16];
  int wrongBytesCount;

  for(int i=0; i<16;i++)
    wrongBytes[i] = 0;

  collectMeasurements(m, c, traces);

  printf("collected power traces for %d messages using first %d traces \n", currentSampleSize, tSize);

  // for each byte in the key
  while ( keyFound == 0){
    printf("\n");
    wrongBytesCount = 0;

    // #pragma omp parallel for firstprivate(v, ham, cor) private(corelationValue) shared(key) schedule(auto)
    for(int keyByteNr=0; keyByteNr<16 ; keyByteNr++){
      double corelationValue = 0;
      // compute intermediate values
      calculateV(keyByteNr, v, m);

      //get hamming weights
      getHammingWeights(ham, v);

      // compute corelations
      computeCorelation(ham, traces, cor);

      // choose best corelation as the best key guess
      key[keyByteNr] = getByteVal(cor, &corelationValue);
      printf("Computing byte number %d = %02X with corelation %f\n", keyByteNr, key[keyByteNr], corelationValue);

      if(corelationValue < 0.5f || corelationValue >= 0.99999f){
        wrongBytes[keyByteNr] = 1;
        wrongBytesCount++;
      }
      else {
        wrongBytes[keyByteNr] = 0;
      }
    }
    testKey(m, c, key);

    printf("%d bytes are probably wrong\n", wrongBytesCount );
    if(wrongBytesCount <= 2){
      printf("do an exhaustive search \n");
      exhaustSearch(key, wrongBytes, c, m);
    }

    increaseSample(m, c, traces);

    printf("key not working!, increased sample size to %d\n", currentSampleSize);
  }

  free(traces);
  free(m);
  free(c);
  free(v);
  free(ham);
  free(cor);
}

// transpose the needed column into an array for easy access
void getTracesColumn(int index, uint8_t* col, uint8_t* traces){
  for(int i=0; i<currentSampleSize; i++){
    col[i] = traces[i*tSize + index];
  }
}

// compute intermediate values
void calculateV(int index, uint8_t* v, uint8_t* m){
  uint8_t plaintext_byte;
  for(int i=0; i<currentSampleSize; i++){
    plaintext_byte = m[i*16 + index];
    for(int keyByteValue=0; keyByteValue<256; keyByteValue++){
      v[keyByteValue*currentSampleSize + i] = s[plaintext_byte ^ keyByteValue];
    }
  }
}

// compute hamming weights of intermediate values
void getHammingWeights(uint8_t* ham, uint8_t* v){
  for(int i=0; i<currentSampleSize; i++)
    for(int j=0; j<256; j++){
      ham[i*256 + j] = hammingWeight(v[i*256 + j]);
    }
}

// cmpute corelation between 2 arrays
double corelation(uint8_t* x, uint8_t* y){
  double xMean=0, yMean=0;

  // compute mean of x
  for(int i=0; i<currentSampleSize; i++){
    xMean += x[i];
    yMean += y[i];
  }
  xMean = xMean/currentSampleSize;
  yMean = yMean/currentSampleSize;

  double top=0;
  double sx = 0, sy = 0, sx2 = 0, sy2 = 0;
  for(int i=0; i<currentSampleSize; i++){
    sx = (x[i]-xMean);
    sy = (y[i]-yMean);
    top += sx * sy;
    sx2 += sx*sx;
    sy2 += sy*sy;
  }
  double check = sqrt(sx2*sy2);
  if(check != 0 )
    return top/check;
  else{
    return 0;
  }
}

// search for the highest corelation
uint8_t getByteVal(double* cor, double *max ){
  *max = 0;
  double maxRow = 0;
  uint8_t row = 0;
  for(int i=0; i< 256; i++){
    maxRow = 0;
    for(int j=0; j< tSize; j++){
      if(maxRow < cor[i*tSize + j])
        maxRow = cor[i*tSize + j];
    }
    if(*max < maxRow){
      row = i;
      *max = maxRow;
      // printf("%f\n", maxR  ow );
    }
  }
  return row;
}

// calculate corelation between the hamming weights and the traces
void computeCorelation(uint8_t* ham, uint8_t* traces, double* cor){
  uint8_t tCol[currentSampleSize];
  for(int i=0; i< 256; i++){
    for(int j=0; j< tSize; j++){
      getTracesColumn(j, tCol, traces);
        cor[i*tSize+j] = corelation( ham+i*currentSampleSize , tCol);
    }
  }
}

// test the key and terminate program if key is correct
void testKey(uint8_t* m, uint8_t* c, uint8_t k[16]){
  uint8_t result[16];
  uint8_t message[16];
  for(int i=0; i<16; i++)
    message[i] = m[i];

  // encrypt message using guessed key
  AES_KEY rk;
  AES_set_encrypt_key( k, 128, &rk );
  AES_encrypt( message, result, &rk );

  // test ciphertexts
  if( !memcmp( result, c, 16 * sizeof( uint8_t ) ) ) {
    printf( "Key found: \n" );
    printState(k);
    printf("key failed attempts %d\n", keyTries);
    printf("interactions with the oracle: %d\n", interactions);
    keyFound = 1;
    exit(EXIT_SUCCESS);
  }
  else{
    keyTries++;
  }
}

// compute the hamming weight of a number
int hammingWeight(uint8_t x){
  int count = 0;
  while(x > 0){
    if(x & 1)
      count++;
    x = x >> 1;
  }
  return count;
}

// interact with the oracle
int interact(const uint8_t* m, uint8_t* s, uint8_t* c){
  int size;
  int dummy;

  // Send      G      to   attack target.
  for(int l=0; l<16; l++){
    fprintf(target_in, "%02X",  m[l]);
  }
  fprintf(target_in,"\n");
  fflush( target_in );

  // read size
  if( 1 != fscanf( target_out, "%d", &size) ) {
    abort();
  }
  // read measurements
  for(int i=0; i<size; i++){
    // printf("%d\n", i);
      if( 1 != fscanf( target_out, ",%d", &dummy )) {
        abort();
      }
      if(i < tSize)
        s[i] = dummy;
  }
  // read ciphertext
  for(int i=0; i<16; i++){
    if( 1 != fscanf( target_out, "%2hhX", &c[i] ) ) {
      abort();
    }
  }

  interactions++;
  return size;
}

// generate random messages for multiple measurements
void generateRandomMessage(uint8_t* m, int size){
  // open file to read random bytes from
  FILE *fp = fopen("/dev/urandom", "r");
  int character;
  for(int i=0; i< size; i++){
    for(int j=0; j<16; j++){
      character = fgetc(fp);
      m[i*16 + j] = character;
    }
  }

  // close file
  fclose(fp);
}

// increase number of messages in the sample set
void increaseSample(uint8_t* m, uint8_t* c, uint8_t* traces){
  currentSampleSize = currentSampleSize + sampleIncrease;

  generateRandomMessage(m+(currentSampleSize-sampleIncrease)*16, sampleIncrease);
  for(int i=currentSampleSize-sampleIncrease; i< currentSampleSize; i++){
    interact(m+i*16, traces+i*tSize, c+i*16);
  }
}

// collect measurements and ciphertexts for multiple random messages
void collectMeasurements(uint8_t* m, uint8_t* c, uint8_t* traces){
    generateRandomMessage(m, currentSampleSize);
    for(int i=0; i< currentSampleSize; i++){
      interact(m+i*16, traces+i*tSize, c+i*16);
    }
}

int main( int argc, char* argv[] ){
  if( pipe( target_raw ) == -1 ) {
    abort();
  }
  if( pipe( attack_raw ) == -1 ) {
    abort();
  }

  switch( pid = fork() ) {
    case -1 : {
      // The fork failed; reason is stored in errno, but we'll just abort.
      abort();
    }

    case +0 : {
      // (Re)connect standard input and output to pipes.
      close( STDOUT_FILENO );
      if( dup2( attack_raw[ 1 ], STDOUT_FILENO ) == -1 ) {
        abort();
      }
      close(  STDIN_FILENO );
      if( dup2( target_raw[ 0 ],  STDIN_FILENO ) == -1 ) {
        abort();
      }

      // Produce a sub-process representing the attack target.
      execl( argv[ 1 ], argv[ 0 ], NULL );

      // Break and clean-up once finished.
      break;
   }

    default : {
      // Construct handles to attack target standard input and output.
      if( ( target_out = fdopen( attack_raw[ 0 ], "r" ) ) == NULL ) {
        abort();
      }
      if( ( target_in  = fdopen( target_raw[ 1 ], "w" ) ) == NULL ) {
        abort();
      }

      // Execute a function representing the attacker.
      // while(keyFound == 0){
        attack();
        printf("futai\n" );
      // }

      // Break and clean-up once finished.
      break;
   }
 }
}

void printState(uint8_t* state){
  for(int i=0; i<16; i++){
    printf("%02X ", state[i]);
    if(i%4 == 3)
      printf("\n");
  }
  printf("\n");
}
