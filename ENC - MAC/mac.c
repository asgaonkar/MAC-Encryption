#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include "md5.h"

char pass[4]; //4 character key

//variables from encrypt.c
MD5_CTX mdContext;
int buf, n, infile, outfile;
int key;

//variables from hash.c
int *pass_pointer, *tmp;
int m, hash_result, *tmp;

//final encryption output string
char final[1024];

check_pw(char * pass)
{
  int i = 0;
  for (i=0;i<4;i++) {
       if (!(((pass[i] >= 'a') && (pass [i] <= 'z'))
             || ((pass[i] >= 'A') && (pass [i] <= 'Z'))
             || ((pass[i] >= '0') && (pass [i] <= '9')))) {
                   printf("Password not as per specifications\n");
                   exit(0);
       };
  };
};

encrypt(char *name, int key)
{
  struct stat st;
  int size,i,j;
  int *temp, result;
  int rollingkey;
  // priliminaries, get files ready and sized
  infile = open (name, O_RDONLY);
  if (infile<0) { printf("input file %s open error\n", name); exit(0); }

  outfile = open ("output", O_RDWR|O_CREAT|O_TRUNC, 0700);
  if (outfile<0) { printf("Cannot access file: output\n"); exit(0); }

  stat(name, &st); size = st.st_size;
  if (size <4) {printf("input file too small\n"); exit(0);};
  //write(outfile,&size,4); // write input file size to output

  // do the encryption, buf contains plaintext, and rollingkey contains key
  buf = 0;
  rollingkey = key;
  printf("Key: %x\n", rollingkey);
  while ((n = read(infile, &buf, 4)) > 0 ) {
         buf = buf ^ rollingkey; //XOR with key, and put ciphertext in buf
         //printf("Buffer ^ RollKey: %x\n", buf);
   MD5Init(&mdContext);  // compute MD5 oprintf(result);f rollingkey
   MD5Update(&mdContext, &rollingkey, 4);
   MD5Final(&mdContext);
   temp = (int *) &mdContext.digest[12];
   result = *temp; // result is 32 bits of MD5 of buf
   //printf("%x\n", result);

   rollingkey = rollingkey ^ result; // new key
   write(outfile, &buf, 4);  // write ciphertext
   buf = 0; // rinse and repeat
  };
  close(infile); close(outfile);
  return(size);
};

hash_enc(char *name, int key_hash) {
  infile = open (name, O_RDONLY);
  if (infile<0) { printf("input file %s open error\n", name); exit(0); }

  while ((n = read(infile, &buf, 4)) > 0 ) {
    //printf("Buffer: %x\n", buf);
    pass_pointer = (int *) buf;

    MD5Init(&mdContext);  // compute MD5 of password
    MD5Update(&mdContext, &pass_pointer, 4);
    MD5Final(&mdContext);

    tmp = (int *) &mdContext.digest[12];
    hash_result = *tmp; // result is 32 bits of MD5 -- there is a BUG here, oh well.

    //printf("HASH: %x\n", hash_result); // print a human readable version of hash (using hex conversion)
    key_hash = key_hash ^ hash_result;
  }
  close(infile);
  return key_hash;
}

main(int argc, char *argv[]) {

    if (argc!= 3) {printf("Usage: %s <filename\\filepath> <key>\n", argv[0]); exit(0);};

    sscanf(argv[2], "%x", &key);
    encrypt(argv[1], key);
    //printf("%s\n", final);
    //printf("%lu\n", strlen(final));
    //printf("%lu\n", strlen(key));
    //strncat(key, final, 1024);
    //printf("%lu\n", strlen(key));
    //printf("%s\n", key);
    //HASH OF KEY
    pass_pointer = (int *) key; // get an int pointer to the key store
    //check_pw(key); //sanity check
    MD5Init(&mdContext);  // compute MD5 of password
    MD5Update(&mdContext, &pass_pointer, 4);
    MD5Final(&mdContext);
    tmp = (int *) &mdContext.digest[12];
    hash_result = *tmp; // result is 32 bits of MD5 -- there is a BUG here, oh well.

    //printf("HASH OF KEY: %x\n", hash_result); // print a human readable version of hash (using hex conversion)

    hash_result = hash_enc("output", hash_result);
    printf("FINAL MAC: %x\n", hash_result);
}
