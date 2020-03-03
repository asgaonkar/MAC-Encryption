
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include "md5.h"

// input : ./prog filename

int key; // symmetric key
int buf, n, infile, outfile;

MD5_CTX mdContext;  // needed to compute MD5

encrypt(char *name)
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
  while ((n = read(infile, &buf, 4)) > 0 ) {
         buf = buf ^ rollingkey; //XOR with key, and put ciphertext in buf
   MD5Init(&mdContext);  // compute MD5 of rollingkey
   MD5Update(&mdContext, &rollingkey, 4);
   MD5Final(&mdContext);
   temp = (int *) &mdContext.digest[12];
   result = *temp; // result is 32 bits of MD5 of buf

   rollingkey = rollingkey ^ result; // new key
   write(outfile, &buf, 4);  // write ciphertext
   buf = 0; // rinse and repeat
  };
  close(infile); close(outfile);
  return(size);
};

mykeygen() // generate a key, from system entropy
{
  int fd = open("/dev/urandom", O_RDONLY);
  read(fd, &buf, 4);
  return(buf);
}

main(int argc, char *argv[])
{
 if (argc!= 3) {printf("Usage: %s <filename> <key>\n", argv[0], argv[1]); exit(0);};


 sscanf(argv[2], "%x", &key);
 printf ("Key (HEX): %x  <needed for decryption>\n", key);
 printf ("Key (HEX): %d  <needed for decryption>\n", key);



 encrypt(argv[1]); // encrypt input file and place in "output"
};
