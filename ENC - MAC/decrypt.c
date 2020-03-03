#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include "md5.h"

// input : ./prog key

unsigned int key;
int buf, n, infile, outfile, outfile_new;
MD5_CTX mdContext;


lastbytes(int outfile, int size, int buf) // magic code for extracting last bytes of encryption without the padding
{
  int i = 0;
  char *last;
  last = (char*) &buf;
  for (i=0;i<size;i++) {write(outfile, &last[i], 1);}
};

decrypt(int key)
{
  struct stat st;
  int size,fsize;
  int *temp, result;
  int rollingkey;
  rollingkey = key;

  infile = open ("output", O_RDONLY);
  if (infile<0) { printf("input open error\n"); exit(0); }

  buf = 0;
  //read(infile,&buf,4);
  //size=buf; // get plaintext size

  // ciphertext has xtra 4 bytes (size) and padding

  stat("output", &st); fsize = st.st_size; // get ciphertext size

  if ((fsize < 4)) {printf("file size sanity check failed\n");};
  size  = fsize;

  int main_size = size - 4;

  //Original
  //if ((fsize < 4)||(size>fsize)||(size<(fsize-4))) {printf("file size sanity check failed\n");};

  outfile = open ("output-dec", O_RDWR|O_CREAT|O_TRUNC, 0700);
  if (outfile<0) { printf("output open error\n"); exit(0); }

  while ((n = read(infile, &buf, 4))> 0) {

      buf = buf ^ rollingkey; // doing the reverse of encrypt
      MD5Init(&mdContext);
      MD5Update(&mdContext, &rollingkey, 4);
      MD5Final(&mdContext);
      temp = (int *) &mdContext.digest[12];
      result = *temp; // result is 32 bits of MD5 of key
      rollingkey = rollingkey ^ result; // new key

      if (size >= 4)
      {
          write(outfile, &buf, 4);
          printf("%x ",buf);
      }
      else lastbytes(outfile, size, buf);

      size -= 4;
      buf = 0;  // repeat, keep track of output size in size.
  };

  FILE *fp;
  fp = fopen("output-dec", "r");
  outfile_new = open ("output-dec-new", O_RDWR|O_CREAT|O_TRUNC, 0700);

  char buff[5];

  printf("\nFile: \n\n");

  while(/*fgets(buff,4,fp)!= NULL*/main_size>=4)
  {
    main_size -= 4;
    fgets(buff,5,fp);
    write(outfile_new, &buff, 4);
    printf("%s",buff);
  }

  printf("\n\n");

  char ch[2], eof[2];

  int check, j;

  for(j=0;j<4;j++)
  {
    fgets(ch,2,fp);
    printf("%d ",ch[0]);
    check = ch[0]-10;
    if(check==0)
      break;
    else
      write(outfile_new, &ch, 1);
  }

  eof[0] = '\n';
  write(outfile_new, &eof, 1);




  if (remove("output-dec") == 0)
  {
    //printf("Deleted successfully");
  }
  else
  {
    //printf("Unable to delete the file");
  }



  if (rename("output-dec-new", "output-dec") == 0)
  {
    //printf("File renamed successfully.\n");
  }
  else
  {
    //printf("Unable to rename files. Please check files exist and you have permissions to modify files.\n");
  }



};

main(int argc, char *argv[])
{
  int key;

  sscanf(argv[1], "%x", &key);
//  printf("%x\n", key);
  decrypt (key);
  printf("\n");
};
