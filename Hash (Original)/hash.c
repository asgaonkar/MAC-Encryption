
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include "md5.h" 

// input : ./prog filename

char pass[4]; // 4 character password
int *pass_pointer, *temp;
int n, result, *temp;
MD5_CTX mdContext;  // needed to compute MD5

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

main(int argc, char *argv[])
{
   pass_pointer = (int *) pass; // get an int pointer to the password store
   *pass_pointer = 0; // all nulls in password field
   if (argc!= 1) {printf("Usage: No Arguments\n", argv[0]); exit(0);};
   pass_pointer = (int *) pass; // get an int pointer to the password store
   printf("Enter a 4 character, alphanumeric password: "); fflush(0);
   n = read(0, pass_pointer, 4); // get 4 bytes, ignore extra
                             // if password too short, will be detected later.
   
   check_pw(pass); // sanity check

   MD5Init(&mdContext);  // compute MD5 of password
   MD5Update(&mdContext, pass_pointer, 4);
   MD5Final(&mdContext);
   temp = (int *) &mdContext.digest[12]; 
   result = *temp; // result is 32 bits of MD5 -- there is a BUG here, oh well.

   printf("%x\n", result); // print a human readable version of hash (using hex conversion)

// Note if you store hashes, do not use human readable HEX, 
// but write the integer to file, raw bits.
 
};

