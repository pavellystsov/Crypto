#include <iostream>
#include <string>
#include <cstdlib>
#include <unistd.h>

#include "Modules/AES.h"
#include "Modules/DES.h"
#include "Modules/RC2.h"
#include "Modules/RC5.h"
#include "Modules/RC6.h"
#include "Modules/GOST.h"
#include "Modules/BLOW.h"
#include "Modules/TWO.h"
#include "Modules/SERP.h"
#include "Modules/CAM.h"

using namespace std;
using namespace CryptoPP;

int main ()
{
  unsigned op, cip;
  string FIn, FOut, Pass;

  do
  {
      cout << "\nEnter the operation (0 - exit, 1 - encrypt, 2 - decrypt): ";
      cin >> op;

      if (op != 0)
      {
        cout << "\nAvailable algorithms: " << endl;
        cout << "|\t1\tAES-256\t\t\t|" << endl;
        cout << "|\t2\tDES\t\t\t|" << endl;
        cout << "|\t3\tRC2\t\t\t|" << endl;
        cout << "|\t4\tRC5\t\t\t|" << endl;
        cout << "|\t5\tRC6\t\t\t|" << endl;
        cout << "|\t6\tGOST-89\t\t\t|" << endl;
        cout << "|\t7\tBlowfish\t\t|" << endl;
        cout << "|\t8\tTwofish\t\t\t|" << endl;
        cout << "|\t9\tSerpent\t\t\t|" << endl;
        cout << "|\t10\tCamellia\t\t|\n" << endl;

        cout << "Choose algorithm and enter the number: ";
        cin >> cip;
      }

      if (op > 2)
      {
        cerr << "Error! Invalid operation\n";
      }

      else if (op > 0)
      {
        cout << "\nEnter a path to input file: ";
        cin >> FIn;

        cout << "\nEnter a path to output file: ";
        cin >> FOut;

        cout << "\nEnter a password: ";
        cin >> Pass;

        if (cip == 1)
        {
          AES_Cryptor aes(FIn, FOut, Pass);

          if (op == 1)
          {
            if (aes.AES_Encrypt())
              cout << "Successfull encrypting!" << endl;
            else
              cout << "Encryption failed!" << endl;
          } else {
            if (aes.AES_Decrypt())
              cout << "Successfull decrypting!" << endl;
            else
              cout << "Decryption failed!" << endl;
          }
        }

        else if (cip == 2)
        {
          DES_Cryptor des(FIn, FOut, Pass);

          if (op == 1)
          {
            if (des.DES_Encrypt())
              cout << "Successfull encrypting!" << endl;
            else
              cout << "Encryption failed!" << endl;
          } else {
            if (des.DES_Decrypt())
              cout << "Successfull decrypting!" << endl;
            else
              cout << "Decryption failed!" << endl;
          }
        }

        else if (cip == 3)
        {
          RC2_Cryptor rc2(FIn, FOut, Pass);

          if (op == 1)
          {
            if (rc2.RC2_Encrypt())
              cout << "Successfull encrypting!" << endl;
            else
              cout << "Encryption failed!" << endl;
          } else {
            if (rc2.RC2_Decrypt())
              cout << "Successfull decrypting!" << endl;
            else
              cout << "Decryption failed!" << endl;
          }
        }

        else if (cip == 4)
        {
          RC5_Cryptor rc5(FIn, FOut, Pass);

          if (op == 1)
          {
            if (rc5.RC5_Encrypt())
              cout << "Successfull encrypting!" << endl;
            else
              cout << "Encryption failed!" << endl;
          } else {
            if (rc5.RC5_Decrypt())
              cout << "Successfull decrypting!" << endl;
            else
              cout << "Decryption failed!" << endl;
          }
        }

        else if (cip == 5)
        {
          RC6_Cryptor rc6(FIn, FOut, Pass);

          if (op == 1)
          {
            if (rc6.RC6_Encrypt())
              cout << "Successfull encrypting!" << endl;
            else
              cout << "Encryption failed!" << endl;
          } else {
            if (rc6.RC6_Decrypt())
              cout << "Successfull decrypting!" << endl;
            else
              cout << "Decryption failed!" << endl;
          }
        }

        else if (cip == 6)
        {
          GOST_Cryptor go(FIn, FOut, Pass);

          if (op == 1)
          {
            if (go.GOST_Encrypt())
              cout << "Successfull encrypting!" << endl;
            else
              cout << "Encryption failed!" << endl;
          } else {
            if (go.GOST_Decrypt())
              cout << "Successfull decrypting!" << endl;
            else
              cout << "Decryption failed!" << endl;
          }
        }

        else if (cip == 7)
        {
          BLOW_Cryptor b(FIn, FOut, Pass);

          if (op == 1)
          {
            if (b.BLOWFISH_Encrypt())
              cout << "Successfull encrypting!" << endl;
            else
              cout << "Encryption failed!" << endl;
          } else {
            if (b.BLOWFISH_Decrypt())
              cout << "Successfull decrypting!" << endl;
            else
              cout << "Decryption failed!" << endl;
          }
        }

        else if (cip == 8)
        {
          Twofish_Cryptor b(FIn, FOut, Pass);

          if (op == 1)
          {
            if (b.Twofish_Encrypt())
              cout << "Successfull encrypting!" << endl;
            else
              cout << "Encryption failed!" << endl;
          } else {
            if (b.Twofish_Decrypt())
              cout << "Successfull decrypting!" << endl;
            else
              cout << "Decryption failed!" << endl;
          }
        }

        else if (cip == 9)
        {
          Serpent_Cryptor s(FIn, FOut, Pass);

          if (op == 1)
          {
            if (s.Serpent_Encrypt())
              cout << "Successfull encrypting!" << endl;
            else
              cout << "Encryption failed!" << endl;
          } else {
            if (s.Serpent_Decrypt())
              cout << "Successfull decrypting!" << endl;
            else
              cout << "Decryption failed!" << endl;
          }
        }

        else if (cip == 10)
        {
          Camellia_Cryptor c(FIn, FOut, Pass);

          if (op == 1)
          {
            if (c.Camellia_Encrypt())
              cout << "Successfull encrypting!" << endl;
            else
              cout << "Encryption failed!" << endl;
          } else {
            if (c.Camellia_Decrypt())
              cout << "Successfull decrypting!" << endl;
            else
              cout << "Decryption failed!" << endl;
          }
        }

        else
        {
          cerr << "Error! Incorrect algorithm number!!!\n";
        }
      }

  } while (op != 0);

  return 0;
}
