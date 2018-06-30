import hashlib
import scrypt
import bcrypt
from passlib.hash import argon2

import random
import binascii
from timeit import default_timer as timer
import base64
import argparse

algos = ["md5","sha1","sha256","sha512","Whirlpool","RIPEMD160","bcrypt","scrypt","Argon2i"]

random128 = base64.b64encode(base64.b64encode(str(random.getrandbits(128))))
random32 = base64.b64encode(base64.b64encode(str(random.getrandbits(32))))

parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=100),description="Hashlab")
parser.add_argument('-a', '--algo', dest="algo", default="", help="Algorithm to use", type=str)
parser.add_argument('-i', '--iterations',dest="iter", default=4096,help="default 4096",type=int)
parser.add_argument('-l', '--list',dest="list",action="store_true",help="lists all supported algorithms")
parser.add_argument('--base64',dest="b64",action="store_true",help="outputs the hash in base64")
parser.add_argument('--hex',dest="hex",action="store_true",help="outputs the hash in hex")
parser.add_argument('-r', '--blocksize', dest="blocksize", default="1024", help="blocksize of underlying hash function ( memory cost )", type=int)
parser.add_argument('-p', '--parallelism', dest="parallelism", default="32", help="finetunes CPU cost ( argon2 and scrypt ) ", type=int)
parser.add_argument('--size', dest="size", default="32", help="Hashes output size in bits ( should only be use with argon2 and scrypt )", type=int)
parser.add_argument('--string',dest="string",default=random128,help="string that is used for the hash")
parser.add_argument('--salt',dest="salt",default=random32,help="Salt that is used for the hash")


args = parser.parse_args()


# global vars

if args.string:
   keyx = (args.string)
else:
   keyx = random128
if args.salt:
  saltx = (args.salt)
else:
  saltx = random32

algolist = [ "Argon2i","Bcrypt","Scrypt","pbkdf2","md5","sha1","sha256","sha512","whirlpool"]
digest=""


# main

def main():
  if args.list:
      List()
      exit()
  if args.algo == "Argon2i":
      CryptoArgon2i()
      if args.hex:
         Hexdigest()
         exit()
      elif args.b64:
         Base64()
         exit()
      else:
         Bindigest()
         exit()
  
  if args.algo == "Scrypt":
      CryptoScrypt()
      if args.hex:
         Hexdigest()
         exit()
      elif args.b64:
         Base64()
         exit()
      else:
         Bindigest()
         exit()
  elif args.algo == "Bcrypt":
      CryptoBcrypt()
      if args.hex:
         Hexdigest()
         exit()
      elif args.b64:
         Base64()
         exit()
      else:
         Bindigest()
         exit()
  elif args.algo == "pbkdf2":
      CryptoPbkdf2()
      if args.hex:
         Hexdigest()
         exit()
      elif args.b64:
         Base64()
         exit()
      else:
         Bindigest()
         exit()
  else:
    for algo in algolist:
     if args.algo == algo:
       CryptoCasual()
       if args.hex:
         Hexdigest()
         exit()
       elif args.b64:
         Base64()
         exit()
       else:
         Bindigest()
         exit()
    else:
            Help()
            exit()

##########################################################################

def CryptoArgon2i():
         start = timer()
         
         global digest
         digest = argon2.using(salt=saltx, rounds=args.iter ,memory_cost=args.blocksize, parallelism=args.parallelism, digest_size=args.size).hash(keyx)
         
         end = timer()
         timex = (end - start)
         print("\n" + str(timex) + " seconds elapsed\n")
         print( "Key was : " + keyx +"\n")
         print( "salt was : " + saltx +"\n")
         

def CryptoScrypt():
         start = timer()
         
         global digest
         digest = scrypt.hash( keyx, saltx,N=args.iter ,r=args.blocksize, p=args.parallelism, buflen=args.size)
         
         end = timer()
         timex = (end - start)
         print("\n" + str(timex) + " seconds elapsed\n")
         print( "Key was : " + keyx +"\n")
         print( "salt was : " + saltx +"\n")


def CryptoBcrypt():
         start = timer()
         
         global digest
         digest = bcrypt.kdf( keyx, saltx, args.size, args.iter)
         
         end = timer()
         timex = (end - start)
         print("\n" + str(timex) + " seconds elapsed\n")
         print( "Key was : " + keyx +"\n")
         print( "salt was : " + saltx + "\n")

def CryptoPbkdf2():

         start = timer()

         global digest
         digest = hashlib.pbkdf2_hmac('sha256', keyx, saltx,args.iter)
         
         end = timer()
         timex = (end - start)
         print("\n" + str(timex) + " seconds elapsed\n")
         print( "Key was : " + keyx +"\n")
         print( "salt was : " + saltx + "\n")


def CryptoCasual():

        counter = args.iter
        usecounter = args.iter - 1
        global keyx
        if args.algo == "md5":
            start = timer()
            for x in range(usecounter):

                keyx2 = hashlib.md5(keyx).digest()
                keyx = keyx2
            
            global digest
            digest = hashlib.md5(keyx).digest()
            
            end = timer()
            timex = (end - start)
            print("\n"+ str(timex) + " seconds elapsed for " + str(counter) + " iterations\n")
            print ("Key was : "+ args.string +"\n") 
####

            
        elif args.algo == "sha1":
            start = timer()
            for x in range(usecounter):

                keyx2 = hashlib.sha1(keyx).digest()
                keyx = keyx2
            
            
            digest = hashlib.sha1(keyx).digest()
            
            end = timer()
            timex = (end - start)
            print("\n"+ str(timex) + " seconds elapsed for " + str(counter) + " iterations\n")
            print ("Key was : "+ args.string +"\n")
            
            
####
        elif args.algo == "sha256":
            start = timer()
            for x in range(usecounter):

                keyx2 = hashlib.sha256(keyx).digest()
                keyx = keyx2
            
            
            digest = hashlib.sha256(keyx).digest()
            
            end = timer()
            timex = (end - start)
            print("\n"+ str(timex) + " seconds elapsed for " + str(counter) + " iterations\n")
            print ("Key was : "+ args.string +"\n")

            
####
        elif args.algo == "sha512":
            start = timer()
            for x in range(usecounter):

                keyx2 = hashlib.sha512(keyx).digest()
                keyx = keyx2
            
            
            digest = hashlib.sha512(keyx).digest()
            
            end = timer()
            timex = (end - start)
            print("\n"+ str(timex) + " seconds elapsed for " + str(counter) + " iterations\n")
            print ("Key was : "+ args.string +"\n")

            
            
        elif args.algo == "whirlpool":
            start = timer()
            for x in range(usecounter):

                keyx2 = hashlib.sha512(keyx).digest()
                keyx = keyx2
            
            
            digest = hashlib.sha512(keyx).digest()
            
            end = timer()
            timex = (end - start)
            print("\n"+ str(timex) + " seconds elapsed for " + str(counter) + " iterations\n")
            print ("Key was : "+ args.string +"\n")

            
        else:
          Help()
def List():

        for algo in algolist:
           print("\n"+ algo)

def Help():

        print ("\nplease use -h for help or -l for a list of supported hashes")

def Hexdigest():
  global digest
  print (binascii.hexlify(digest))
  
def Base64():
  global digest
  print ("\n" + base64.b64encode(digest))
  
def Bindigest():
  global digest
  print(digest)
  


main()
