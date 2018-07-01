import hashlib
import scrypt
import bcrypt
from passlib.hash import argon2

import random
import binascii
from timeit import default_timer as timer
import base64
import argparse

algos = ["md5","sha1","sha256","sha512","sha384","sha224","bcrypt","scrypt","Argon2i","pbkdf2","ripemd160","whirlpool"]

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
parser.add_argument('--size', dest="size", default="32", help="Hashes output size in bits ( should only be use with bcrypt, argon2i and scrypt )", type=int)
parser.add_argument('--string',dest="string",default=random128,help="string that is used for the hash")
parser.add_argument('--salt',dest="salt",default=random32,help="Salt that is used for the hash")
parser.add_argument('--Veracrypt-mode-system',dest="VCMS",action="store_true",help="Run in Veracrypt System PIM mode")
parser.add_argument('--Veracrypt-mode-none-system',dest="VCMNS",action="store_true",help="Run in Veracrypt non System PIM mode")


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

algolist = [ "Argon2i","Bcrypt","Scrypt","pbkdf2","md5","sha1","sha256","sha512","sha384","sha224","ripemd160","whirlpool"]
digest=""


# main

def main():
  if args.list:
      List()
      exit()
  if args.algo == "Argon2i":
      if args.VCMNS:
         VCMNS()
      if args.VCMS:
         VCMS()
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
      if args.VCMNS:
         VCMNS()
      if args.VCMS:
         VCMS()
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
      if args.VCMNS:
         VCMNS()
      if args.VCMS:
         VCMS()
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
      if args.VCMNS:
         VCMNS()
      if args.VCMS:
         VCMS()
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
    if args.VCMNS:
        VCMNS()
    if args.VCMS:
        VCMS()
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

         TimeEstimation()
         start = timer()
         
         global digest
         digest = argon2.using(salt=saltx, rounds=args.iter ,memory_cost=args.blocksize, parallelism=args.parallelism, digest_size=args.size).hash(keyx)
         
         end = timer()
         timex = (end - start)
         print("\n" + str(timex) + " seconds elapsed\n")
         print( "Key was : " + keyx +"\n")
         print( "salt was : " + saltx +"\n")
         

def CryptoScrypt():

         TimeEstimation()
         start = timer()
         
         global digest
         digest = scrypt.hash( keyx, saltx,N=args.iter ,r=args.blocksize, p=args.parallelism, buflen=args.size)
         
         end = timer()
         timex = (end - start)
         print("\n" + str(timex) + " seconds elapsed\n")
         print( "Key was : " + keyx +"\n")
         print( "salt was : " + saltx +"\n")


def CryptoBcrypt():

         TimeEstimation()
         start = timer()
         
         global digest
         digest = bcrypt.kdf( keyx, saltx, args.size, args.iter)
         
         end = timer()
         timex = (end - start)
         print("\n" + str(timex) + " seconds elapsed\n")
         print( "Key was : " + keyx +"\n")
         print( "salt was : " + saltx + "\n")

def CryptoPbkdf2():

         TimeEstimation()
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
            TimeEstimation()
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
            TimeEstimation()
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
            TimeEstimation()
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
            TimeEstimation()
            start = timer()
            for x in range(usecounter):

                keyx2 = hashlib.sha512(keyx).digest()
                keyx = keyx2
            
            
            digest = hashlib.sha512(keyx).digest()
            
            end = timer()
            timex = (end - start)
            print("\n"+ str(timex) + " seconds elapsed for " + str(counter) + " iterations\n")
            print ("Key was : "+ args.string +"\n")

            
####            
        elif args.algo == "whirlpool":
            TimeEstimation()
            keyx2 = hashlib.new('whirlpool')
            start = timer()
            for x in range(usecounter):

                keyx2.update(str(keyx))
                keyx = keyx2
            
            
            digest = keyx.digest()
            
            end = timer()
            timex = (end - start)
            print("\n"+ str(timex) + " seconds elapsed for " + str(counter) + " iterations\n")


####            
        elif args.algo == "sha224":
            TimeEstimation()
            start = timer()
            for x in range(usecounter):

                keyx2 = hashlib.sha224(keyx).digest()
                keyx = keyx2
            
            
            digest = hashlib.sha224(keyx).digest()
            
            end = timer()
            timex = (end - start)
            print("\n"+ str(timex) + " seconds elapsed for " + str(counter) + " iterations\n")


####
        elif args.algo == "sha384":
            TimeEstimation()
            start = timer()
            for x in range(usecounter):

                keyx2 = hashlib.sha384(keyx).digest()
                keyx = keyx2
            
            
            digest = hashlib.sha384(keyx).digest()
            
            end = timer()
            timex = (end - start)
            print("\n"+ str(timex) + " seconds elapsed for " + str(counter) + " iterations\n")

####

        elif args.algo == "ripemd160":
            TimeEstimation()
            keyx2 = hashlib.new('ripemd160')
            start = timer()
            for x in range(usecounter):

                keyx2.update(str(keyx))
                keyx = keyx2
            
            
            digest = keyx.digest()
            
            end = timer()
            timex = (end - start)
            print("\n"+ str(timex) + " seconds elapsed for " + str(counter) + " iterations\n")


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
  
def VCMS():
  
  print "\nRunning in Veracrypt system PIM mode\n"
  args.iter = ( int(args.iter) * 2048)
  print args.iter

def VCMNS():
   
  print "\nRunning in Veracrypt none system PIM mode\n"
  args.iter = ( 15000 + int(args.iter) * 1000)
  print args.iter

def TimeEstimation():
 
   global algolist
   
   if args.algo == "Argon2i":
      if args.iter < 1024 and args.parallelism < 16 and args.blocksize < 512 :
            estimate = " very low < 1 second "
      elif args.iter <= 1024 and args.parallelism <= 16 and args.blocksize <= 512 :
            estimate = " low < 4 second      "
      elif args.iter <= 2048 and args.parallelism <= 16 and args.blocksize <= 512 :
            estimate = " low < 4 second      "
      elif args.iter <= 1024 and args.parallelism <= 16 and args.blocksize <= 1024 :
            estimate = "low < 7 seconds "
      elif args.iter <= 1024 and args.parallelism <= 16 and args.blocksize <= 2048 :
            estimate = "low < 5 seconds "
      elif args.iter <= 2048 and args.parallelism <= 32 and args.blocksize <= 2048 :
            estimate = "medium 10-20 seconds " 
      elif args.iter <= 4096 and args.parallelism >= 32 and args.blocksize >= 1024 :
            estimate = estimate = "high ~60 seconds    "
      elif args.iter >= 4096 and args.parallelism >= 32 and args.blocksize >= 1024 :
            estimate = estimate = "extream 60++ Seconds "
      else:
            estimate = "N/A            "
      
   
   elif args.algo == "Scrypt":
      if args.iter < 1024 and args.parallelism < 16 and args.blocksize < 512 :
            estimate = " very low < 1 second "
      elif args.iter <= 1024 and args.parallelism <= 16 and args.blocksize <= 512 :
            estimate = " low < 4 second      "
      elif args.iter <= 2048 and args.parallelism <= 16 and args.blocksize <= 512 :
            estimate = " low < 4 second      "
      elif args.iter <= 1024 and args.parallelism <= 16 and args.blocksize <= 1024 :
            estimate = "low < 7 seconds "
      elif args.iter <= 1024 and args.parallelism <= 16 and args.blocksize <= 2048 :
            estimate = "low < 5 seconds "
      elif args.iter <= 2048 and args.parallelism <= 32 and args.blocksize <= 2048 :
            estimate = "medium 10-20 seconds " 
      elif args.iter <= 4096 and args.parallelism >= 32 and args.blocksize >= 1024 :
            estimate = estimate = "high ~60 seconds    "
      elif args.iter >= 4096 and args.parallelism >= 32 and args.blocksize >= 1024 :
            estimate = estimate = "extream 60++ Seconds "
      else:
            estimate = "N/A            "
            
            
   elif args.algo == "Bcrypt":
      if args.iter < 1024:
            estimate = " very low ~ 2 seconds "
      elif args.iter >= 1024 and args.iter < 2000:
            estimate = " low  ~ 5 seconds    "      
      elif args.iter >= 2048 and args.iter < 3500:
            estimate = "medium ~ 10 seconds  "
      elif args.iter >= 4096 and args.iter < 8192:
            estimate = "high ~ 20 seconds "
      elif args.iter > 4096:
            estimate = "high < 60 seconds "
      else:
            esitmate = "N/A           "

            
   elif args.algo == "pbkdf2":
      if args.iter < 1000000:
            estimate = " very low < 1 second "
      elif args.iter >= 10000000 and args.iter < 5000000:
            estimate = " low  ~ 5 seconds    "      
      elif args.iter >= 10000000 and args.iter < 20000000:
            estimate = "medium ~ 10 seconds  "
      elif args.iter >= 20000000 and args.iter < 300000000:
            estimate = "high ~ 20 seconds "
      elif args.iter > 300000000:
            estimate = "high < 60 seconds "
      else:
            esitmate = "N/A           "

            
   elif args.algo != "":
      for algo in algolist:
        if algo == args.algo:
           if args.iter < 1000000:
            estimate = " very low < 1 second "
           elif args.iter >= 10000000 and args.iter < 5000000:
            estimate = " low  ~ 5 seconds    "      
           elif args.iter >= 10000000 and args.iter < 20000000:
            estimate = "medium ~ 10 seconds  "
           elif args.iter >= 20000000 and args.iter < 30000000:
            estimate = "high ~ 20 seconds "
           elif args.iter > 30000000:
            estimate = "high < 60 seconds    "
           else:
            esitmate = "N/A           "
   else:
      print "could not estimate time"
        
           
           
               
   print "\n#######################################"
   print "Estimated time : " + estimate + "#"
   print "#######################################"


         

main()
