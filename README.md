<p align="left">
   <a href="https://github.com/RichardRMatthews/Crypto-Hash-Lab/issues"><img src="https://img.shields.io/github/issues/RichardRMatthews/Crypto-Hash-Lab.svg" alt=""></a>
   <a href="https://github.com/RichardRMatthews/Crypto-Hash-Lab/forks"><img src="https://img.shields.io/github/forks/RichardRMatthews/Crypto-Hash-Lab.svg" alt=""></a>
   <a href="https://github.com/RichardRMatthews/Crypto-Hash-Lab/stargazers"><img src="https://img.shields.io/github/stars/RichardRMatthews/Crypto-Hash-Lab.svg" alt=""></a>  
   <a href="https://github.com/RichardRMatthews/Crypto-Hash-Lab/blob/master/LICENSE"><img src="https://img.shields.io/github/license/RichardRMatthews/Crypto-Hash-Lab.svg" alt=""></a>
</p>

# Crypto Hash Lab
A python tool for experimenting with diverse cryptographic hash algorithms.

About Crypto Hash Lab
---------------------

Crypto-Hash-Lab is a small tool which aims to facilitate the usage of cryptographic hash algorithms.
It comes with some optional workfactors which can help you to finetune the cost of your cryptographic hashes.
This information can be usefule when running cryptographic applications on your devide & network or if you want to write a
cryptographic tool.

The hash count could be a little under the maximum possible on your device ,compared to a C implementation.

Parameters
------------

Basic parameters
----------------

 **--help**  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  This Parameter outputs a list of all parameters.   
 **--algo**  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; This specifies the algorithm to use.  
 **--list**  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Will list all supported hash algorithms.  
 **--salt** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Specifies the salt that is used for supported hashes. ( default is random )    
 **--string** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Sets the input string "key" of the hash. ( default is random )     
 **--base64** &nbsp;&nbsp;&nbsp; Outputs the hash with base64 encoding.  
 **--hex**    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Outputs the hash with hex encoding.  

If not encoding is specified the hash will be displaied in raw binary format , except for Argon2 which will be displaied in it's custom base64 format.

Hash parameters
---------------

**--iterations** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; The number of iterations ( rounds ). Can be used with any hash , but needs to be a multiple of 2 for Scrypt.  
**--blocksize**   &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  This factor sets the memory cost. Will only work for Scrypt and Argon2.  
**--paralleslism** &nbsp;&nbsp; Is used to increase the CPU work factor. Can be used only for Scrypt and Argon2.  
**--size** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Sets the size in bytes. Will only work with Argon2 , Bcrypt and Scrypt.            

Installation
------------

Requires Python 2.7

`Pip install -r requirements.txt`


License
--------
Code distributed under MIT licence.
