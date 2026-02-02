 # Highly Optimized Low Latency Hardware AES128ECB Implementation and Benchmarking
 - Pure x86_64 Intel Assembly without any external library 
 - CPU: Intel Skylake   AVX2, AES-NI
##
- ``Assemble : nasm -felf64 -o aex.o aesdqw.asm``
- ``link     : ld -o aex aex.o``
- ``execute  : ./aex``

##
- Input : File : 16 bytes plain text 'plainVector128'
- Output: File : 16 bytes cipher text in file 'encop'
- STDOUT :
  - Average cycle count for enc+dec
  -  Cipher Text 
  -  Decrypted Text 
  -  Key


 ## Achieved Performance Benchmarks:
 *For Intel Skylake , Cpu clock speed : 2300mhz(max scaling) , Memory : 2133 MT/s* 
#
 - block size : 16 Bytes (Single)
 - Average AES encryption: 10-11 clock cycles
 - Average AES decryption: 10-11 clock cycles
#
- block size : 16 Bytesx4 (Concurrent)
- Average AES encryption: 1-2 clock cycles
- Average AES decryption: 1-2 clock cycles
