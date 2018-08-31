# bn_tool  
Big number tool  
## support  
```
mod exp  
mod inv  
mod  
exp  
add  
sub  
mul  
```

## make  
gcc calc.c -lcrypto -o calc.o  

## usage  
To calculate `65451^4660 mod 26505`:  
`./calc.o mod_exp "FFAB" "1234" "6789"`  
  
To calculate `11806078888327 * 3`:  
`./calc.o mod_exp "ABCD1236987" "03"`  
  
To calculate `k*G` which G is the basepoint of secp256k1 `./calc.o ec_mul secp256k1 "cef147652aa90162e1fff9cf07f2605ea05529ca215a04350a98ecc24aa34342"`  
