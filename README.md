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

## `make`
gcc calc.c -lcrypto -o calc.o

## `usage`
To calculate `65451^4660 mod 26505`:  
`./calc.o mod_exp "FFAB" "1234" "6789"`  
  
To calculate `11806078888327 * 3`:  
`./calc.o mod_exp "ABCD1236987" "03"`  
