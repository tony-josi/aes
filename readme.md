## Advanced Encryption Standard

```

           ______  _____ 
     /\   |  ____|/ ____|
    /  \  | |__  | (___  
   / /\ \ |  __|  \___ \ 
  / ____ \| |____ ____) |
 /_/    \_\______|_____/ 
                         
```

The Advanced Encryption Standard (AES), also known by its original name Rijndael is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST).

This implementation currently supports Electronic codebook mode with support for 128/192/256 bit keys.

### High-level description of the algorithm
1. `KeyExpansion` – round keys are derived from the cipher key using the AES key schedule. AES requires a separate 128-bit round key block for each round plus one more.
2. Initial round key addition:
    1. `AddRoundKey` – each byte of the state is combined with a byte of the round key using bitwise xor.
    2. 9, 11 or 13 rounds:
        1. `SubBytes` – a non-linear substitution step where each byte is replaced with another according to a lookup table.
        2. `ShiftRows` – a transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
        3. `MixColumns` – a linear mixing operation which operates on the columns of the state, combining the four bytes in each column.
        4. `AddRoundKey`
3. Final round (making 10, 12 or 14 rounds in total):
    1. `SubBytes`
    2. `ShiftRows`
    3. `AddRoundKey`


[src](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

**Note:** The project objective was more of a way to learn C++, hence the efficiency and security side of this AES implementation may not be perfect.

#### To Do:
* Use pointer based XOR operation instead of loop - individual bytes & XOR
* Implement more API functions for encrypting larger chunks of data
* Implement other encryption modes - Cipher block chaining, Output feedback, Counter modes
* Implement algorithm for mix column & inverse mix column instead of lookup table for learning
