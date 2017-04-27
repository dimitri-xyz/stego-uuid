# stego-uuid
A generator and verifier for steganographic numbers that look random

The standard use of this package is to generate a 64-bit number and use
this, along with a secret key, as input to the marking function.

Example:

```haskell

secretHi = KeyHi64 12345  -- secret key hi  64 bits
secretLo = KeyLo64 67890  -- secret key low 64 bits

main :: IO ()
main = do

  putStrLn "Is this marked?"
  r  <- randomIO :: IO Word64           -- get 64-bit random number
  let x = mark secretHi secretLo r      -- produce marked 128-bit UUID
  print x                               
  print (isMarked secretHi secretLo x)  -- True
```

## Security considerations
This is a poor man's MAC. We use SHA256 to generate the second half of the UUID from the 64-bit
random looking input and the secret key. The small number of bits limits the security.

We will start getting collisions on the 64-bit random number after about 2^32 numbers are used.
But this just means we will be providing the function with the same input, so the same output
will be produced.

### False Negatives
This is zero. If you produced the number with the `mark` function, this number will always be
detected with `isMarked` as long as you provide the correct key.

### False positives
This is false detection. We worry about a UUID that was *not* generated using `mark` but is
detected as marked by `isMarked`. (A malicious adversary can always replay any UUIDs known as
marked. Thus, we will consider only new UUIDs.)

Assuming SHA256 is a perfect pseudo-random function, its truncated output, i.e. the last 64 bits of
the UUID, does not leak any information about the secret key. Given a fixed secret key, for any
64-bit input (corresponding to the the first half of the UUID), there is a unique 64-bit output
(corresponding to the second half of the UUID). There is only one such output per 64-bit input. So,
the probability of finding such input from a random draw is 2^(-64). The adversary would have more
than a 1/2 chance of finding it after 2^63 guesses.

### Information leakage
The adversary can only know a UUID is marked if it is able to differentiate the output of truncated
SHA256 from a pseudo-random function. I am unaware of any significant results in doing so. The key
is 128-bits in length, so going through all possible values is currently unfeasible.
