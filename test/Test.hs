import System.Random
import Data.Word
import Data.UUID

import StegoUUID


secretHi = KeyHi64 12345
secretLo = KeyLo64 67890

main :: IO ()
main = do

  putStrLn ""
  r  <- randomIO :: IO Word64
  let x = mark secretHi secretLo r
  print x
  print (isMarked secretHi secretLo x)  -- True

  y <- randomIO :: IO UUID
  print y
  print (isMarked secretHi secretLo y)  -- False
