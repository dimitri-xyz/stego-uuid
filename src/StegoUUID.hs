module StegoUUID where

import           Data.Maybe
import           Data.Word

import           Data.UUID
import           Crypto.Hash

import qualified Data.ByteArray             as BA
import qualified Data.ByteString.Builder    as BSB
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Lazy       as BSL

newtype StegoKeyHi = KeyHi64 Word64
newtype StegoKeyLo = KeyLo64 Word64

mark :: StegoKeyHi -> StegoKeyLo -> Word64 -> UUID
mark (KeyHi64 selfKeyHi) (KeyLo64 selfKeyLo) rand =
  let selfKeyHiAsLazyBS = BSB.toLazyByteString (BSB.word64BE selfKeyHi)
      selfKeyLoAsLazyBS = BSB.toLazyByteString (BSB.word64BE selfKeyLo)
      randAsLazyBS      = BSB.toLazyByteString (BSB.word64BE rand)
      hashInput         = BSL.concat [randAsLazyBS, selfKeyHiAsLazyBS, selfKeyLoAsLazyBS]
      digest            = hash (BSL.toStrict hashInput) :: Digest SHA256
      hashBitsStrict    = BS.take 8  (BA.convert digest)
      halfAndHalf       = BSL.concat [randAsLazyBS, BSL.fromStrict hashBitsStrict]
   in fromJust (fromByteString halfAndHalf)


isMarked :: StegoKeyHi -> StegoKeyLo -> UUID -> Bool
isMarked selfKeyHi selfKeyLo uuid =
  let (rHi, rLo, _, _) = toWords uuid
      r = fromIntegral rHi * 2^32 + fromIntegral rLo
  in mark selfKeyHi selfKeyLo r == uuid
