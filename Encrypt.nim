import nimcrypto
import std/sha1
import random
import zippy

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc rand_str_16 : string =
    set_len result, 16
    for n in result.low .. result.high: result[n] = rand 'A' .. 'Z'

proc customEncrypt(iv: seq[byte], data: seq[byte], customKey: string): string =
    var
      ectx: CTR[aes256]
      key: array[aes256.sizeKey, byte]
      plaintext = newSeq[byte](len(data))
      enctext = newSeq[byte](len(data))

    # We do not need to pad data, `CTR` mode works byte by byte.
    copyMem(addr plaintext[0], unsafeAddr data[0], len(data))

    # Expand key to 32 bytes using SHA256 as the KDF
    var expandedkey = sha256.digest(customKey)
    copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

    ectx.init(key, iv)
    ectx.encrypt(plaintext, enctext)
    ectx.clear()
    return toHex(enctext)

when isMainModule:
    randomize()
    var 
        msgTitle = "NimRekey" #Replace me
        msgContent = "Hi Northsec!" #Replace me
        drmUniquePattern = "~~~" #Replace me with something unique not commonly found in byte patterns on disk
        keyRaw = "7h15 15 4 pr377y 50l1d k3y" #Replace me
    var
        ivStr: string = toHex(toByteSeq(rand_str_16()))
        iv: seq[byte] = utils.fromHex(ivStr)
        keyDRM = secureHash(rand_str_16())
        key = $(secureHash(keyRaw))

    echo "iv: ", ivStr
    echo "drmUniquePattern: ", drmUniquePattern
    echo "key: ", key
    echo "keyDRM: ", drmUniquePattern, $keyDRM, drmUniquePattern
    echo "keyDRMPlaceHolderHash: ", secureHash($keyDRM)
    echo "msgTitle: ", customEncrypt(iv, compress(toByteSeq(msgTitle), 9), key)
    echo "msgContent: ", customEncrypt(iv, compress(toByteSeq(msgContent), 9), key)