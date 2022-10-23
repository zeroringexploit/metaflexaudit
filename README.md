![](https://i.imgur.com/vCxCmjT.png)

# Metaflexer Contract Audit via Slither

Main.sol analyzed (15 contracts with 81 detectors), 93 result(s) found

## High severity

*Metaflexer.t1 (Main.sol#1392) is never initialized*. It is used in:
 - Metaflexer.withdraw() (Main.sol#1542-1552)
*Metaflexer.t2 (Main.sol#1393)* is never initialized. It is used in:
 - Metaflexer.withdraw() (Main.sol#1542-1552)
*Metaflexer.t3 (Main.sol#1394) is never initialized*. It is used in:
 - Metaflexer.withdraw() (Main.sol#1542-1552)
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#uninitialized-state-variables

## Medium severity

**Reentrancy** in ERC721A._mint(address,uint256,bytes,bool) (Main.sol#1133-1175):
 External calls:
 - ! _checkContractOnERC721Received(address(0),to,updatedIndex ++,_data) (Main.sol#1161)
 - IERC721Receiver(to).onERC721Received(_msgSender(),from,tokenId,_data) (Main.sol#1315-1325)
 State variables written after the call(s):
 - _currentIndex = updatedIndex (Main.sol#1172)
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-1

## Low severity

ERC721A._checkContractOnERC721Received(address,address,uint256,bytes) (Main.sol#1309-1326) ignores return value by IERC721Receiver(to).onERC721Received(_msgSender(),from,tokenId,_data) (Main.sol#1315-1325)
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#unused-return
Metaflexer.walletOfOwner(address)._owner (Main.sol#1456) shadows:
 - Ownable._owner (Main.sol#186) (state variable)
Metaflexer.setSaleStatus(uint256)._status (Main.sol#1538) shadows:
 - ReentrancyGuard._status (Main.sol#40) (state variable)
Metaflexer.isApprovedForAll(address,address).owner (Main.sol#1560) shadows:
 - Ownable.owner() (Main.sol#200-202) (function)
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#local-variable-shadowing
Metaflexer.setCost(uint256) (Main.sol#1509-1511) should emit an event for:
 - cost = _cost (Main.sol#1510)
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#missing-events-arithmetic
Metaflexer.setSignerAddress(address).newSigner (Main.sol#1501) lacks a zero-check on :
 - signerAddress = newSigner (Main.sol#1502)
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#missing-zero-address-validation

Variable 'ERC721A._checkContractOnERC721Received(address,address,uint256,bytes).retval (Main.sol#1315)' in ERC721A._checkContractOnERC721Received(address,address,uint256,bytes) (Main.sol#1309-1326) potentially used before declaration: retval == IERC721Receiver(to).onERC721Received.selector (Main.sol#1316)
Variable 'ERC721A._checkContractOnERC721Received(address,address,uint256,bytes).reason (Main.sol#1317)' in ERC721A._checkContractOnERC721Received(address,address,uint256,bytes) (Main.sol#1309-1326) potentially used before declaration: reason.length == 0 (Main.sol#1318)
Variable 'ERC721A._checkContractOnERC721Received(address,address,uint256,bytes).reason (Main.sol#1317)' in ERC721A._checkContractOnERC721Received(address,address,uint256,bytes) (Main.sol#1309-1326) potentially used before declaration: revert(uint256,uint256)(32 + reason,mload(uint256)(reason)) (Main.sol#1322)
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#pre-declaration-usage-of-local-variables

Address.isContract(address) (Main.sol#271-281) uses assembly
 - INLINE ASM (Main.sol#277-279)
Address.verifyCallResult(bool,bytes,string) (Main.sol#440-460) uses assembly
 - INLINE ASM (Main.sol#452-455)
ERC721A._checkContractOnERC721Received(address,address,uint256,bytes) (Main.sol#1309-1326) uses assembly
 - INLINE ASM (Main.sol#1321-1323)
Metaflexer.splitSignature(bytes) (Main.sol#1603-1612) uses assembly
 - INLINE ASM (Main.sol#1607-1611)
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#assembly-usage

Metaflexer.tokenURI(uint256) (Main.sol#1481-1489) compares to a boolean constant:
 - revealed == false (Main.sol#1483)
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#boolean-equality

Different versions of Solidity are used:
 - Version used: ['>=0.8.9<0.9.0', '^0.8.0', '^0.8.4', '^0.8.9']
 - ^0.8.9 (Main.sol#7)
 - ^0.8.0 (Main.sol#73)
 - ^0.8.0 (Main.sol#143)
 - ^0.8.0 (Main.sol#170)
 - ^0.8.0 (Main.sol#248)
 - ^0.8.0 (Main.sol#468)
 - ^0.8.0 (Main.sol#498)
 - ^0.8.0 (Main.sol#526)
 - ^0.8.0 (Main.sol#557)
 - ^0.8.0 (Main.sol#702)
 - ^0.8.0 (Main.sol#733)
 - ^0.8.4 (Main.sol#762)
 - >=0.8.9<0.9.0 (Main.sol#1377)
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#different-pragma-directives-are-used

Address.functionCall(address,bytes) (Main.sol#324-326) is never used and should be removed
Address.functionCall(address,bytes,string) (Main.sol#334-340) is never used and should be removed
Address.functionCallWithValue(address,bytes,uint256) (Main.sol#353-359) is never used and should be removed
Address.functionCallWithValue(address,bytes,uint256,string) (Main.sol#367-378) is never used and should be removed
Address.functionDelegateCall(address,bytes) (Main.sol#413-415) is never used and should be removed
Address.functionDelegateCall(address,bytes,string) (Main.sol#423-432) is never used and should be removed
Address.functionStaticCall(address,bytes) (Main.sol#386-388) is never used and should be removed
Address.functionStaticCall(address,bytes,string) (Main.sol#396-405) is never used and should be removed
Address.sendValue(address,uint256) (Main.sol#299-304) is never used and should be removed
Address.verifyCallResult(bool,bytes,string) (Main.sol#440-460) is never used and should be removed
Context._msgData() (Main.sol#160-162) is never used and should be removed
ERC721A._baseURI() (Main.sol#1008-1010) is never used and should be removed
ERC721A._burn(uint256) (Main.sol#1244-1284) is never used and should be removed
ERC721A._getAux(address) (Main.sol#927-930) is never used and should be removed
ERC721A._numberBurned(address) (Main.sol#919-922) is never used and should be removed
ERC721A._setAux(address,uint64) (Main.sol#936-939) is never used and should be removed
ERC721A._totalMinted() (Main.sol#882-888) is never used and should be removed
Metaflexer._baseURI() (Main.sol#1554-1556) is never used and should be removed
Strings.toHexString(uint256) (Main.sol#109-120) is never used and should be removed
Strings.toHexString(uint256,uint256) (Main.sol#125-135) is never used and should be removed
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#dead-code

Pragma version^0.8.9 (Main.sol#7) allows old versions
Pragma version^0.8.0 (Main.sol#73) allows old versions
Pragma version^0.8.0 (Main.sol#143) allows old versions
Pragma version^0.8.0 (Main.sol#170) allows old versions
Pragma version^0.8.0 (Main.sol#248) allows old versions
Pragma version^0.8.0 (Main.sol#468) allows old versions
Pragma version^0.8.0 (Main.sol#498) allows old versions
Pragma version^0.8.0 (Main.sol#526) allows old versions
Pragma version^0.8.0 (Main.sol#557) allows old versions
Pragma version^0.8.0 (Main.sol#702) allows old versions
Pragma version^0.8.0 (Main.sol#733) allows old versions
Pragma version^0.8.4 (Main.sol#762) allows old versions
Pragma version>=0.8.9<0.9.0 (Main.sol#1377) is too complex
solc-0.8.17 is not recommended for deployment
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity

Low level call in Address.sendValue(address,uint256) (Main.sol#299-304):
 - (success) = recipient.call{value: amount}() (Main.sol#302)
Low level call in Address.functionCallWithValue(address,bytes,uint256,string) (Main.sol#367-378):
 - (success,returndata) = target.call{value: value}(data) (Main.sol#376)
Low level call in Address.functionStaticCall(address,bytes,string) (Main.sol#396-405):
 - (success,returndata) = target.staticcall(data) (Main.sol#403)
Low level call in Address.functionDelegateCall(address,bytes,string) (Main.sol#423-432):
 - (success,returndata) = target.delegatecall(data) (Main.sol#430)
Low level call in Metaflexer.withdraw() (Main.sol#1542-1552):
 - (hs) = address(t1).call{value: address(this).balance * 10 / 100}() (Main.sol#1544)
 - (vs) = address(t2).call{value: address(this).balance * 50 / 100}() (Main.sol#1547)
 - (os) = address(t3).call{value: address(this).balance}() (Main.sol#1550)
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#low-level-calls

Parameter ERC721A.safeTransferFrom(address,address,uint256,bytes)._data (Main.sol#1081) is not in mixedCase
Variable ERC721A._currentIndex (Main.sol#830) is not in mixedCase
Variable ERC721A._burnCounter (Main.sol#833) is not in mixedCase
Variable ERC721A._ownerships (Main.sol#843) is not in mixedCase
Parameter Metaflexer.whitelistMint(uint256,bytes)._mintAmount (Main.sol#1439) is not in mixedCase
Parameter Metaflexer.publicMint(uint256)._mintAmount (Main.sol#1446) is not in mixedCase
Parameter Metaflexer.mintForAddress(uint256,address)._mintAmount (Main.sol#1452) is not in mixedCase
Parameter Metaflexer.mintForAddress(uint256,address)._receiver (Main.sol#1452) is not in mixedCase
Parameter Metaflexer.walletOfOwner(address)._owner (Main.sol#1456) is not in mixedCase
Parameter Metaflexer.tokenURI(uint256)._tokenId (Main.sol#1481) is not in mixedCase
Parameter Metaflexer.setRevealed(bool)._state (Main.sol#1505) is not in mixedCase
Parameter Metaflexer.setCost(uint256)._cost (Main.sol#1509) is not in mixedCase
Parameter Metaflexer.setMaxMintAmountPerTx(uint256)._maxMintAmountPerTx (Main.sol#1513) is not in mixedCase
Parameter Metaflexer.setMaxPresale(uint256)._maxMintAmountPresale (Main.sol#1517) is not in mixedCase
Parameter Metaflexer.setMaxPublic(uint256)._maxMintAmountPublic (Main.sol#1521) is not in mixedCase
Parameter Metaflexer.setHiddenMetadataUri(string)._hiddenMetadataUri (Main.sol#1525) is not in mixedCase
Parameter Metaflexer.setUriPrefix(string)._uriPrefix (Main.sol#1529) is not in mixedCase
Parameter Metaflexer.setUriSuffix(string)._uriSuffix (Main.sol#1533) is not in mixedCase
Parameter Metaflexer.setSaleStatus(uint256)._status (Main.sol#1538) is not in mixedCase
Parameter Metaflexer.getMessageHash(address)._message (Main.sol#1578) is not in mixedCase
Parameter Metaflexer.getMessageHashEth(bytes32)._sender (Main.sol#1583) is not in mixedCase
Parameter Metaflexer.verify(bytes,address)._signature (Main.sol#1589) is not in mixedCase
Parameter Metaflexer.recoverSigner(bytes32,bytes)._messageHash (Main.sol#1597) is not in mixedCase
Parameter Metaflexer.recoverSigner(bytes32,bytes)._signature (Main.sol#1597) is not in mixedCase
Parameter Metaflexer.splitSignature(bytes)._sig (Main.sol#1603) is not in mixedCase
Parameter Metaflexer.upgrade(uint256,uint256)._tokenID (Main.sol#1614) is not in mixedCase
Parameter Metaflexer.upgrade(uint256,uint256)._collectionID (Main.sol#1614) is not in mixedCase
Parameter Metaflexer.setCollectionID(uint256,address,string)._collectionID (Main.sol#1621) is not in mixedCase
Parameter Metaflexer.setCollectionID(uint256,address,string)._contractAddress (Main.sol#1621) is not in mixedCase
Parameter Metaflexer.setCollectionID(uint256,address,string)._baseURL (Main.sol#1621) is not in mixedCase
Constant Metaflexer.proxyRegistryAddress (Main.sol#1407) is not in UPPER_CASE_WITH_UNDERSCORES

**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#conformance-to-solidity-naming-conventions

Metaflexer.t1 (Main.sol#1392) should be constant
Metaflexer.t2 (Main.sol#1393) should be constant
Metaflexer.t3 (Main.sol#1394) should be constant
Metaflexer.totalCollectionsID (Main.sol#1409) should be constant
**Reference**: https://github.com/crytic/slither/wiki/Detector-Documentation#state-variables-that-could-be-declared-constant
