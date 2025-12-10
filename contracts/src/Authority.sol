// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/access/Ownable.sol";

// contract Authority{

//     address public admin;

//     mapping(address=>bool) isAuthority;

//     error ZeroAddressCannotBeAnAuthority();

//     constructor(){
//         admin=msg.sender;

//     }

//     function addTrustedAuthority(address trustedAddress) external onlyOwner{

//     if(trustedAddress==address(0)) revert ZeroAddressCannotBeAnAuthority();
//     if(isAuthority[trustedAddress]==true) revert AddressAlreadyAdded();

//     isAuthority[trustedAddress]==true;

//     emit TrustedAuthorityAdded(trustedAddress);

//     }

//     function removeTrustedAddress(address trustedAddress)  external onlyOwner{
//     if(trustedAddress==address(0)) revert ZeroAddressCannotBeAnAuthority();
//     if(isAuthority[trustedAddress]==false) revert AddressNotThere();

//     isAuthority[trustedAddress]==false;

//      emit TrustedAuthorityAdded(trustedAddress);

//     }

//}
