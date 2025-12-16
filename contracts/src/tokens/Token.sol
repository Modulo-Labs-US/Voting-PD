// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";

contract Token is ERC20, ERC20Permit, ERC20Votes, Ownable {
    // Track whether an address is locked
    mapping(address => bool) private _locked;

    // Custom errors
    error TokenAlreadyLocked();
    error TokenNotLocked();
    error TokenLockedCannotTransfer();
    error TokenLockedCannotApprove();
    error TokenLockedCannotSpend();

    constructor(address _owner) ERC20("MyToken", "MT") ERC20Permit("MyToken") Ownable(_owner) {}

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function lock(address user) external {
        if (_locked[user] == true) revert TokenAlreadyLocked();
        _locked[user] = true;
    }

    function unlock(address user) external {
        if (_locked[user] == false) revert TokenNotLocked();
        _locked[user] = false;
    }

    function isLocked(address user) public view returns (bool) {
        return _locked[user];
    }

    function approve(address spender, uint256 amount) public override returns (bool) {
        if (_locked[_msgSender()] == true) revert TokenLockedCannotApprove();
        return super.approve(spender, amount);
    }

    // after the token transfer it means that you increase the voting power of the delegate
    function transfer(address to, uint256 amount) public override returns (bool) {
        if (_locked[_msgSender()] == true) revert TokenLockedCannotTransfer();
        _update(_msgSender(), to, amount);
        return super.transfer(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override(ERC20, ERC20Votes) {
        super._update(from, to, value);
    }

    function nonces(address owner) public view override(ERC20Permit, Nonces) returns (uint256) {
        return super.nonces(owner);
    }
}
