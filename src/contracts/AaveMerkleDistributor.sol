// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IERC20 } from "solidity-utils/contracts/oz-common/interfaces/IERC20.sol";
import { SafeERC20 } from "solidity-utils/contracts/oz-common/SafeERC20.sol";
import { Ownable } from "solidity-utils/contracts/oz-common/Ownable.sol";
import { MerkleProof } from "./dependencies/openZeppelin/MerkleProof.sol";
import { IAaveMerkleDistributor } from "./interfaces/IAaveMerkleDistributor.sol";

contract AaveMerkleDistributor is Ownable, IAaveMerkleDistributor {
    using SafeERC20 for IERC20;

    mapping(uint256 => Distribution) public _distributions;

    uint256 public override _nextDistributionId = 0;

    // This mapping allows whitelisted addresses to claim on behalf of others
    // useful for contracts that hold tokens to be rewarded but don't have any native logic to claim Liquidity Mining rewards
    mapping(address => address) internal _authorizedClaimers;

    modifier onlyAuthorizedClaimers(address claimer, address user) {
        require(_authorizedClaimers[user] == claimer, "CLAIMER_UNAUTHORIZED");
        _;
    }

    function contructor() public {}

    function setClaimer(address user, address caller) external override {
        // TODO: needs some guard...probably short executor?
        _authorizedClaimers[user] = caller;
        emit ClaimerSet(user, caller);
    }

    /// @inheritdoc IAaveMerkleDistributor
    function getDistribution(
        uint256 distributionId
    ) external view override returns (DistributionWithoutClaimed memory) {
        require(
            distributionId < _nextDistributionId,
            "MerkleDistributor: Distribution dont exist"
        );

        return
            DistributionWithoutClaimed({
                token: _distributions[distributionId].token,
                merkleRoot: _distributions[distributionId].merkleRoot
            });
    }

    /// @inheritdoc IAaveMerkleDistributor
    function addDistributions(
        address[] memory tokens,
        bytes32[] memory merkleRoots
    ) external override onlyOwner {
        require(
            tokens.length == merkleRoots.length,
            "MerkleDistributor: tokens not the same length as merkleRoots"
        );
        for (uint i = 0; i < tokens.length; i++) {
            uint256 currentDistributionId = _nextDistributionId;
            _distributions[currentDistributionId].token = tokens[i];
            _distributions[currentDistributionId].merkleRoot = merkleRoots[i];

            _nextDistributionId++;

            emit DistributionAdded(
                tokens[i],
                merkleRoots[i],
                currentDistributionId
            );
        }
    }

    /// @inheritdoc IAaveMerkleDistributor
    function isClaimed(
        uint256 index,
        uint256 distributionId
    ) public view override returns (bool) {
        require(
            distributionId < _nextDistributionId,
            "MerkleDistributor: Distribution dont exist"
        );
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        uint256 claimedWord = _distributions[distributionId].claimedBitMap[
            claimedWordIndex
        ];
        uint256 mask = (1 << claimedBitIndex);
        return claimedWord & mask == mask;
    }

    /// @inheritdoc IAaveMerkleDistributor
    function claim(TokenClaim[] calldata claim) external override {
        _claim(claim, msg.sender, msg.sender);
    }

    function claimOnBehalfOf(
        TokenClaim[] calldata claim,
        address onBehalfOf,
        address receiver
    ) external {
        _claim(claim, onBehalfOf, receiver);
    }

    /// @inheritdoc IAaveMerkleDistributor
    function emergencyTokenTransfer(
        address erc20Token,
        address to,
        uint256 amount
    ) external override onlyOwner {
        IERC20(erc20Token).safeTransfer(to, amount);
    }

    /// @inheritdoc IAaveMerkleDistributor
    function emergencyEtherTransfer(
        address to,
        uint256 amount
    ) external override onlyOwner {
        _safeTransferETH(to, amount);
    }

    /**
     * @dev set claimed as true for index on distributionId
     * @param index indicating which node of the tree needs to be set as true
     * @param distributionId id of the distribution we want to set claimed to true
     */
    function _setClaimed(uint256 index, uint256 distributionId) private {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        _distributions[distributionId].claimedBitMap[claimedWordIndex] =
            _distributions[distributionId].claimedBitMap[claimedWordIndex] |
            (1 << claimedBitIndex);
    }

    /**
     * @dev transfer ETH to an address, revert if it fails.
     * @param to recipient of the transfer
     * @param value the amount to send
     */
    function _safeTransferETH(address to, uint256 value) internal {
        (bool success, ) = to.call{ value: value }(new bytes(0));
        require(success, "ETH_TRANSFER_FAILED");
    }

    function getClaimer(address user) external view returns (address) {
        return _authorizedClaimers[user];
    }

    function _claim(
        TokenClaim[] calldata claim,
        address onBehalfOf,
        address receiver
    ) internal {
        for (uint256 i = 0; i < claim.length; i++) {
            require(
                claim[i].distributionId < _nextDistributionId,
                "MerkleDistributor: Distribution dont exist"
            );
            require(
                !isClaimed(claim[i].index, claim[i].distributionId),
                "MerkleDistributor: Drop already claimed."
            );

            require(
                onBehalfOf == msg.sender ||
                    _authorizedClaimers[onBehalfOf] == msg.sender,
                "CLAIMER_UNAUTHORIZED"
            );
            // Verify the merkle proof.
            bytes32 node = keccak256(
                abi.encodePacked(claim[i].index, onBehalfOf, claim[i].amount)
            );
            require(
                MerkleProof.verify(
                    claim[i].merkleProof,
                    _distributions[claim[i].distributionId].merkleRoot,
                    node
                ),
                "MerkleDistributor: Invalid proof."
            );

            // Mark it claimed and send the token.
            _setClaimed(claim[i].index, claim[i].distributionId);
            IERC20(_distributions[claim[i].distributionId].token).safeTransfer(
                receiver,
                claim[i].amount
            );

            emit Claimed(
                claim[i].index,
                onBehalfOf,
                claim[i].amount,
                claim[i].distributionId
            );
        }
    }
}
