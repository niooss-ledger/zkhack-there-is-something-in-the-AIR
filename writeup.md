# Write-up for ZK Hack Mini puzzle #1: There's Something in the AIR

- Author: Nicolas IOOSS
- Date: 2022-03-04
- Puzzle: <https://www.zkhack.dev/puzzleM1.html>, <https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR>

## 1. Subject

```text
Alice implemented a Semaphore protocol to collect anonymous votes from her friends on various
topics. She collected public keys from 7 of her friends, and together with her public key, built
an access set out of them.

During one of the votes, Alice collected 9 valid signals on the same topic. But that should not be
possible! The semaphore protocol guarantees that every user can vote only once on a given topic.
Someone must have figured out how to create multiple signals on the same topic.

Below is a transcript for generating a valid signal on a topic using your private key. Can you
figure out how to create a valid signal with a different nullifier on the same topic?

============================================================
Built domain of 2^8 elements in 0 ms
Extended execution trace of 25 registers from 2^5 to 2^8 steps (8x blowup) in 0 ms
Committed to extended execution trace by building a Merkle tree of depth 8 in 0 ms
Evaluated constraints over domain of 2^8 elements in 2 ms
Converted constraint evaluations into 8 composition polynomial columns of degree 31 in 0 ms
Evaluated composition polynomial columns over LDE domain (2^8 elements) in 0 ms
Committed to composed evaluations by building a Merkle tree of depth 8 in 0 ms
Built DEEP composition polynomial of degree 31 in 0 ms
Evaluated DEEP composition polynomial over LDE domain (2^8 elements) in 0 ms
Computed 2 FRI layers from composition polynomial evaluations in 0 ms
Determined 32 query positions in 0 ms
Built proof object in 0 ms
---------------------
Signal created in 5 ms
Nullifier: fa9f5e2287b26f5fc91643a65ecfebbf308c6230283cd5c2a6a57ffe8a60e19d
Proof size: 19.6 KB
Proof security: 95 bits
---------------------
Signal verified in 1.4 ms
============================================================
```

## 2. Understanding the Protocol

This puzzle is about a voting system where participants can vote for a topic by signing a message.
The protocol relies on a hash function called Rescue Prime, specified in <https://eprint.iacr.org/2020/1143>.
As it is quite central to the protocol, let's start by describing this function.

In the puzzle, the actual function which is used is named `Rp64_256`.
It works on numbers modulo the prime number $M = 2^{64} - 2^{32} + 1$ (defined in [`winterfell::math::fields::f64`](https://github.com/novifinancial/winterfell/blob/v0.3.0/math/src/field/f64/mod.rs#L39-L40)).
As the set of numbers modulo $M$ is a finite field, its numbers are called *Felt* in the code, for "Field Element".

`Rp64_256` is an instance of Rescue Prime documented in <https://docs.rs/winter-crypto/0.3.2/winter_crypto/hashers/struct.Rp64_256.html> and implemented in <https://github.com/novifinancial/winterfell/blob/v0.3.0/crypto/src/hash/rescue/rp64_256/mod.rs>.
It works on a state of 12 *Felts*.
Its main function, called [`apply_permutation`](https://github.com/novifinancial/winterfell/blob/v0.3.0/crypto/src/hash/rescue/rp64_256/mod.rs#L235), mixes the content of the state by repeated a sequence of operations (called "round") 7 times.

Usually a hash function is defined to take as input some data of arbitrary size and return a digest of a fixed size.
In Winterfell, this is what [the function `Rp64_256::hash`](https://github.com/novifinancial/winterfell/blob/v0.3.0/crypto/src/hash/rescue/rp64_256/mod.rs#L95) does, the result being the 4 *Felts* at positions 4, 5, 6 and 7 of the state.
However in the puzzle, another function is used: [`Rp64_256::merge`](https://github.com/novifinancial/winterfell/blob/v0.3.0/crypto/src/hash/rescue/rp64_256/mod.rs#L153).

For example, [the function `Pubkey::new`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/lib.rs#L201) uses this function:

```rust
pub struct PubKey(Digest);

impl PubKey {
    /// Returns a [PubKey] instantiated from the provided private key.
    ///
    /// The key is computed simply as hash(priv_key, 0).
    pub fn new(priv_key: &PrivKey) -> Self {
        let priv_key_elements: [Felt; 4] = priv_key.elements();
        let priv_key_hash = Rescue::merge(&[priv_key_elements.into(), [Felt::ZERO; 4].into()]);
        Self(priv_key_hash)
    }
```

This code helps understanding the notions of private and public keys in the puzzle: a private key consists in 4 *Felts* and the public key is the `Rp64_256::merge` hash of the private key and four zeros.

Actually [`main.rs`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/main.rs#L23) defines a private key which can be displayed, in `main()`:

```rust
let my_key = PrivKey::parse(MY_PRIV_KEY);
println!("My private key is {:?}", my_key);
```

This shows the private key, with four 64-bit numbers:

```text
PrivKey([BaseElement(13206036382039558022), BaseElement(517331312156736027),
BaseElement(9198413848005809253), BaseElement(11948213059844406752)])
```

As the notation with `BaseElement` is quite heavy, it will be considered implicit when writing *Felt* numbers in this document.

It is possible to compute the public key directly:

```rust
use winterfell::{
    crypto::{hashers::Rp64_256 as Rescue, Hasher},
    math::fields::f64::BaseElement as Felt,
};

// ... in main:
let my_pub_key = Rescue::merge(&[
    [
        Felt::new(13206036382039558022),
        Felt::new(517331312156736027),
        Felt::new(9198413848005809253),
        Felt::new(11948213059844406752),
    ].into(),
    [Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0)].into(),
]);
println!("My public key is {:?}", my_pub_key);
println!("My hex public key is {:?}", hex::encode(my_pub_key.to_bytes()));
```

The computed public key is `[9011071827917972693, 10859627823097510656, 10746405100124929242, 18013997999185297261]`, with hexadecimal representation `d5a494b415c20d7d00fbace4f725b596da7c646d80e622956d7f09eebc93fef9`.
This matches the public key documented in [a comment in `main.rs`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/main.rs#L22).

Now, how does the voting system work, in the puzzle?
Each participant can sign a topic, producing digest named *nullifier*.
This algorithm is described [in `lib.rs`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/lib.rs#L25-L26) and is implemented using the same `Rp64_256::merge` function:

```rust
pub struct PrivKey([Felt; 4]);

impl PrivKey {
    pub fn get_nullifier(&self, topic: Digest) -> Digest {
        let key: Digest = self.0.into();
        // In the puzzle, winterfell::crypto::hashers::Rp64_256 is imported as Rescue
        Rescue::merge(&[key, topic])
    }
```

For example, when the participant with the previous private key votes for the topic `"The Winter is Coming..."` (which is hashed to `[4463284768739483164, 4599506553585284435, 12638017427182494382, 17795526900212791439]`), the computed *nullifier* is `[6876911449484992506, 13829375086194529993, 14039193556705512496, 11376480283806115238]`.
The hexadecimal representation of this *nullifier* is `fa9f5e2287b26f5fc91643a65ecfebbf308c6230283cd5c2a6a57ffe8a60e19d`.

The function `main` fails when the code produced a proof for this *nullifier*, [using `assert_ne!`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/main.rs#L79-L82):

```rust
assert_ne!(
    signal.nullifier.to_bytes(),
    hex::decode("fa9f5e2287b26f5fc91643a65ecfebbf308c6230283cd5c2a6a57ffe8a60e19d").unwrap()
);
```

So solving the puzzle requires producing a *signal* with the given private key and topic which does not use the expected *nullifier*.
But this should be impossible: a *signal* only consists in the *nullifier* and a proof which ensures that it was computed from the key and topic (this is the definition of a *signal*).

The puzzle likely consists in breaking the proof verification to enable using signals with unexpected *nullifier*.

## 3. Restricting Access with a Merkle Tree 

Before digging into the details of the proof itself, one may wonder: what is preventing an attacker from using a different private key?
Indeed, when verifying a signal, the private key is not used, and neither is the associated public key!

What happens if we try to use a different private key?
The program fails with:

```text
thread 'main' panicked at 'public key for the provided private key could not be found', src/lib.rs:118:14
```

Why does it fail?
The verification function is actually [`AccessSet::verify_signal`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/lib.rs#L139-L154):

```rust
/// Returns Ok(()) if the provided signal is a valid signal on the specified topic by someone
/// with a key from this access set.
pub fn verify_signal(&self, topic: &str, signal: Signal) -> Result<(), String> {
    // create public inputs for proof verification
    let pub_inputs = PublicInputs {
        tree_root: self.root(),
        nullifier: signal.nullifier,
        topic: Rescue::hash(topic.as_bytes()),
    };

    // check if the STARK proof is valid against the above public inputs
    match winterfell::verify::<SemaphoreAir>(signal.proof, pub_inputs) {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("proof verification failed: {}", err)),
    }
}
```

This relies on an object called "Merkle tree" and built from 8 public keys.
The private key has to match one of these keys.
Using a Merkle tree is a quite common way to ensure that an object belongs to a specific set of objects.
It works by progressively merging the objects using digests with two inputs (`Rp64_256::merge` is used again!).

More precisely with 8 public keys named `[Pub000, Pub001, Pub010, Pub011, Pub100, Pub101, Pub110, Pub111]`, computing a Merkle tree consists in:

- computing 4 digests: `H00 = merge(Pub000, Pub001)`, `H01 = merge(Pub010, Pub011)`, `H10 = merge(Pub100, Pub101)` and `H11 = merge(Pub110, Pub111)`.
- computing 2 digests: `H0 = merge(H00, H01)` and `H1 = merge(H10, H11)`
- computing 1 digest: `H = merge(H0, H1)`

The last digest is called "the root of the Merkle tree".
(Here the binary representation of numbers was used to better illustrate the merge logic.)

With such a tree, checking that the public key `Pub011` belongs to the set of 8 known public keys only takes 3 digest computations: `H01`, `H0` and `H`.

In the puzzle, the *signal* contains a proof about: "the used private key is associated with an allowed public key".
This proof computes 3 digests, and one more to derive the public key from the private key.

This is a very high-level description of how the "access check" works in the puzzle.
Now, how is the check actually implemented?

## 4. The AIR Prover

Quick recap of what has been presented so far: the puzzle is about a voting system which relies on *signals*.
A *signal* consists in a *nullifier* and a proof which ensures:

- this *nullifier* was actually generated by computing the digest of a private key with a specific vote topic ;
- and the public key associated with the private key is one of the 8 public key allowed to vote (using a Merkle tree).

Now it is time to dig a bit more about what the proof actually is.

The puzzle involves a STARK prover implemented in [project Winterfell](https://github.com/novifinancial/winterfell) to create a proof and to verify it.
This requires defining *AIR constraints* (*AIR* meaning "Algebraic Intermediate Representation"), [in `src/air/mod.rs`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/air/mod.rs):

```rust
fn get_assertions(&self) -> Vec<Assertion<Felt>> {
    let last_step = self.trace_length() - 1;
    vec![
        Assertion::single(4, last_step, self.tree_root[0]),
        Assertion::single(5, last_step, self.tree_root[1]),
        Assertion::single(6, last_step, self.tree_root[2]),
        Assertion::single(7, last_step, self.tree_root[3]),
        Assertion::single(16, 7, self.nullifier[0]),
        Assertion::single(17, 7, self.nullifier[1]),
        Assertion::single(18, 7, self.nullifier[2]),
        Assertion::single(19, 7, self.nullifier[3]),
        Assertion::single(20, 0, self.topic[0]),
        Assertion::single(21, 0, self.topic[1]),
        Assertion::single(22, 0, self.topic[2]),
        Assertion::single(23, 0, self.topic[3]),
    ]
}

fn evaluate_transition<E: FieldElement + From<Felt>>(
    &self,
    frame: &EvaluationFrame<E>,
    periodic_values: &[E],
    result: &mut [E],
) {
    // ...
    result.agg_constraint(1, hash_init_flag, are_equal(E::from(8u8), next[0]));
    result.agg_constraint(2, hash_init_flag, is_zero(next[1]));
    result.agg_constraint(3, hash_init_flag, is_zero(next[2]));
    result.agg_constraint(4, hash_init_flag, is_zero(next[3]));

    result.agg_constraint(4, hash_init_flag, not_bit * are_equal(current[4], next[4]));
    result.agg_constraint(5, hash_init_flag, not_bit * are_equal(current[5], next[5]));
    result.agg_constraint(6, hash_init_flag, not_bit * are_equal(current[6], next[6]));
    result.agg_constraint(7, hash_init_flag, not_bit * are_equal(current[7], next[7]));

    result.agg_constraint(8, hash_init_flag, bit * are_equal(current[4], next[8]));
    result.agg_constraint(9, hash_init_flag, bit * are_equal(current[5], next[9]));
    result.agg_constraint(10, hash_init_flag, bit * are_equal(current[6], next[10]));
    result.agg_constraint(11, hash_init_flag, bit * are_equal(current[7], next[11]));

    // enforce that values in the bit column must be binary
    result[24] = is_binary(current[24]);

    result.agg_constraint(25, key_cmp_flag, are_equal(current[4], current[16]));
    result.agg_constraint(26, key_cmp_flag, are_equal(current[5], current[17]));
    result.agg_constraint(27, key_cmp_flag, are_equal(current[6], current[18]));
    result.agg_constraint(28, key_cmp_flag, are_equal(current[7], current[19]));
```

At first, this code is difficult to understand.

A key factor to achieve understanding it is to consider that it works on an *execution trace* produced by [function `SemaphoreProver::build_trace`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/prover.rs#L16).
Instead of showing more Rust code, let's describe what this function does in English: it fills a table with values.
Each line of the table contains a state of the *program* while it is being executed.
The lines are arranged in chronological order, which enables building them one after another.
Each column of the table contains the values that a variable takes through the program execution (using type *Felt*).

This table is called *execution trace*.

In this model, *AIR constraints* mainly consists in equations which ensures that the table is consistent.
Some of these constraints ensure that the values of the table match some expected values (named *public inputs*).
This is what [function `SemaphoreAir::get_assertions`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/air/mod.rs#L120) is about.

Other constraints ensure that each pair of consecutive lines is coherent with the execution of the executed program.
This is what [function `SemaphoreAir::evaluate_transition`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/air/mod.rs#L147) is about.

In the puzzle, the *execution trace* contains 25 columns (this is [the constant `TRACE_WIDTH`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/lib.rs#L294-L295)):

- The first 12 columns are used to compute the `Rp64_256` digests used to ensure that the used private key authenticates a voter (using the Merkle tree which was described in the previous section).
- The next 12 columns (columns 12 to 23) are used to compute the *nullifier*, with a single `Rp64_256` digest.
- The last column (column 24) is used to store the bit which defines the path in the Merkle tree.

The Rescue Prime family of functions was designed to be easily integrated to such a proof mechanism.
Here, computing the function `Rp64_256::merge` only takes 8 lines in the *execution trace*, including the one with the input and the one with the output (there are 7 state transitions).

To display the *execution trace* produced by `SemaphoreProver::build_trace`, the puzzle provides [a function named `print_trace` in `src/lib.rs`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/lib.rs#L301).
Its arguments are quite complex, but it is possible to display the full content of a *trace* using:

```rust
print_trace(&trace, 1, 0, 0..trace.width());
```

In the puzzle, adding this statement without modifying anything else produces a verbose output, presented here with some editing (each line of the *execution trace* is showed with its index and the 25 columns ; some lines were removed):

```text
0 [
    8, 0, 0, 0,
    13206036382039558022, 517331312156736027, 9198413848005809253, 11948213059844406752,
    0, 0, 0, 0,
    8, 0, 0, 0,
    13206036382039558022, 517331312156736027, 9198413848005809253, 11948213059844406752,
    4463284768739483164, 4599506553585284435, 12638017427182494382, 17795526900212791439,
    0]
...
7 [
    4495072513865720712, 3945887069796286958, 7608938753899010961, 12753112536029537235,
    9011071827917972693, 10859627823097510656, 10746405100124929242, 18013997999185297261,
    6262117207064384356, 8137730120197750425, 9014490610598049618, 6202340900709085247,
    2544543745636817775, 3722459418433538504, 16604079892499542577, 13870241195418460083,
    6876911449484992506, 13829375086194529993, 14039193556705512496, 11376480283806115238,
    14167707770871314971, 9342513938821057136, 14118317453594014171, 13804027170305889596,
    0]

8 [
    8, 0, 0, 0,
    12767808730495469206, 13244458061434156287, 90024575623735950, 3952986473822358277,
    9011071827917972693, 10859627823097510656, 10746405100124929242, 18013997999185297261,
    0, 0, 0, 0,
    12767808730495469206, 13244458061434156287, 90024575623735950, 3952986473822358277,
    0, 0, 0, 0,
    1]
...
15 [
    14977717683162532750, 14154994633393897290, 16698750712706620174, 2067134382449834562,
    11469976317309306406, 13211206706221544421, 6023305737523924235, 18123275983713439981,
    9453492606893831337, 13587706164553967950, 7226476370645943312, 4333443327009036446,
    18211128941273630638, 12311304489072097823, 1020681897697711773, 12271037525563400351,
    12389724262586096612, 3929794568111164299, 460075759196148733, 6827686422677208125,
    10073405123736664229, 4068200492475514038, 6992159010814283593, 7965127157560534259,
    1]

16 [
    8, 0, 0, 0,
    15786494477146823530, 1713230857413052153, 7243537621107966370, 1671580013135355408,
    11469976317309306406, 13211206706221544421, 6023305737523924235, 18123275983713439981,
    0, 0, 0, 0,
    15786494477146823530, 1713230857413052153, 7243537621107966370, 1671580013135355408,
    0, 0, 0, 0,
    1]
...
23 [
    8252439170008481175, 17476044035220767421, 2966607087398280325, 12664552146924248073,
    5738647880366151377, 3664659757383124955, 2499700430251413809, 13944835640354141017,
    7317789083260869199, 1817615442339827779, 8472076286993936317, 10720304920789424840,
    3589121175498445699, 2070927790607594441, 9917528343697821668, 553296083189542283,
    2668754990366237872, 2559547244344607087, 13265515656789382261, 2523990240256099207,
    4826828561030004019, 7528052080501435936, 3010271262553190431, 15614414327944631647,
    1]

24 [
    8, 0, 0, 0,
    5738647880366151377, 3664659757383124955, 2499700430251413809, 13944835640354141017,
    4954685324544117415, 4734294503183843428, 14490376437082051470, 12676700936937265717,
    0, 0, 0, 0,
    5738647880366151377, 3664659757383124955, 2499700430251413809, 13944835640354141017,
    0, 0, 0, 0,
    0]
...
31 [
    1314755571124399985, 17915854223114358381, 2202123205813867130, 2121689688354877839,
    9696724157787789154, 10947061792565826340, 18400246858674580916, 11224380513111398973,
    16725808170089551038, 15730814575649187410, 16313246056814023579, 3005820286158783349,
    2657411158956549623, 1042424696067694541, 2882817449524482140, 4437139921733564096,
    15395137395998714958, 10279084829974181745, 255930003268076249, 17598058371392041670,
    5387173287646466781, 9154016989582401961, 4122139480851985720, 847098563960991490,
    0]
```

Here are some observations:

- The first line (index 0) contains the private key twice (`13206036382039558022, ...`): it is first used to prove it is associated to a known public key, and a second time to compute the *nullifier*.
- The first line also contains the digest of the topic (`4463284768739483164, ...`).
- Line 7 contains two final 12-*Felt* states of the end of a `Rp64_256` digest computation. The actual digests are located in columns 4, 5, 6 and 7 for the public key (`9011071827917972693, ...`) and in columns 16, 17, 18 and 19 for the *nullifier* (`6876911449484992506, ...`). The fact that these digests are precisely in the middle of the `Rp64_256` state is by definition of this hash function.
- Line 8 contains the public key again, and another public key. They are the inputs of the computation `H01 = merge(Pub010, Pub011)`, used to verify that a public key is part of a Merkle tree. As the used private key is the second input, the last column is 1.
- Line 15 contains result of the computation: `H01` (`11469976317309306406, ...`).
- Line 16 contains the inputs of `H0 = merge(H00, H01)`. As the previous digest is the second input, the last column is 1.
- Line 23 contains the result: `H0` (`5738647880366151377, ...`).
- Line 24 contains the inputs of `H = merge(H0, H1)`. As the previous digest is the first input, the last column is 0.
- Line 31 contains the result: `H` (`9696724157787789154, ...`). It is the root of the Merkle tree.

With these observations, the constraints implemented in [`src/air/mod.rs`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/air/mod.rs) make more sense.
They actually ensure that the trace computes several `Rp64_256` digests, that the values get propagated correctly, and that the topic digest, the *nullifier* and the root of the Merkle tree match the inputs given to the function which verifies a produced proof.

At first, this seems to be implemented correctly.
What's the catch?

## 5. Trying to Find Something in the AIR

When looking at the *execution trace*, the *AIR constraints* and the way the proof included in a *signal* is verified, one may wonder: how is the private key actually verified?

This question appears to be easy to answer:

- The proof ensures that the private key which was set in columns 4, 5, 6 and 7 in the first line of the *trace* is associated with one of the 8 public keys (by ensuring that 4 `Rp64_256` digests were computed correctly and that the results match the root of the Merkle tree built from all the keys).
- The proof ensures that the private key which was set in columns 16, 17, 18, 19 in the first line of the *trace* is used to compute the *nullifier* of the *signal* (by ensuring that the `Rp64_256` digest was computed correctly, that the first line also contains the digest of the topic and that line 7 contains the *nullifier*).

Do the constraints also ensure that these two copies of the private key were equals?
Yes, they do, and [there is actually a comment about this in the code](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/air/mod.rs#L210-L216):

```rust
// finally, we need to make sure that at steps which are multiples of 8 (e.g. 0, 16, 32 etc.)
// values in columns [4, 5, 6, 7] are the same as in columns [16, 17, 18, 19]; technically,
// we care about this only for step 0, but it is easier to enforce it for all multiples of 8
result.agg_constraint(25, key_cmp_flag, are_equal(current[4], current[16]));
result.agg_constraint(26, key_cmp_flag, are_equal(current[5], current[17]));
result.agg_constraint(27, key_cmp_flag, are_equal(current[6], current[18]));
result.agg_constraint(28, key_cmp_flag, are_equal(current[7], current[19]));
```

This code relies on [functions defined in `src/air/utils.rs`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/air/utils.rs), which actually do:

```rust
result[25] += key_cmp_flag * (current[4] - current[16]);
result[26] += key_cmp_flag * (current[5] - current[17]);
// ...
```

For the proof to be correct, all *Felts* in the `result` array need to be zero, for each pair of lines of the *execution trace*.

Here, the computation involves a periodic value `key_cmp_flag` which is 1 on the first line (because it is the first value of [`KEY_CMP_MASK` in `src/air/mod.rs`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/air/mod.rs#L241)).
Therefore this code actually requires that on the first line of the *trace*, columns 4 and 16 are equal, columns 5 and 17 too, etc.

In short, the *AIR constraints* successfully ensure that the two copies of the private key are equal.
No issue so far... Is there something missing?

## 6. The Missing Piece of the Puzzle

Taking a look at the *execution trace*, the sequence `8, 0, 0, 0` which appears when starting each the digest computation seems to be important.
For columns 0, 1, 2 and 3, this is verified [in function `SemaphoreAir::evaluate_transition`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/air/mod.rs#L189-L192):

```rust
result.agg_constraint(1, hash_init_flag, are_equal(E::from(8u8), next[0]));
result.agg_constraint(2, hash_init_flag, is_zero(next[1]));
result.agg_constraint(3, hash_init_flag, is_zero(next[2]));
result.agg_constraint(4, hash_init_flag, is_zero(next[3]));
```

But where is this check for columns 12, 13, 14 and 15?
Nowhere!
This means that in the *trace*, it is possible to use other values when computing the *nullifier*.

To give it a try, let's try to use 9 instead of 8!
Function `AccessSet::make_signal` also need to be modified to retrieve the *nullifier* from the *trace* instead of computing it separately.

```diff
diff --git a/src/lib.rs b/src/lib.rs
index 6c9fcb261016..33fceb8c1e09 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -124,12 +124,19 @@ impl AccessSet {
             .expect("failed to build a Merkle path for key index");
 
         // compute the nullifier for this key and topic
-        let nullifier = priv_key.get_nullifier(topic);
+        //let nullifier = priv_key.get_nullifier(topic);
 
         // build the proof asserting that the key is in the access set and that if hashed with
         // the specified topic it produces a given nullifier.
         let prover = SemaphoreProver::default();
         let trace = prover.build_trace(priv_key, key_idx, topic, &key_path);
+        // retrieve the nullifier from the trace
+        let nullifier = Digest::from([
+            trace.get(16, 7),
+            trace.get(17, 7),
+            trace.get(18, 7),
+            trace.get(19, 7),
+        ]);
         let proof = prover.prove(trace).expect("failed to generate proof");
 
         // return the signal
diff --git a/src/prover.rs b/src/prover.rs
index 7a03783e2151..f5af17b9e99a 100644
--- a/src/prover.rs
+++ b/src/prover.rs
@@ -49,7 +49,7 @@ impl SemaphoreProver {
                 state[11] = Felt::ZERO;
 
                 // -- nullifier section of the trace --
-                state[12] = Felt::new(8);
+                state[12] = Felt::new(9);
                 state[13] = Felt::ZERO;
                 state[14] = Felt::ZERO;
                 state[15] = Felt::ZERO;
```

This works!

```text
$ cargo run --release
...
Signal created in 5 ms
Nullifier: aac9702c5dbb348dcc1456d236b26ff08a05bedf5278639a1a6719478949c0f1
Proof size: 19.9 KB
Proof security: 95 bits
---------------------
Signal verified in 1.2 ms
============================================================
```

The program create a new *nullifier* with a proof which was accepted.

This enables any participant to forge many *signals* for a single vote (by replacing each *Felts* `(8, 0, 0, 0)` with another one, so there are $M^4 - 1$ possibilities).

This is a powerful attack against this voting system, but still requires knowing a private key.

## 6. The Dangerous Misspelling

There is a misspelling in the *AIR constraints* implemented [in function `SemaphoreAir::evaluate_transition`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/air/mod.rs#L192-L194):

```rust
result.agg_constraint(4, hash_init_flag, is_zero(next[3]));

result.agg_constraint(4, hash_init_flag, not_bit * are_equal(current[4], next[4]));
```

The constraint index 4 is used twice!
Can this be used to break the protocol?

To better understand what is happening, here is the same code where the functions have been inlined:

```rust
not_bit = Felt::ONE - next[24];
result[4] += hash_init_flag * next[3];
result[4] += hash_init_flag * not_bit * (current[4] - next[4]);
```

In this code:

- `hash_init_flag` is a periodic value which is 1 on lines 7, 15 and 23, and which is 0 otherwise (because it is the boolean negation of [`HASH_CYCLE_MASK` defined in `src/air/mod.rs`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/air/mod.rs#L229-L238)).
- `current` and `next` are the lines of the *trace* which are being verified.
- `not_bit` is the boolean negation of `next[24]`, which contains a bit related to Merkle tree computation.

So, when `SemaphoreAir::evaluate_transition` operates on the pair of lines 7 and 8 of the *trace* and when `next[24]` is set to zero (by an attacker), the buggy constraint becomes:

```rust
// next contains line 8 of the trace
result[4] += next[3] + current[4] - next[4];
```

This constraint is weak and enables tampering with the computations related to the Merkle tree!

More precisely, line 8 contains the inputs of a computation which was previously written `H01 = merge(Pub010, Pub011)`.
In this context:

- The computation normally initializes the 12 first *Felts* of line 8 of the *trace* to `(8, 0, 0, 0)` followed by `Pub010` and `Pub011`.
- The condition "`next[24]` is zero" in the context of the implement Merkle tree algorithm means that line 7 of the *trace* is supposed to contain `Pub010`.
- Actually, the condition `are_equal(current[4], next[4])` ensures that line 7 really contains `Pub010`, and more specifically the first *Felt* of this digest, which will be named `Pub010[0]`.
- The misspelling weakens the condition: now line 7 only needs to contain `Pub010[0] - next[3]`, where `next[3]` is the value in column 3, line 8 of the *trace* (this is normally the last zero of `(8, 0, 0, 0)`.

However if this `next[3]` is modified, the result of the `Rp64_256` computation on line 15 is likely to be modified, which would modify the following digests until the computed root of the Merkle tree.
This is a problem for the attacker, as this last digest needs to be a predefined value.

If we consider `Rp64_256` to be a secure hash function, being able to modify a single *Felt* (or two) of the state without modifying the computed digest is too difficult.

In short, the *AIR constraints* contain a dangerous issue, which does not seem to be exploitable in practice.

## 7. Another Missing Piece

The previous section focused on a constraint between two digest computations of the Merkle tree.
And this reveals that something is missing in the *AIR constraints*: the initial state of the first digest computation is not checked!

Indeed, [function `SemaphoreAir::evaluate_transition`](https://github.com/kobigurk/zkhack-there-is-something-in-the-AIR/blob/30fcf5312fc0fa78c57ecfed58c0ec7af002453c/src/air/mod.rs#L189-L192) contains:

```rust
result.agg_constraint(1, hash_init_flag, are_equal(E::from(8u8), next[0]));
result.agg_constraint(2, hash_init_flag, is_zero(next[1]));
result.agg_constraint(3, hash_init_flag, is_zero(next[2]));
result.agg_constraint(4, hash_init_flag, is_zero(next[3]));
```

The previous section presented that `hash_init_flag` is a periodic value which is 1 on lines 7, 15 and 23 of the *trace*.
But what about the first line?

These constraints would not make much sense as-is, because `next` would be the second line (`current` would need to be used, to check constraints on the first line).

In fact, the first *Felts* of the first line are never checked!
The sole constraints for the first line are:

- the two copies of the private key are equal ;
- columns 20 to 23 contains the digest of the topic ;
- column 24 contains either 0 or 1.

From the perspective of an attacker, this is paradise! The initial state of the `Rp64_256` computation is not verified.

And this can be exploited to forge a valid *signal* without knowing any valid private key :)

How?

- Line 7 needs to contain a known public key in columns 4, 5, 6 and 7. Let's use the first public key for this.
- Lines 6, 5, ... 0 are then computed by inverting the `Rp64_256` permutation, in the first 12 columns of the *trace*.
- Line 0 does not contain a valid state for a real `Rp64_256` computation (it is very unlikely that it starts with `(8, 0, 0, 0)`, but this does not matter as this state is not verified.
- The fake private key is extracted from the columns 4, 5, 6 and 7 from the line 0 and copied to columns 16, 17, 18 and 19.
- The *nullifier* is then computed normally.

The resulting trace fulfills the *AIR constraints* of the puzzle!

In practice, here is the code of this attack:

```rust
pub fn forge_signal() -> Signal {
    // Target the first public key
    let pub_keys = PUB_KEYS
        .iter()
        .map(|&k| PubKey::parse(k))
        .collect::<Vec<_>>();
    let first_pubkey = pub_keys[0].elements();
    let mut rescue_state = [
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        first_pubkey[0],
        first_pubkey[1],
        first_pubkey[2],
        first_pubkey[3],
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];

    // Reverse Rp64_256 algorithm
    for round in (0..7).rev() {
        // Reverse add_constants
        rescue_state
            .iter_mut()
            .enumerate()
            .for_each(|(i, s)| *s -= ARK2[round][i]);
        // Reverse apply_mds
        apply_inv_mds(&mut rescue_state);
        // Reverse apply_inv_sbox
        rescue_state.iter_mut().for_each(|s| *s = s.exp(7));
        // Reverse add_constants
        rescue_state
            .iter_mut()
            .enumerate()
            .for_each(|(i, s)| *s -= ARK1[round][i]);
        // Reverse apply_mds
        apply_inv_mds(&mut rescue_state);
        // Reverse apply_sbox
        rescue_state
            .iter_mut()
            .for_each(|s| *s = s.exp(10540996611094048183));
    }

    // Initialize a trace with 25 columns and 32 lines
    let mut trace = TraceTable::new(25, 32);

    // Copy the fake initial Rescue state
    let mut trace_state = [Felt::ZERO; 25];
    trace_state[..12].clone_from_slice(&rescue_state[..12]);

    // Initialize the nullifier computation
    let topic_hash: [Felt; 4] = Rescue::hash(TOPIC.as_bytes()).into();
    trace_state[12] = Felt::new(8);
    trace_state[16..20].clone_from_slice(&rescue_state[4..8]);
    trace_state[20..24].clone_from_slice(&topic_hash);
    trace.update_row(0, &trace_state);

    // Compute the nullifier
    for round in 0..7 {
        apply_rescue_round(&mut trace_state[..12], round);
        apply_rescue_round(&mut trace_state[12..24], round);
        trace.update_row(round + 1, &trace_state);
    }

    // Save the computed nullifier
    let nullifier = <Rescue as Hasher>::Digest::from([
        trace_state[16],
        trace_state[17],
        trace_state[18],
        trace_state[19],
    ]);

    // Compute the Merkle tree for the public keys
    let leaves = pub_keys
        .iter()
        .map(|p| <Rescue as Hasher>::Digest::new(p.elements()))
        .collect::<Vec<_>>();
    assert_eq!(leaves.len(), 8);
    let key_tree: MerkleTree<Rescue> = MerkleTree::new(leaves).unwrap();
    let merkle_path = key_tree.prove(0).unwrap();
    assert_eq!(merkle_path.len(), 4);
    assert_eq!(<[Felt; 4]>::from(merkle_path[0]), first_pubkey);

    // Fill the trace
    for cycle_num in 1..4 {
        trace_state[0] = Felt::new(8);
        trace_state[1] = Felt::ZERO;
        trace_state[2] = Felt::ZERO;
        trace_state[3] = Felt::ZERO;
        let path_node: [Felt; 4] = merkle_path[cycle_num].into();
        path_node
            .iter()
            .enumerate()
            .for_each(|(i, v)| trace_state[8 + i] = *v);
        for i in 12..25 {
            trace_state[i] = Felt::ZERO;
        }
        trace_state[16] = trace_state[4];
        trace_state[17] = trace_state[5];
        trace_state[18] = trace_state[6];
        trace_state[19] = trace_state[7];
        trace.update_row(8 * cycle_num, &trace_state);

        for round in 0..7 {
            apply_rescue_round(&mut trace_state[..12], round);
            apply_rescue_round(&mut trace_state[12..24], round);
            trace.update_row(8 * cycle_num + round + 1, &trace_state);
        }
    }

    // Set a bit to one to ensure the constraint degree is not zero, without
    // actually changing the validity of the execution trace.
    // Otherwise, running in debug mode fails.
    trace.set(24, 1, FieldElement::ONE);

    // Display the generated trace
    print_trace(&trace, 1, 0, 0..25);

    // Generate a proof
    let prover = SemaphoreProver::default();
    let proof = prover.prove(trace).expect("failed to generate proof");
    Signal { nullifier, proof }
}
```

This function can be copied in `main.rs` and used directly, once some files are also modified to make some functions and data public:

```diff
In src/air/mod.rs
-mod rescue;
+pub mod rescue;

In src/air/rescue.rs
-fn apply_inv_mds<E: FieldElement + From<Felt>>(state: &mut [E; STATE_WIDTH]) {
+pub fn apply_inv_mds<E: FieldElement + From<Felt>>(state: &mut [E; STATE_WIDTH]) {

-const ARK1: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = [
+pub const ARK1: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = [

-const ARK2: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = [
+pub const ARK2: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = [

In src/lib.rs
-mod air;
+pub mod air;

-mod prover;
+pub mod prover;

In src/main.rs
-use semaphore::{AccessSet, PrivKey, PubKey};
+use semaphore::{
+    air::rescue::{apply_inv_mds, ARK1, ARK2},
+    print_trace,
+    prover::{apply_rescue_round, SemaphoreProver},
+    AccessSet, PrivKey, PubKey, Signal,
+};
+use winterfell::{
+    crypto::{hashers::Rp64_256 as Rescue, Hasher, MerkleTree},
+    math::{fields::f64::BaseElement as Felt, FieldElement},
+    Prover, TraceTable,
+};

In src/prover.rs
-fn apply_rescue_round(state: &mut [Felt], round: usize) {
+pub fn apply_rescue_round(state: &mut [Felt], round: usize) {
```

With these changes, replacing `access_set.make_signal(&my_key, TOPIC)` with `forge_signal()` in `main()` produces a valid *signal* using the first public key, even though we did not know the private key:

```text
---------------------
Signal created in 6 ms
Nullifier: 05321040103b38da154baabbf2e7e56efb562d4dbdfeb30c058f17a25e5e2c4b
Proof size: 19.5 KB
Proof security: 95 bits
---------------------
Signal verified in 1.3 ms
============================================================
```

The full code of this attack is available on <https://github.com/niooss-ledger/zkhack-there-is-something-in-the-AIR>.

## Conclusion

The puzzle uses *AIR constraints* to ensure that a *signal* is valid for a given topic, meaning that its *nullifier* was generated from an private key which is allowed to vote.
One of the main objective of the protocol is to guarantee that a voter cannot produce several *nullifiers* for a single topic.

However the puzzle contains two vulnerabilities caused by missing constraints.
They enable attackers to forge valid *signals* without knowing any private key!

Both these vulnerabilities can be fixed by adding constraints which ensure the initial state of the hash function is valid.
