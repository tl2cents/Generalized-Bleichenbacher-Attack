# Generalized Bleichenbacher's RSA Padding Oracle Attack

## Attack info

This repository implements the generalized Bleichenbacher' attack. For any fixed padding prefix and an oracle returning the "Good Padding"  or "Bad padding" information of the decrypted ciphertext, you can use the `rsa_prefix_padding_oracle_attack` to decrypt ciphertext. This implementation is mainly modified from [Karim Kanso's codes](https://gist.github.com/kazkansouh/e4d710c6a6928187323fa164bdd70401). 



## Related CTF challenges

See : 

- SECCON CTF 2022 - this is not lsb - [writeup](https://imp.ress.me/blog/2022-11-13/seccon-ctf-2022/#this-is-not-lsb) .
- DUCTF 2022  - rsa interval oracle - [writeup](https://github.com/DownUnderCTF/Challenges_2022_Public#crypto).
- SekaiCTF 2022 - EZmaze - [writeup](https://jsur.in/posts/2022-10-03-sekai-ctf-2022-ezmaze-writeup).



## Example

Decrypt ciphertext of unpadded message :

``` python
oracle_prfix = bin(1145)[2:].zfill(11)
choose_plaintext = b"flag{this_is_a_sample_flag_for_testing!}"    
ciphertext, oracle, e, n = local_setup(oracle_prfix,choose_plaintext)
rsa_prefix_padding_oracle_attack(n,e,ciphertext,oracle_prfix,oracle)
```

Decrypt ciphertext of padded message ( step 1 is skipped ) :

``` python
oracle_prfix = bin(11451)[2:].zfill(16)
choose_plaintext = pad_message(oracle_prfix , 1024//8 , b"flag{this_is_a_sample_flag_for_testing!}")
ciphertext, oracle, e, n = local_setup(oracle_prfix,choose_plaintext)
rsa_prefix_padding_oracle_attack(n,e,ciphertext,oracle_prfix,oracle)
```

