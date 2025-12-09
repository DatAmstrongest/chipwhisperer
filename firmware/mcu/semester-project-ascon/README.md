# To test ascon on local (For MacOS)

```
gcc test_ascon.c ascon.c -o test
./test
```

# To test ascon on target

1. Connect your pc to the target
2. Run this command to create binaries
```
make PLATFORM=CWHUSKY CRYPTO_TARGET=NONE
```
3. Run this command to start tests
```
python3 target_test.py
```