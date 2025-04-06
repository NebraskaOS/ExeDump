# EXEd 1.0.0
Get information about any EXE file from the windows 1.0 Era (MZ and PE)

compile like
```
g++ -o exedump main.cpp mz.cpp -I.
```

run like
```
./exedump exe file path
```

# How to add more instructions:
Go to MZ.cpp and add the instruction to the switch statement in the analyzeMZExecutable function.
Scroll to the switch statement and add the new instruction to the list.