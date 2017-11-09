# Smashing the Stack by e41c m.

## What is a Buffer Overflow Exploit?

In ASM and many C/C++ implementations, if you allocate an array and add more items to the array that it can contain, it will let you. In ASM, any memory (belonging to your program) can be accessed and manipulated by assembly instructions.

Many programs take in user input in the form of strings (arrays of BYTEs). It is very common to need to make a copy of a string and store it elsewhere for further processing. Maybe you have a function that takes a string and returns a capitalized version.

Given a vulnerable program, a malicious user can enter certain input, to specifically overwrite key areas of memory such that your program is hijacked so that instead of running its own code, it runs code that the user encoded into their malicious string.

## Organization of Memory

| Contents                                | Memory Addresses |
| --------------------------------------- | ---------------- |
| .....                                   | 0000000          |
| TEXT - Your programs code               | ...              |
| DATA - Uninitialized + Initialized data | ...              |
| STACK                                   | ...              |
| .....                                   | FFFFFFFF         |



## The Stack

The stack is an area of memory where you can PUSH things and POP things.

The stack grows downward towards the lower memory locations.

The top of the stack faces the lower memory addresses while the bottom of the stack faces the higher memory addresses.

What that means is that when you add a new item to the stack, its memory location is smaller than the item under it.

For example imagine PUSHing three bytes 'a', 'b', 'c' in that order. Memory might look like this.

| Stack Content | Memory Location |
| ------------- | --------------- |
| 'c'           | FFAABB00        |
| 'b'           | FFAABB01        |
| 'a'           | FFAABB02        |

Notice the location for 'c' has a smaller value than 'a'.

## The Forbidden Register (EIP)

The EIP register holds the memory location of the next instruction to execute.

| Location | Instruction               |
| -------- | ------------------------- |
| FFAAAA04 | mov EAX, 10 **(current)** |
| FFAAAA08 | mov ebx, 2                |
| FFAAAA0C | mov ecx, 2                |

If `mov EAX, 10 ` is the last instruction to have executed then EIP holds FFAAAA08 since that is the memory location of the next instruction. The CPU then pulls the address at EIP, looks at the instruction at that address, then executes it.

<u>Remember the first rule of EIP:</u>
**YOU DON'T TOUCH EIP.** *(directly)*

## CALL / RET

CALL and RET are really simple.

Imagine you had a procedure funky and a main:

```
funky PROC
	mov eax, 99
	ret
funky ENDP

main PROC
	call funky
	mov ebx, 10
	...
main ENDP
```

any time you call that procedure, EIP would just be modified so that execution is redirected to that line of ASM. The ret instruction takes you back to where you were before, by restoring EIP to what it should have been before you called it.

| human | Memory Location | Code                       |
| ----- | --------------- | -------------------------- |
| funky | FFAABB00        | mov eax, 99                |
|       | FFAABB04        | ret                        |
| main  | FFAABB05        | call funky / call FFAABB00 |
|       | FFAABB09        | mov ebx, 10                |



When you `call funky` EIP would then get loaded with FFAABB00. Then the procedure code would execute then you hit `ret`.  Since after the procedure call we want to do `mov ebx, 10`, the call instruction pushes `FFAABB09` to the stack. The `ret` command will POP from the stack and move what it popped into register EIP.  After the procedure returns in this example, EIP would contain FFAABB09 so that execution can resume under the procedure call.

**Key takeaway: The memory location of where to go back to when a  procedure finishes is stored on the STACK by the CALL instruction.**



## Local Variables

Local variables exist on the stack.

The following C code

```c++
void funk(){
  int a;
}
```

has a local variable.



The line `int a;` is compiled to `sub esp, 4` in assembly. Four bytes are reserved since an integer in C/C++ is a DWORD (4 bytes) in assembly.

What? I know I know. Hold your horses. You see it makes a lot of sense. ESP points to the top of the stack. So if I just push the 'top' of the stack four bytes down, I've reserved some space to store something in the middle.

Why subtraction? Well the stack grows towards the smaller memory addresses, so by subtracting I actually make the stack bigger by 4 bytes. 

So by moving the top of the stack over, I reserve space in the middle for things. That space is the space for variable a. Provided I know where the location is, I can always access it.

This is how C/C++ implement local variables.

## Local arrays and the Stack

Consider the following C code.

The following C code

```c++
void funk(){
  char str[] = "hello";
  int b=4;
}
```

with two local variables. 

Here is what that would look like on the stack.

| Greedy | Human       | Memory Location | Stack |
| ------ | ----------- | --------------- | ----- |
| str[0] | str[0]      | FFAACC00        | 'h'   |
| str[1] | str[1]      | FFAACC01        | 'e'   |
| str[2] | str[2]      | FFAACC02        | 'l'   |
| str[3] | str[3]      | FFAACC03        | 'l'   |
| str[4] | str[4]      | FFAACC04        | 'o'   |
| str[5] |             | FFAACC05        | 0     |
| str[6] | b (4 bytes) | FFAACC06        | 00    |
| str[7] |             | FFAACC07        | 00    |
| str[8] |             | FFAACC08        | 00    |
| str[9] |             | FFAACC09        | 04    |



### "Memory knows no bounds" -Gandalf

Ok he didn't say that. But! It is entirely possible in certain versions of C/C++ to overwrite the contents of variable **b** by simply being greedy about **str**. You can access any memory location with the right index relative to the starting memory address of str. Any memory location can be accessible by going the right number of bytes into or away from location str. Therefore we can overwrite the values for variable **b** by overwriting str[6], str[7], str[8], and str[9].

**But those aren't part of the string, you can't access those ?!?!?**

Unfortunately, on many implementations of C/C++ you can.



## C/C++ Functions / Function Calls

The following C code

```c++
void funk(){
  int a;
  a=9;
}
```

has a local variable.

It compiles to:

```
PUSH EBP
MOV EBP, ESP

;an int is a DWORD and so 4 bytes is allocated on the stack
SUB ESP, 4 
MOV DWORD PTR [ebp + 4], 9

MOV ESP, EBP
POP EBP
RET
```



**<u>Whats with all the EBP stuff?</u>**

Good question. The EBP register is used to store what ESP was before you starting messing around with the stack (because your program might make local variables and make it bigger). EBP then stores the value of what ESP was before the function was called.



**<u>Breakdown</u>**

* EBP is saved to the stack
* Then ESP is backed up into EBP. It is backed up into a register so it can be used for addressing the local variables.
* Then the space for the variable is allocated. 
* 9 is moved into the reserved space using EBP to index
* Then  ESP is restored
* Then EBP is restored
* Function returns by popping return value from stack into EIP



**<u>Inside the heart of a function (forget all the setup and teardown)</u>**

Register ESP holds the memory location of the END of the stack.

Register EBP holds the value of ESP before your function messed with it. Your stack may continue to grow inside a function (local variables, push/pop) and so ESP might change.



**<u>What memory looks during funk() call right after variable is initialized:</u>**



```
PUSH EBP
MOV EBP, ESP

SUB ESP, 4 ;an int is a DWORD and so 4 bytes is allocated on the stack

POP EBP
RET
```

|                  |          |          | STACK       |
| ---------------- | -------- | -------- | ----------- |
| variable a       | ESP ---> | FFAABB00 | 00 00 00 09 |
| this was pushed  | EBP----> | FFAABB04 | ebp value   |
| CALL pushed this |          | FFAABB08 | ret address |



The last thing on the stack is the variable, thats why ESP points there. EBP points to the beginning of the STACK use in the function. First thing pushed was EBP.



## The Attack / strcpy

If at any point a program allows the user to input a string, many times that string is copied to the destination **<u>WITHOUT LOOKING THAT THERE IS SPACE FOR IT.</u>**

This happens when a program uses the **strcpy** method. It is unsafe. Never use it!!!!

When this happens, memory that did not belong to the string is overwritten. In this example, the 4 bytes following the string on the stack is the value of EBP (gets pushed onto the stack by the resulting assembly).

The next 4 bytes after that is the value for the return address for where to go when **bad()** has finished executing. The return address is supposed to point to the assembly code that would show "today is the best".



```c++
void bad(char *input){
   char small[5];
   //copies input string to small string
   strcpy(small, input);
}

void main(){
  bad("ohnothisisbad");
  cout << "today is the best"<<endl;
}
```



It is possible then, to craft a string to input into the **bad()** function that specifically overwrites the return address with another return address that points somewhere unintended.

If the program allows for user input into **bad()** then the user could craft a malicious string that encodes assembly language instructions. Then the user could overwrite the area of memory storing the return address with the memory location of the string they just type....

therefore, executing their input string as valid assembly language.

## Overwriting the return address

`bad("aaaa")` this does not cause a problem, the string "aaaa" gets copied into the buffer where it fits nicely.

`bad("aaaab")` this does not cause a big problem, the string "aaaab" gets copied into the buffer where it overwrites the null-terminator of the string with 'b'

`bad("aaaabcc")` causes a problem. the value of EBP on the stack is partially overridden by two "c". 

`bad("aaaabcccc")` causes a problem. the value of EBP on the stack is completely overridden and has value 43434343 in hex. "c" is represented by 43 in hex.

`bad("aaaabccccdddd")` causes a huge problem. the value of the return address is overwritten. that means when bad() finishes executing it will try to execute the code at memory location 44444444. 44 is how you represent 'd' in hex.

## Customizing the return address

Now knowing we can overwrite the return address how do we get it to overwrite the return address with a custom memory location of our choosing.

If we want to execute the instruction at memory location 41345678 then we need to overwrite the return address with 78 56 34 41 in memory (remember little endian format).

Then I look up in an ASCII chart the letters that go with the target bytes.

| Hex  | ASCII |
| ---- | ----- |
| 78   | 'x'   |
| 56   | 'V'   |
| 34   | '4'   |
| 41   | 'a'   |



Now I can overwrite the return address to go to execute the code at memory location 41345678 with a simple call to `bad("aaaabccccxV4a")`

**<u>WHAT IF THERE WAS VIRUS CODE AT MEMORY LOCATION 41345678??</u>**

If there was, it would now be executed and your machine would be annihilated.



## Inserting Virus Code



If you open you program in a debugger (OllyDbg), you can find the memory location where the `small` array begins in function `bad()`. You can customize the return address to execute code beginning at that memory location utilizing the trick above.

Then, instead of inserting "aaaabcccc" you can insert the bytes that represent machine code instructions (encoded as a string).



# To Be Continued

### Example Simple Virus Code / Vulnerable Program

### JMP ESP Trick

### Finding Virus Code

### Creating Virus Code





