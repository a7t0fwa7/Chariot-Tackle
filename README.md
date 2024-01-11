# Chariot-Tackle
### A small API for C++ that makes local indirect syscalls easy.

![urien-chariot-rush](https://github.com/Uri3n/Chariot-Tackle/assets/153572153/2e0f3083-8c71-417e-90b1-42fe415c0b16)

Note: this was intended to be used with Visual Studio. Using it with 
other IDEs is probably possible, but I can't be bothered to test that.
Also, this API is CRT library independent, and does not require it to be loaded (NTDLL is required though).


## How To Set Up:
Create a Visual Studio C++ empty project, right-click on the project in the solution viewer, click "build dependencies", and add **"masm, (targets, .props)"**

![ctExample2](https://github.com/Uri3n/Chariot-Tackle/assets/153572153/2ab6e0f4-997a-4069-8731-8dc0e8e72db5)

Next, go to the solution viewer and right-click on "Header Files". Select "Add", followed by "Existing Item".
Select the **ChariotTackle.h header** file from this repository to add it to your project.

![ctExample3](https://github.com/Uri3n/Chariot-Tackle/assets/153572153/9948a7eb-1352-4236-be46-c7fa9816b085)

Finally, do the same for **"ChariotTackleAsm.asm"** as well, by adding an existing item to the "Source Files" folder, 
and selecting ChariotTackleAsm.asm. This file is necessary to perform the technique.

After this is done, your solution viewer should look something like this:

![ctExample7](https://github.com/Uri3n/Chariot-Tackle/assets/153572153/f2de1013-6169-4610-a008-ac581b3b42e3)


## Using Chariot Tackle:
After completing the above steps, the API is now ready for use.
You can use Chariot Tackle by first calling the **CT_DECLARESYSCALL** macro on every syscall you'd like to perform, like so:

![ctExample4](https://github.com/Uri3n/Chariot-Tackle/assets/153572153/bf14de02-64fe-44b0-9f80-e36596571b92)

Using this macro will generate a unique compile-time hash associated with the syscall, ensuring that strings for these syscalls
stay out of the binary.

Next, call the **CT_INIT** macro, and pass in all of the syscalls that you declared in the previous step.

![ctExample5](https://github.com/Uri3n/Chariot-Tackle/assets/153572153/e6e91d45-ff54-4d86-af02-9d03d59110b6)

You are now ready to call the syscalls you want.
You can do this by calling the **ctCall** function, passing in the name of one of the syscalls initialized previously,
along with all of your other arguments for the syscall. The syscall arguments are passed as a variadic argument list, so you may pass
as many as you like.

Please note that Chariot Tackle does not provide the required arguments for the syscalls to be used, and you'll need to find that yourself.
I'd recommend you check out NtDoc at https://ntdoc.m417z.com/ for full documentation on all syscalls in Windows.

Here's an example of me allocating some virtual memory with **NtAllocateVirtualMemory**, and then changing it's memory permissions using **NtProtectVirtualMemory**:

![ctExample1](https://github.com/Uri3n/Chariot-Tackle/assets/153572153/0f9ff626-8c12-4d2a-ba98-a8a9c7e1e0ba)


Once you're done using Chariot Tackle, make sure you call the **ctCleanup** function. This will free
any memory that Chariot Tackle was using. The reason for this kind of implementation is that
C++ deconstructors utilize parts of the CRT library.

![ctExample8](https://github.com/Uri3n/Chariot-Tackle/assets/153572153/8940fe58-b938-4307-bcf6-e2c910c39518)


## IMPORTANT STUFF!!
1. I wrote this shit in like, a day. It does not handle undefined or unexpected behavior, and can be dangerous to use.
2. Your program WILL crash if NTDLL is not loaded into the process' address space at the time that **CT_INIT** is called.
   Please ensure NTDLL is loaded first by calling LoadLibraryA/W.
   ![ctExample6](https://github.com/Uri3n/Chariot-Tackle/assets/153572153/0e257cf0-07a7-4337-9cde-0dcd0af4821b)
3. The source code is actual fucking spaghetti. I would not recommend you even attempt to read it.

