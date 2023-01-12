### 目前的hash格式

主要使用的字段：

* prefix

* opcode

* mnemonic

* 操作数类型

具体格式

```
    #  ---------------- 1 Byte ---------------------- ------------- 1 Byte -------------- ----- n Byte ------ -------------------- 1 Byte ------------------- -- [optional] n Byte --
    # |        5bit        |         3bit            |     4bit     |        4bit        |        nbit       | 2bit      | 2bit      | 2bit      | 2bit      |         n bit         |
    # | length of mnemonic | length of prefix+opcode | prefix group |     0(preserved)   |   prefix + opcode | op1 type  | op2 type  | op3 type  | op4 type  |        mnemonic       |
```

* 5bit  助记符长度

* 3bit  prefix+opcode的长度

* 4bit  使用到的prefix group（prefix分为4类）

* 4bit  保留

* n bytes  **prefix和opcode的具体bytes**

* 1 byte  **操作数类型**，这里预留了4组操作数，实际上目前看到一条指令最多有3个操作数
  
  * 01  寄存器类型
  
  * 02  内存类型
  
  * 03  立即数类型

* n bytes  **助记符**

### 几个问题

#### 为什么不用modrm

直接使用modrm字段目前发现非常多问题

```
modrm
2bit  3bit  3bit
mod   reg    rm
```

* modrm本身大多数情况下用于操作数编码，如果直接使用会导致很多误判，如
  
  ```
  89 c0                   mov    eax,eax
  89 c3                   mov    ebx,eax
  ```
  
  modrm分别为C0和C3，会直接断定为两条指令

* 按资料中所说，modrm只有reg这3位可能作为opcode使用，但实际上情况复杂很多，如vmx指令
  
  ```
  0f 01 c4                vmxoff
  0f 01 c3                vmresume
  0f 01 c2                vmlaunch
  ```
  
  这里仅有rm这3位有区别

* 从目前的结果来看使用opcode与mnemonic，加上操作数类型可以正确区分所有指令
  
  仅使用opcode的方案可能存在的问题是漏掉一些使用了modrm字段作为opcode的指令，因此可能将这两条指令误识别为一类，如
  
  ```
  83 c0 0a                add    eax,0xa
  83 c8 0a                or     eax,0xa
  ```
  
  而仅使用mnemonic的方案则粒度较粗，仅保留了语义信息而丢失了opcode信息，这里不举例了

原来考虑使用xed解析的信息去选择性地将modrm字段纳入哈希解决上面这个问题，但该方案会在建表时造成很大的额外开销，实现难度也较大，所以改用上述的方案

#### 为什么不考虑SIB

SIB字段是编码内存操作数时使用的，主要用于指定基址变址寻址的寄存器，若将SIB纳入哈希中，则

```
8b 04 18                mov    eax,DWORD PTR [eax+ebx*1]
8b 04 08                mov    eax,DWORD PTR [eax+ecx*1]
8b 04 98                mov    eax,DWORD PTR [eax+ebx*4]
```

这几条指令的哈希结果都会不同

#### 该方案存在的问题

有部分单字节指令使用opcode中的几位作为操作数，如

```
50                      push   eax
53                      push   ebx
```

目前这个问题只在查表时加入特殊处理解决，没有从哈希方案本身解决
