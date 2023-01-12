#### opcode编码规则

* 单字节： xx

* 双字节： 0F xx

* 三字节：
  
  * 0F 38 xx
  
  * 0F 3A xx

#### prefix

##### group 1

- lock repeat
  
  - LOCK F0H 指定原子指令，只有下列命令可以使用
    
    ```
    ADC, ADD, AND, BTC, BTR, BTS, CMPXCHG, CMPXCHG8B, CMPXCHG16B, DEC, INC, NEG, NOT, OR, SBB, SUB, XADD, XCHG and XOR
    ```
  
  - REP F3H
    
    ```
    INS, LODS, MOVS, OUTS and STOS
    ```
  
  - REPNZ F2H
    
    ```
    CMPS, CMPSB, CMPSD, CMPSW, SCAS, SCASB, SCASD and SCASW
    ```
  
  - REPZ F3H 两个REP前缀F2 F3可能在不能使用REP前缀的指令中表示其他意思
    
    ```
    CMPS, CMPSB, CMPSD, CMPSW, SCAS, SCASB, SCASD and SCASW
    ```

- BND intel memory protection extensions扩展前缀

##### group 2

- 段寄存器前缀，指定该条指令使用的段寄存器。64位模式下只有FS和GS有效
  - CS 2EH
  - SS 36H
  - DS 3EH
  - ES 26H
  - FS 64H
  - GS 65H
- branch hints 用于告诉处理器某个跳转是否倾向于执行，只有奔腾4以后的支持，AMD似乎不支持
  - 2EH 跳转未执行
  - 3EH 跳转执行

##### group 3

- Operand-size override prefix 66H 选择某个操作数应该为16b或32b

##### group 4

- Address-size override prefix 67H 选择寻址为16b或32b模式

#### 讨论

##### prefix

首先prefix虽然最多可以叠加4字节，但其所有在prefix中出现的字节本身不可能是某条指令的第一个字节（实际也验证了）

因此在考虑opcode full mismatch的时候实际上是可以直接忽略prefix的，这边直接假设要对一条指令计算opcode full mismatch

```
f0 3e 66 67 0f 38 33    lock pmovzxwd xmm1,QWORD PTR ds:[bx]
```

*其中f0为lock prefix，3e为ds段寄存器的prefix，66 67为切换操作数长度和寻址模式的prefix，分别对应4个group*

假设从任意一个prefix处开始计算mismatch，如

```
66 67 0f 38 33
```

这里的66和67依然会被当做某条指令的前缀进行解析，而第一条实际的指令opcode还是从0f开始计算

**因此prefix理论上并不影响full mismatch的结果**

##### opcode

由上面的讨论可知，因为opcode的最大长度为3，所以只有小于等于3的HSR可能发生opcode full mismatch，而我们使用的HSR最短为2，所以只需要讨论长度为2的HSR

在这种情况下，唯一可能发生的mismatch是对于长度为3的opcode，HSR在后两字节发生mismatch。

由编码格式可知，HSR第一字节必为0x38或0x3A，而0x38和0x3A开头的指令仅有cmp，且不是单字节指令（目前的2字节HSR必是由一条单字节指令+一字节跳转的opcode构成）。

所以目前这种情况下不会发生opcode full mismatch
