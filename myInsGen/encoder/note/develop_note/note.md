### Time Line

#### 20201209

V1.0	最简单的版本，可以生成部分指令，但只添加了对NT的处理，没有处理sequence，因此只能处理最简单的寄存器为操作数的指令，对于MODRM等没法处理。
	这版本的context采用一个统一的类NTContext，这个类只在每个iform_t创建时被创建。每个nonterminal被执行时新的状态都保存在其中，因此contexts是个树状结构，所有执行NT后的context都存放在这棵树内。迭代器只迭代叶子节点，因此造成了很多空间浪费（除了叶子节点外的其他节点没什么用，因为已经执行过了）

##### TODO: 

在写处理sequence的代码时发现一个问题，就是最常用的sequence ISA_BINDING对于每个iform_t只有INSTRUCTION这一个NT不同，但按照目前方式所有iform_t传入时都需要把INSTRUCTION前的NT重新执行一遍，每个大概有100+个状态。完全是浪费

此外还有路径爆炸的问题。测试的一个两个8位寄存器操作数的iform_t context数目到了12000+个。考虑使用DFS解决

#### 20201211

BFS版本完成得差不多了，还有一些小细节（写在TODO

但运行发现路径爆炸问题很严重，新建DFS算法相关

将GeneratorStorage单独分出来，剩下的内容（NTContext ContextNode SeqContext Emulator和Generator类）按照同样接口重写，因为我发现解耦有点困难，不如重写清晰

#### 20210308

时隔三个月来看这代码好难受 （

DFS三个月前就能用了，现在试图加速运行速度

考虑将每个nonterminal做成查找表的形式，类似于FPGA的LUT

#### 20210407

一个bug：在LoadContext中，是使用遍历当前condition context的key的方法，举个例子如下：在SIB_REQUIRED_ENCODE中有下列条件

```
({'EASZ': '3', 'INDEX': 'XED_REG_R14'}, {'emit': [], 'EASZ': '3', 'INDEX': 'XED_REG_R14', 'SIB': '1'})
({'EASZ': '3', 'INDEX': 'XED_REG_R15'}, {'emit': [], 'EASZ': '3', 'INDEX': 'XED_REG_R15', 'SIB': '1'})
({'EASZ': '3', 'BASE0': '@', 'DISP_WIDTH': '32'}, {'emit': [], 'EASZ': '3', 'BASE0': '@', 'DISP_WIDTH': '32', 'SIB': '1'})
({'EASZ': '2', 'MODE': '2', 'BASE0': '@', 'DISP_WIDTH': '32'}, {'emit': [], 'EASZ': '2', 'MODE': '2', 'BASE0': '@', 'DISP_WIDTH': '32', 'SIB': '1'})
({'EASZ': '!1', 'BASE0': 'XED_REG_SP'}, {'emit': [], 'EASZ': '1', 'BASE0': 'XED_REG_SP', 'SIB': '1'})
```

假设其编号为0,1,2,3,4则使用LoadContext建表如下

```
keyname:
    EASZ:       '2':[3] '3':[0,1,2]
    INDEX:      'XED_REG_R14':[0] 'XED_REG_R15':[1]
    BASE0:      '@':[2,3] 'XED_REG_SP':[4]
    DISP_WIDTH: '32':[2,3]
neqkey:
    EASZ:       '1':[4]
```

这里存在问题，因为如2和3是不存在INDEX条件的（因为根本没有INDEX关键字），所以照理2和3也应满足条件，应该被加入INDEX列表，并且无论INDEX为'XED_REG_R14'还是'XED_REG_R15'，返回的context都应包含2和3，即

```
keyname:
    EASZ:       '2':[3] '3':[0,1,2] ' ':[]
    INDEX:      'XED_REG_R14':[0] 'XED_REG_R15':[1] ' ':[2,3,4]
    BASE0:      '@':[2,3] 'XED_REG_SP':[4] ' ':[0,1]
    DISP_WIDTH: '32':[2,3] ' ':[0,1,4]
neqkey:
    EASZ:       '1':[4]
```

其中无该条件的以空格为键，实际上存放的就是全集对其他键的集合的补集

#### 20210408

新bug：

* 首先现阶段对于otherwise处理是有问题的：otherwise只能在其他条件都不满足时才会执行，而现在即使满足其他条件也会执行。

  理论上otherwise应该仅在这两种情况下会执行

  * context中当前没有任何与正在执行的NT条件相关的内容，应遍历执行NT中的所有情况，包括otherwise
  * 当前context不满足所有的rule，则执行otherwise

* 还有就是检查的时候发现一种emit方式，见REX_PREFIX_ENC，具体为：

  emit类型为letter，value为wrxb，其中wrxb分别context中的REXW REXR REXX和REXB



### 一些设计

#### NTIterNum

`relative: Emulator.nt_iternum Generator.SetNTIterNum `

用于设置一个NT的最大循环次数，即当一个NT迭代了`nt_iternum[nt_name]`次时就不会继续迭代下去

注意这里只关注迭代次数，不管当前的条件有没有最终产生输出，只要迭代次数到了就不会继续迭代下去（跟NTEmitNum区别）

此外，当一个NTNode/NTHashNode销毁时会重置次数。下面以一个例子说明该机制

```
self.route:
==head==
FIXUP_EOSZ_ENC
FIXUP_EASZ_ENC
ASZ_NONTERM
==head==    emit code
```

假设上述是当前执行的路径，此时设置

```
nt_iternum["FIXUP_EOSZ_ENC"] = 2
nt_iternum["FIXUP_EASZ_ENC"] = 2
nt_iternum["ASZ_NONTERM"] = 3
```

那么运行的顺序应该如下（下划线后代表当前是NT的第几次迭代）

```
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_1 ASZ_NONTERM_1
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_1 ASZ_NONTERM_2
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_1 ASZ_NONTERM_3
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_2 ASZ_NONTERM_1
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_2 ASZ_NONTERM_2
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_2 ASZ_NONTERM_3
FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_1 ASZ_NONTERM_1
FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_1 ASZ_NONTERM_2
FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_1 ASZ_NONTERM_3
FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_2 ASZ_NONTERM_1
FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_2 ASZ_NONTERM_2
FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_2 ASZ_NONTERM_3
```

即一共会迭代`2*2*3=12`次

此外，如前所述，该参数不管最终输出了几次，因此上述过程即使12次迭代最后全部因无法满足条件而没有任何输出，也不会有额外的迭代

#### NTEmitNum

##### 基础功能

`relative: Emulator.nt_emitnum Emulator.nt_emitnum_limit NTNode/NTHashNode.last_emit_num`

用于设置每个NT的最大执行次数，注意，该参数就是为了解决NTIterNum的不足之处，用于限制每个NT的输出次数

一样采用下述例子

```
self.route:
==head==
FIXUP_EOSZ_ENC
FIXUP_EASZ_ENC
ASZ_NONTERM
==head==    emit code
```

```
nt_limit_emitnum["FIXUP_EOSZ_ENC"] = 2
nt_limit_emitnum["FIXUP_EASZ_ENC"] = 3
nt_limit_emitnum["ASZ_NONTERM"] = 2
```

此处为了说明问题，假设ASZ_NONTERM_2和FIXUP_EASZ_ENC_1不满足条件，迭代运行次序如下

```
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_1 不满足
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_2 ASZ_NONTERM_1 不满足
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_2 ASZ_NONTERM_2 输出
    nt_emitnum状态: "FIXUP_EOSZ_ENC":1  "FIXUP_EASZ_ENC":1 "ASZ_NONTERM":1
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_2 ASZ_NONTERM_3 输出
    nt_emitnum状态: "FIXUP_EOSZ_ENC":1  "FIXUP_EASZ_ENC":1 "ASZ_NONTERM":2
    因为FIXUP_EOSZ_ENC和FIXUP_EASZ_ENC使用了和上次一样的context，所以不变
    此时ASZ_NONTERM到达限制，回退

FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_3 ASZ_NONTERM_1 不满足
    nt_emitnum状态: "FIXUP_EOSZ_ENC":1  "FIXUP_EASZ_ENC":1 "ASZ_NONTERM":0
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_3 ASZ_NONTERM_2 输出
    nt_emitnum状态: "FIXUP_EOSZ_ENC":1  "FIXUP_EASZ_ENC":2 "ASZ_NONTERM":1
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_3 ASZ_NONTERM_3 输出
    nt_emitnum状态: "FIXUP_EOSZ_ENC":1  "FIXUP_EASZ_ENC":2 "ASZ_NONTERM":2

FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_4 ASZ_NONTERM_1 不满足
    nt_emitnum状态: "FIXUP_EOSZ_ENC":1  "FIXUP_EASZ_ENC":3 "ASZ_NONTERM":0
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_4 ASZ_NONTERM_2 输出
    nt_emitnum状态: "FIXUP_EOSZ_ENC":1  "FIXUP_EASZ_ENC":3 "ASZ_NONTERM":1
FIXUP_EOSZ_ENC_1 FIXUP_EASZ_ENC_4 ASZ_NONTERM_3 输出
    nt_emitnum状态: "FIXUP_EOSZ_ENC":1  "FIXUP_EASZ_ENC":3 "ASZ_NONTERM":2
    此时回退两次


FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_1 不满足
FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_2 ASZ_NONTERM_1 不满足
FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_2 ASZ_NONTERM_2 输出
    nt_emitnum状态: "FIXUP_EOSZ_ENC":2  "FIXUP_EASZ_ENC":1 "ASZ_NONTERM":1
FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_2 ASZ_NONTERM_3 输出
    nt_emitnum状态: "FIXUP_EOSZ_ENC":2  "FIXUP_EASZ_ENC":1 "ASZ_NONTERM":2

FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_3 ASZ_NONTERM_1 不满足
    nt_emitnum状态: "FIXUP_EOSZ_ENC":2  "FIXUP_EASZ_ENC":1 "ASZ_NONTERM":0
FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_3 ASZ_NONTERM_2 输出
    nt_emitnum状态: "FIXUP_EOSZ_ENC":2  "FIXUP_EASZ_ENC":2 "ASZ_NONTERM":1
FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_3 ASZ_NONTERM_3 输出
    nt_emitnum状态: "FIXUP_EOSZ_ENC":2  "FIXUP_EASZ_ENC":2 "ASZ_NONTERM":2

FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_4 ASZ_NONTERM_1 不满足
    nt_emitnum状态: "FIXUP_EOSZ_ENC":2  "FIXUP_EASZ_ENC":2 "ASZ_NONTERM":0
FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_4 ASZ_NONTERM_2 输出
    nt_emitnum状态: "FIXUP_EOSZ_ENC":2  "FIXUP_EASZ_ENC":3 "ASZ_NONTERM":1
FIXUP_EOSZ_ENC_2 FIXUP_EASZ_ENC_4 ASZ_NONTERM_3 输出
    nt_emitnum状态: "FIXUP_EOSZ_ENC":2  "FIXUP_EASZ_ENC":3 "ASZ_NONTERM":2
```

##### 扩展功能

`relative: Emulator.iform_emit_limit Emulator.iform_emit_limit_clean`

若在赋值`nt_emitnum_limit`时其中含有iform这个键，那么默认iform产生的每个NT都会被自动赋值

`nt_emitnum_limit[nt_name] = nt_emitnum_limit["iform"]`

但如果原先已有设置，则不会覆盖

`iform_emit_limit_clean`用于在iform的node释放时清理上述临时生成的约束

#### otherwise_first

otherwise机制改动见下面

`relative: Generator.SetOtherwiseFirst  Emulator.otherwise_first_dict  NTNode.otherwise_first_dict  CreateNTNode`

这个机制是用于控制一些NT是否先执行otherwise的

很多时候我们应该先执行有条件约束的，而不是otherwise，因为otherwise总会生成拥有最少约束条件的指令，而通常我们不希望这样

但也有一些例外，比如对于PREFIX_ENC，我们倾向于先生成不带前缀的指令（因为对于一个没有前缀约束的指令也可以生成前缀）

因此对于**NTHashNode的默认otherwise_first是False**，当部分NT需要为True时，应该通过一个dict设置，并且使用

需要注意的是，这个设置只对NTHashNode有效。而对于**NTNode，首先它的otherwise_first默认为False**，这是因为NTNode在目前版本的代码中只在调用CreateNTHashTable时会用到，这个函数将一个NTNode的各种情况转换成一个查找表来代替原来NTNode的模拟执行过程，从而极大增加运行的效率。而在其建表的时候，会根据NTNode遍历情况的先后顺序分配一个唯一的id（`HashTableItem.id`），这个id是每新建一个HashTableItem就加一的，因此对于有otherwise的NTNode，其otherwise条件对应的HashTableItem就是id最小的那个，而在NTHashNode中依赖这个特性来处理otherwise_first标志（当然这里也可以设计成NTNode默认也为False，这样otherwise条件对应的就是id最大的那个，但是这里统一采取了上述设计）

PS：上述描述也表明最好不要对NTNode设置otherwise_first（除非知道自己在干嘛）。此外基于同样的考虑，专门用于生成HashTable的DFSNTContext函数在调用CreateNTNode时没有使用otherwise_first_dict参数

#### otherwise

在[20210408](#20210408)中提到了一个新bug，由于当前NTNode只用于创建hashtable，而hashtable的创建条件都符合bug描述中提到的执行otherwise的第一种情况，所以只要NTNode不直接用于代替HashNodeTable生成指令，则当前bug不会导致错误（当前的实现中，所有NT已经建表）。

而因为对这种情况修改NTNode的otherwise比较复杂一些

* NTNode的otherwise_first标志肯定不能用了，因为对于NTNode只有知道其他rules的运行情况才能获知当前条件下能不能执行otherwise
* 仅在下面两种情况下应执行otherwise
  * 所有的其他rules都能满足条件，即对应[20210408](#20210408)的第一种情况
  * 所有其他rules都不能满足条件，对应第二种情况

因为修改较为麻烦而且当前没必要（NTNode当前在生成指令过程中只用来处理iform，而iform没有otherwise）

所以**当前仅修改NTHashNode**，也就是说明在GenerateIform中，除了iform_t外，其他都不应使用NTNode（这个限制现在已经加入CreateNTNode，虽然感觉很不优雅）

##### TODO：修改NTNode思路

* dfs_generator有个全局变量prev_NT，此外Emulator类也有个prev_nt属性，这两者都记录了上一个NT
* NTNode有个成员nodelst，记录了self，和从自己派生的所有node
* 在执行中，若条件不符合，使用InvalidPath来将当前路径删除

因此思路如下：

* 首先otherwise肯定是要最后执行了
* 在NTNode中定义一个用于记录当前条件成功次数的变量a，该变量与两个地方有关联：
  * 刷新prev_NT时，这说明之前NT的条件已经满足，a+1
  * InvalidPath时，这说明之前NT的条件不满足（但这里其实不需要修改，因为计数不变）
* 若所有条件执行完，只剩otherwise，则先判断a
  * 若`a==rule_len`，说明所有rule都被执行过，也就对应上述第一种执行otherwise的情况
  * 若`a==0`，说明所有rule都不满足，对应第二种情况

#### default_emit_num

`relative: Emulator.default_valid_emit_num Emulator.default_novalue_emit_num`

`Generator.SetDefaultValidEmitNum Generator.SetNovalueValidEmitNum`

一般在两种情况下，EmitCode中没有指定需要输出的值

* 发射类型为letter，context中含有要发射的字段对应的属性值，但属性值为`*`，这说明这个值可以是符合位数的任意数字，默认的发射数字可以在default_valid_emit_num中指定。默认为0
* 发射类型为letter，context中不含有对应的属性值，则使用default_novalue_emit_num指定发射的值，默认为0

### xed datafile

#### enc-pattern

编码用的pattern，当前代码大多数的nt，全部seq都在这个文件中

##### ISA_BINDINGS/ISA_EMIT

总的编码过程，一共有三个版本，一个是编码大多数指令的，另外两个分别对应AVX512VEX个AVX512EVEX

###### FIXUP_EOSZ_ENC

指定EOSZ，即operand size

###### FIXUP_EASZ_ENC

指定EASZ，即address size

###### ASZ_NONTERM

指定ASZ，实际上就是根据67 prefix（Address-size override prefix）来确定地址操作数的长度

###### OSZ_NONTERM_ENC

指定OSZ/REXW，实际上是根据各种条件来确定是否使用66 prefix（Operand-size override prefix）

###### PREFIX_ENC

根据前面指定的prefix类型，发射对应的prefix

###### REX_PREFIX_ENC

根据前面指定的REX类型，发射对应的prefix

##### MODRM

###### SIB_REQUIRED_ENCODE

用于编码SIB，即是否需要SIB字段（若需要，SIB=1）。

注意eamode16（EASZ=1）的时候SIB始终为0

###### SIBSCALE_ENCODE

编码SIB.SIBSCALE（主要是SCALE长度），若SIB=0则直接跳过

###### SIBINDEX_ENCODE

根据SIB.INDEX使用的寄存器（变址寄存器）确定对应发射的位

###### SIBBASE_ENCODE

根据BASE0使用的寄存器（基址寄存器）确定对应发射的位

###### MODRM_RM_ENCODE

当SIB没有完全编码时，还有对SIB编码中涉及到MODRM.RM位的修正

###### MODRM_MOD_ENCODE

根据address size和displacement的长度对MODRM.MOD进行修正

###### SEGMENT_DEFAULT_ENCODE

根据使用的BASE0寄存器确定默认的段寄存器

###### SEGMENT_ENCODE

根据SEG0和默认段寄存器确定段寄存器前缀类型

###### SIB_NT

输出SIB字段编码

###### DISP_NT

输出displacement编码

#### enc-dec-pattern

编解码都需要用的pattern，当前代码所有ntluf，部分nt都在这个文件中

