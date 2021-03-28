from global_init import *

# Duplicated: I think I find a better way to do these things, which implemented in HashTable.py

# Used to accelerate context lookup
# Because we have created a list which contains several tuples of conditions and its corresponding context after one nonterminal executed
# So now when we execute a nonterminal, we should build a method to quickly search the conditions that current context matched. Then we can easily change context to the corresponding context which we have saved before.

# My method is to build a lookup tree
# Assume that there is a condition like this:
# MODE=0 EOSZ=0 EASZ=0
# At first we has only one root_node
#  -----------
# | root_node |
#  -----------

# 1. We add the first condition into root_node
#  -----------
# | root_node |  name=["MODE"]
#  -----------
#      |
#  ----------
# | MODE=[0] |
#  ----------

# 2. Then we add other nodes
#  -----------
# | root_node |  name=["MODE"]
#  -----------
#      |
#  ----------
# | MODE=[0] |
#  ----------
#      |
#  ----------
# | EOSZ=[0] |
#  ----------
#      |
#  ----------
# | EASZ=[0] |
#  ----------

# Now the second condition add, assume it like this:
# MODE=0 EOSZ=1 EASZ=0  # It's just an example, and seems never appears in XED's rules
# We build tree like this
#  -----------
# | root_node |  name=["MODE"]
#  -----------
#      |
#  ----------
# | MODE=[0] |
#  ----------
#      |
#  ------------
# | EOSZ=[0,1] |
#  ------------
#      |       \
#  ----------   ----------
# | EASZ=[0] | | EASZ=[0] |
#  ----------   ----------

# Note that, if one condition doesn't has any key matches the children of root_node, it will be treated as a new subtree
# For example, if condition is EOSZ=1 EASZ=0
#  -----------
# | root_node |  name=["MODE","EOSZ"]
#  ----------- 
#      |        \
#  ----------     ----------
# | MODE=[0] |   | EOSZ=[1] |
#  ----------     ----------
#      |              |
#  ------------   ----------
# | EOSZ=[0,1] | | EASZ=[0] |
#  ------------   ----------
#      |       \
#  ----------   ----------
# | EASZ=[0] | | EASZ=[0] |
#  ----------   ----------


def GetIndex(cond):
    mystr = ""
    for key in cond:
        if key == "neq":
            for neq_key in cond["neq"]:
                mystr += "%s!=%s " %(neq_key, cond["neq"][neq_key])
        else:
            mystr += "%s=%s " %(key, cond[key])
    return mystr

def GetFindPattern(context):
    pass


class LookUpNode(object):
    def __init__(self, name, neq=False):            # neq will be true only when the expersion is not equal 
        self.name = name
        self.neq = neq
        self.value = []
        self.child = []

    def AddChild(self, node):
        self.child.append(node)

    def __iter__(self):
        self.iter = iter(self.child)
        return self

    def __next__(self):
        return next(self.iter)


class NTLookUpTree(object):
    def __init__(self, nt_name, all_context):       # all_context is a list which is a tuple of (condtions context, final context)
        self.nt_name = nt_name
        self.cond_var = []
        self.root_node = LookUpNode("root_node")

        for tmp in all_context:
            cond = tmp[0]
            cond_iter = iter(cond)
            current_node = self.root_node
            node_exist = []
            name = ""
            while True:
                flag = False
                for node in current_node:
                    name = node.name
                    if name in cond:
                        if cond[name] in node.value:
                            flag = True         # find a match condition
                            current_node = node
                            break
                        else:
                            flag = True
                            node.value.append(cond[name])
                            node.child.append(None)     # TODO: add a new value
                            current_node = node
                            break
                if flag:
                    node_exist.append(name)
                else:
                    for name in cond:
                        if not name in node_exist:
                            tmp = LookUpNode(name)
                            current_node.AddChild(tmp)


    def GetPos(self, key, value):
        node = self.root_node
        if key in node.child:
            pass




class LookUpTableItem(object):
    def __init__(self, context_item):   # one tuple from all_context
        self.cond = context_item[0]
        self.out = context_item[1]
        self.index = GetIndex(self.cond)

    def __eq__(self, rhs):
        if isinstance(rhs, LookUpTableItem):
            return self.index == rhs.index
        elif isinstance(rhs, dict):
            return self.index == self.GetIndex(rhs)
        else:
            return TypeError("LookUpTableItem __eq__ doesn't support %s" %type(rhs))


class LookUpTable(object):
    def __init__(self, nt_name, all_context):
        self.nt_name = nt_name
        self.lut = {}
        for context in all_context:
            tmp = LookUpTableItem(context)
            self.lut[tmp.index] = tmp

    def LookUp(self, context):
        pass

if __name__ == "__main__":
    a = LookUpNode("test")
    a.child = [1,2,3]
    for i in a:
        print(i)