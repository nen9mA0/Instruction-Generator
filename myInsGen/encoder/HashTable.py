from global_init import *

def HTMSave(f, obj):
    pickle.dump(obj.nt_names, f)
    pickle.dump(obj.repeat_nts, f)
    pickle.dump(obj.repeat_ntlufs, f)

def HTMLoad(f, obj):
    obj.nt_names = pickle.load(f)
    obj.repeat_nts = pickle.load(f)
    obj.repeat_ntlufs = pickle.load(f)


hash_num = 10000

class HashTableItem(object):            # this class is a wrapper of structure ({},{}), and just because dictionary is unhashable
    def __init__(self, context_tuple):
        self.context = context_tuple
        global hash_num
        self.id = hash_num
        self.condition_num = 0          # number of key in cond_context
        self.num = 0                    # number of conditions currently satisfied
        hash_num -= 1

    # def __hash__(self):                 # hash is address of HashTableItem
    #     return id(self)
    def __hash__(self):
        return self.id

    def __eq__(self, rhs):
        return self.id == rhs.id

    def __getitem__(self, index):       # self.context is a tuple
        return self.context[index]

    def __next__(self):
       item = next(self.iter)
       return item

    def __str__(self):
        mystr = "("
        for context in self.context:
            mystr += "{"
            for key in context:
                if not key == "emit":
                    mystr += "%s:%s " %(key, context[key])
                else:
                    mystr += "["
                    for emit_name, action in context["emit"]:
                        mystr += "(%s,%s) " %(emit_name, str(action))
                    mystr += "]"
            mystr += "} "
        return mystr

    def __repr__(self):
        return str(self.context)



class HashTable(object):
    def __init__(self, name):
        self.name = name
        self.keyname = {}
        self.neqkey = {}
        self.all_context = None
        self.value_context = []       # context without otherwise
        self.otherwise = None

    # def GetContextHash(self, context):
    #     tmp = []
    #     for key in context:
    #         tmp.append("%s: %s" %(key, context[key]))
    #     tmp.sort()
    #     return " ".join(tmp)

    def LoadContext(self, all_context):             # bug fixed 20210407: previous implement only assume that every context in one NT has the same condition key
                                                    # **see note**
        self.all_context = all_context
        for context in all_context:                 # first create all key
            for key in context[0]:
                if not key in self.keyname:
                    self.keyname[key] = {' ':[]}

        for context in all_context:
            if len(context[0]):
                self.value_context.append(context)
                for key in self.keyname:
                    if key in context[0]:
                        context.condition_num += 1
                        value = context[0][key]
                        if not value[0] == "!":
                            if not value in self.keyname[key]:
                                self.keyname[key][value] = [context]
                            else:
                                self.keyname[key][value].append(context)
                        else:                       # for neq
                            if not key in self.neqkey:
                                self.neqkey[key] = {}
                            raw_value = value[1:]
                            if not raw_value in self.neqkey[key]:
                                self.neqkey[key][raw_value] = [context]
                            else:
                                self.neqkey[key][raw_value].append(context)
                    else:
                        self.keyname[key][' '].append(context)      # if there is no such condition in context, just add it into key ' '
            else:
                if not self.otherwise:
                    self.otherwise = [context]
                    context.condition_num = 1
                else:
                    raise ValueError("Multi otherwise in NT %s: %s" %(self.name, context))
        return self.keyname

    def GetActContext(self, context, otherwise_first=True):
        ret = None
        sat_lst = []
        flag = False                     # optimization
        for key in self.keyname:
            if key in context:
                flag = True
                context_lst = []
                value = context[key]
                if not value[0] == "!":
                    if value in self.keyname[key]:
                        context_lst.extend(self.keyname[key][value])
                    if  "*" in self.keyname[key]:
                        context_lst.extend(self.keyname[key]["*"])
                    if key in self.neqkey:
                        for neq_value in self.neqkey[key]:
                            if value != neq_value:
                                context_lst.extend(self.neqkey[key][neq_value])
                else:                           # when condition is not equal
                    neq_value = value[1:]
                    for key_value in self.keyname[key]:
                        if key_value != neq_value and key_value != "*":
                            context_lst.extend(self.keyname[key][key_value])
                    if key in self.neqkey:
                        if neq_value in self.neqkey[key]:
                            context_lst.extend(self.neqkey[key][neq_value])
                for sat_context in context_lst:     # until now, all the context in context_lst match the condition accuracy
                    sat_context.num += 1
                    # === check ===
                    if sat_context.num > sat_context.condition_num:
                        raise ValueError("Num bigger than Condition Num")
                    # === ===
                context_lst.extend(self.keyname[key][' '])      # no matter the condition is equal or not, keyname[key][' '] will always satisfy the condition
                                                                # because these context don't have the key
            else:                               # if key not in context, return all context
                # context_lst = self.value_context
                if not flag:
                    context_lst = self.value_context
                    flag = True
                else:
                    context_lst = None

            if context_lst:
                if ret:
                    ret = ret & set(context_lst)
                else:
                    ret = set(context_lst)

        # check if there is any context that satisfied the condition accuracy, if not, otherwise should be added into ret_lst
        # see note
        flag = True            # mark if otherwise should be added
        if ret:
            for tmp in ret:
                if tmp.num == tmp.condition_num:    # if there is one context that satisfied the condition accuracy, otherwise can't be added
                    flag = False
                    break
        otherwise_in_retlst = False                 # if otherwise is in retlst
        if self.otherwise and flag:
            if not ret:
                ret = set(self.otherwise)           # in this case, otherwise is the only context in ret, so we don't need to set otherwise_in_retlst
                                                    # because we don't need to reorder the otherwise
            else:
                ret = ret | set(self.otherwise)
                otherwise_in_retlst = True

        # handle otherwise_first
        if otherwise_in_retlst:
            if otherwise_first:                     # otherwise.condition_num = 1, so we do the operation below for sorting
                self.otherwise[0].num = 2           # this guarantee otherwise will be biggest element after sorting
            else:
                self.otherwise[0].num = 0           # guarantee otherwise will be smallest

        # sort return list
        ret_lst = list(ret)
        ret_lst.sort(reverse=True, key=lambda obj: (obj.num / obj.condition_num) * 100000 + obj.id)        # by default(all NTNode's otherwise_first field are True), the id of otherwise will always smaller than others

        # reset all num
        for tmp in self.value_context:
            tmp.num = 0
        return ret_lst

    def RefreshContext(self, context, act_context):
        has_outreg = False
        outreg = None
        for key in act_context:
            if key == "emit":
                context[key].extend(act_context[key])
            elif key == "OUTREG":
                has_outreg = True
                outreg = act_context[key]
                # seems like we don't have to care about whether the OUTREG is rewrited
                # if key in context:
                #     raise ValueError("NT %s: Rewrite OUTREG\ncontext: %s\nact_context: %s" %(self.name, context, act_context))
                context[key] = outreg
            elif act_context[key] == "*":
                pass
            else:
                context[key] = act_context[key]
        return has_outreg, outreg


class HashTableManager(object):
    def __init__(self):
        self.nt_names = {}
        self.repeat_nts = {}
        self.repeat_ntlufs = {}
        self.seq_names = {}
        self.done = False

    def AddHashTable(self, hashtable):
        name = hashtable.name
        if name in self.nt_names:
            raise ValueError("One NT has multi hashtable(repeat NT must been handled by repeat_nts)")
        self.nt_names[name] = hashtable

    def AddSeqHashTable(self, hashtable):
        name = hashtable.name
        if name in self.seq_names:
            raise ValueError("One NT has multi hashtable(repeat NT must been handled by repeat_nts)")
        self.seq_names[name] = hashtable

    def __getitem__(self, name):
        return self.nt_names[name]

    def __setitem__(self, name, value):
        self.nt_names[name] = value

    def __contains__(self, item):
        return item in self.nt_names

    def __iter__(self):
        self.iter = iter(self.nt_names)
        return self

    def __next__(self):
        item = next(self.iter)
        return item


if __name__ == "__main__":
    all_context = [({'EASZ': '1', 'MODE': '0'}, {'emit': [], 'EASZ': '1', 'MODE': '0', 'ASZ': '0'}), ({'EASZ': '2', 'MODE': '0'}, {'emit': [], 'EASZ': '2', 'MODE': '0', 'ASZ': '1'}), ({'EASZ': '2', 'MODE': '1'}, {'emit': [], 'EASZ': '2', 'MODE': '1', 'ASZ': '0'}), ({'EASZ': '1', 'MODE': '1'}, {'emit': [], 'EASZ': '1', 'MODE': '1', 'ASZ': '1'}), ({'EASZ': '3', 'MODE': '2'}, {'emit': [], 'EASZ': '3', 'MODE': '2', 'ASZ': '0'}), ({'EASZ': '2', 'MODE': '2'}, {'emit': [], 'EASZ': '2', 'MODE': '2', 'ASZ': '1'}), ({'MODE': '0', 'EASZ': '0'}, {'emit': [], 'MODE': '0', 'EASZ': '1', 'ASZ': '0'}), ({'EASZ': '2', 'MODE': '1'}, {'emit': [], 'MODE': '1', 'EASZ': '2', 'ASZ': '0'}), ({'EASZ': '1', 'MODE': '2'}, {'emit': [], 'MODE': '2', 'EASZ': '3', 'ASZ': '0'}), ({'EASZ': '2', 'MODE': '0', 'EOSZ': '0'}, {'emit': [], 'MODE': '0', 'EOSZ': '1', 'EASZ': '1', 'ASZ': '0'}), ({'EASZ': '2', 'MODE': '0'}, {'emit': [], 'MODE': '0', 'EOSZ': '1', 'EASZ': '2', 'ASZ': '1'}), ({'EASZ': '2', 'MODE': '1'}, {'emit': [], 'MODE': '0', 'EOSZ': '1', 'EASZ': '1', 'ASZ': '0'}), ({'EASZ': '2', 'MODE': '1', 'EOSZ': '0'}, {'emit': [], 'MODE': '1', 'EOSZ': '2', 'EASZ': '2', 'ASZ': '0'}), ({'EASZ': '1', 'MODE': '1'}, {'emit': [], 'MODE': '1', 'EOSZ': '2', 'EASZ': '1', 'ASZ': '1'}), ({'EASZ': '3', 'MODE': '2'}, {'emit': [], 'MODE': '1', 'EOSZ': '2', 'EASZ': '2', 'ASZ': '0'}), ({'EASZ': '1', 'MODE': '2', 'EOSZ': '0'}, {'emit': [], 'MODE': '2', 'EOSZ': '2', 'EASZ': '3', 'ASZ': '0'}), ({'EASZ': '2', 'MODE': '2'}, {'emit': [], 'MODE': '2', 'EOSZ': '2', 'EASZ': '2', 'ASZ': '1'}), ({'MODE': '0', 'EASZ': '0'}, {'emit': [], 'MODE': '2', 'EOSZ': '2', 'EASZ': '3', 'ASZ': '0'})]
    h = HashTable("")
    h.LoadContext(all_context)
    h.ReHash(all_context)

    context = {'EASZ': '1', 'MODE': '2', 'EOSZ': '0'}

    context = h.FreshContext(context)

    print(context)