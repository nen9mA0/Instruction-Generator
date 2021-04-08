from global_init import *

def HTMSave(f, obj):
    pickle.dump(obj.nt_names, f)
    pickle.dump(obj.repeat_nts, f)
    pickle.dump(obj.repeat_ntlufs, f)

def HTMLoad(f, obj):
    obj.nt_names = pickle.load(f)
    obj.repeat_nts = pickle.load(f)
    obj.repeat_ntlufs = pickle.load(f)


hash_num = 0

class HashTableItem(object):            # this class is a wrapper of structure ({},{}), and just because dictionary is unhashable
    def __init__(self, context_tuple):
        self.context = context_tuple
        global hash_num
        self.id = hash_num
        hash_num += 1

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
        return str(self.context)

    def __repr__(self):
        return str(self.context)



class HashTable(object):
    def __init__(self, name):
        self.name = name
        self.keyname = {}
        self.neqkey = {}
        self.all_context = None
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
                for key in self.keyname:
                    if key in context[0]:
                        value = context[0][key]
                        if not value[0] == "!":
                            if not key in self.keyname:
                                self.keyname[key] = {}
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
                else:
                    raise ValueError("Multi otherwise in NT %s: %s" %(self.name, context))
        return self.keyname

    def GetActContext(self, context, otherwise_first=True):
        ret = None
        for key in self.keyname:
            if key in context:
                context_lst = []
                context_lst.extend(self.keyname[key][' '])      # no matter the condition is equal or not, keyname[key][' '] will always satisfy the condition
                value = context[key]
                if not value[0] == "!":
                    if value in self.keyname[key]:
                        context_lst.extend(self.keyname[key][value])
                    elif  "*" in self.keyname[key]:
                        context_lst.extend(self.keyname[key]["*"])
                    if key in self.neqkey:
                        for neq_value in self.neqkey[key]:
                            if value != neq_value:
                                context_lst.extend(self.neqkey[key][neq_value])
                else:                           # when condition is not equal
                    neq_value = value[1:]
                    for key_value in self.keyname[key]:
                        if key_value != neq_value:
                            context_lst.extend(self.keyname[key][key_value])
                    if key in self.neqkey:
                        if neq_value in self.neqkey[key]:
                            context_lst.extend(self.neqkey[key][neq_value])
            else:                               # if key not in context, return all context
                context_lst = self.all_context

            if ret:
                ret = ret & set(context_lst)
            else:
                ret = set(context_lst)

        if self.otherwise:
            if ret:
                ret = ret | set(self.otherwise)
            else:
                ret = set(self.otherwise)
        ret_lst = list(ret)
        ret_lst.sort(key=lambda obj: obj.id)        # by default(all NTNode's otherwise_first field are True), the id of otherwise will always smaller than others
        if self.otherwise and not otherwise_first:  # if otherwise_first is False, we exchange otherwise(in ret_lst[0] if it has otherwise) with the last element
            tmp = ret_lst[0]
            ret_lst[0] = ret_lst[-1]
            ret_lst[-1] = tmp
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