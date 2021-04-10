def CheckContextCondNum(context):
    cond_context = context[0]
    num = 0
    for key in cond_context:
        num += 1
    if num != context.condition_num and len(cond_context) != 0:
        raise ValueError("CheckContextCondNum")

def CheckHashTableManager(old_htm, new_htm):
    for nt_name in old_htm.nt_names:
        if not nt_name in new_htm.nt_names:
            print("nt_name %s in old but not in new" %nt_name)

    for nt_name in new_htm.nt_names:
        if not nt_name in old_htm.nt_names:
            print("nt_name %s in new but not in old" %nt_name)

    for nt_name in old_htm.nt_names:
        old_ht = old_htm.nt_names[nt_name]
        new_ht = new_htm.nt_names[nt_name]
        old_all_context = old_ht.all_context
        new_all_context = new_ht.all_context
        if len(old_all_context) != len(new_all_context):
            raise ValueError("old length is different from new length")
        for i in range(len(old_all_context)):
            if not str(old_all_context[i]) == str(new_all_context[i]):
                raise ValueError("old context is different from new context")