import os
import re

xed_datafile_dir = "I:\\rtfsc\\intelxed\\xed\\datafiles"
cfg_needed = ["I:\\rtfsc\intelxed\\xed\datafiles\\files.cfg", ]
out_dir = "all-datafiles"
generate_file_prefix = "basic-test-"
subdir_name = "basic_test"

config_filename_pattern = re.compile(r"files.*.cfg$")
config_pattern = re.compile(r"(?P<config>[\w-]+)\s*:\s*(?P<filename>[\w.-]+)")

def SearchDir(dir_name, lst):
    if os.path.isdir(dir_name):
        for node in os.listdir(dir_name):
            name = os.path.join(dir_name, node)
            if os.path.isfile(name):
                if config_filename_pattern.search(name):
                    lst.append(name)
            elif os.path.isdir(name):
                SearchDir(name, lst)
            else:
                raise ValueError("What???")

def GetAllSortsOfConfig(dir_name):
    configs = []
    if os.path.isdir(dir_name):
        SearchDir(dir_name, configs)
    else:
        raise ValueError("%s not exist or is not a directory" %xed_datafile_dir)
    return configs

def GetConfigContent(config_lst):
    config_map = {}
    for config in config_lst:
        with open(config) as f:
            lines = f.readlines()
        for line in lines:
            result = config_pattern.search(line)
            if result:
                key = result.group("config")
                value = result.group("filename")
                if key in config_map:
                    config_map[key].append(value)
                else:
                    config_map[key] = [value]
    return config_map

def GenerateConfigFiles(indir, outdir, config_dict, subdir="", name_prefix=""):
    if len(subdir):         # if has sub directory
        dir_name = os.path.join(outdir, subdir)
        if not os.path.exists(dir_name):
            os.mkdir(dir_name)
    for config_name in config_dict:
        lines = []
        for filename in config_dict[config_name]:
            config_filename = os.path.join(indir, filename)
            with open(config_filename) as f:
                lines.extend(f.readlines())

        save_config_name = os.path.join(outdir, subdir, name_prefix+config_name+".txt")
        with open(save_config_name, "w") as f:
            f.writelines(lines)

def GenConfigCode(config_dict, main_dir="all-datafiles", subdir="", name_prefix=""):
    code = []
    key = "registers"
    if key in config_dict:
        filename = os.path.join(main_dir, subdir, name_prefix+key+".txt")
        filename = filename.replace("\\", "/")
        code.append("all_reg = \"%s\"" %filename)
    key = "state"
    if key in config_dict:
        filename = os.path.join(main_dir, subdir, name_prefix+key+".txt")
        filename = filename.replace("\\", "/")
        code.append("all_state_file = \"%s\"" %filename)
    key = "enc-patterns"
    if key in config_dict:
        filename = os.path.join(main_dir, subdir, name_prefix+key+".txt")
        filename = filename.replace("\\", "/")
        code.append("all_enc_pattern = \"%s\"" %filename)
    key = "enc-dec-patterns"
    if key in config_dict:
        filename = os.path.join(main_dir, subdir, name_prefix+key+".txt")
        filename = filename.replace("\\", "/")
        code.append("all_enc_dec_pattern = \"%s\"" %filename)
    key = "fields"
    if key in config_dict:
        filename = os.path.join(main_dir, subdir, name_prefix+key+".txt")
        filename = filename.replace("\\", "/")
        code.append("all_field = \"%s\"" %filename)
    key = "enc-instructions"
    if key in config_dict:
        filename = os.path.join(main_dir, subdir, name_prefix+key+".txt")
        filename = filename.replace("\\", "/")
        code.append("all_ins = \"%s\"" %filename)
    return code

if __name__ == "__main__":
    # for filename in GetAllSortsOfConfig(xed_datafile_dir):
    #     print(filename)

    config_dict = GetConfigContent(cfg_needed)
    for key in config_dict:
        print("%s : %s" %(key, config_dict[key]))

    GenerateConfigFiles(xed_datafile_dir, out_dir, config_dict, subdir=subdir_name, name_prefix=generate_file_prefix)
    # code = GenConfigCode(config_dict, subdir=subdir_name, name_prefix=generate_file_prefix)
    # for line in code:
    #     print(line)