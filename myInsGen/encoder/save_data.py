import os

class SaveData(object):
    def __init__(self, filename, pkl_dir=None, logger=None):
        filename = filename.lower()
        if ".txt" in filename:
            pkl_name = filename.replace(".txt", ".pkl")
        else:
            pkl_name = filename + ".pkl"

        if pkl_dir:
            raw_filename = os.path.split(pkl_name)[-1]
            pkl_name = os.path.join(pkl_dir, raw_filename)

        self.name = pkl_name
        self.logger = logger
        self.ext_filename = ""
        if os.path.exists(pkl_name):
            self.haspkl = True
        else:
            self.haspkl = False

    def SetFilename(self, name):
        self.ext_filename = name

    def ResetFilename(self):
        self.ext_filename = ""

    def Save(self, fn, *args):
        if self.ext_filename != "":
            name = self.ext_filename
        else:
            name = self.name
        try:
            with open(name, "wb") as f:
                fn(f, *args)
        except Exception as e:
            print(e)
            if os.path.exists(name):
                os.remove(name)
            return
        self.haspkl = True
        if self.logger:
            self.logger.info("data saved at %s" %name)
        return

    def Load(self, fn, *args):
        if self.haspkl:
            if self.ext_filename != "":
                name = self.ext_filename
            else:
                name = self.name

            if self.logger:
                self.logger.info("load data from %s" %name)
            try:
                with open(name, "rb") as f:
                    fn(f, *args)
            except Exception as e:
                print(e)
                return None
            return True
        else:
            return None