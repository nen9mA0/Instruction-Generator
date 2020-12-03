import pickle
import os

class SaveData(object):
    def __init__(self, filename, logger=None):
        if ".txt" in filename:
            pkl_name = filename.replace(".txt", ".pkl")
        else:
            pkl_name = filename + ".pkl"

        self.name = pkl_name
        self.logger = logger
        if os.path.exists(pkl_name):
            self.haspkl = True
        else:
            self.haspkl = False

    def Save(self, obj):
        try:
            with open(self.name, "wb") as f:
                    pickle.dump(obj.storage_fields, f)
                    pickle.dump(obj.state_bits, f)
                    pickle.dump(obj.seqs, f)
                    pickle.dump(obj.nts, f)
                    pickle.dump(obj.ntlufs, f)
                    pickle.dump(obj.deleted_unames, f)
                    pickle.dump(obj.deleted_instructions, f)
                    pickle.dump(obj.iarray, f)
        except Exception as e:
            print(e)
            if os.path.exists(self.name):
                os.remove(self.name)
            return
        self.haspkl = True
        if self.logger:
            self.logger.info("data saved at %s" %self.name)
        return

    def Load(self, obj):
        if self.haspkl:
            if self.logger:
                self.logger.info("load data from %s" %self.name)
            try:
                with open(self.name, "rb") as f:
                    obj.storage_fields = pickle.load(f)
                    obj.state_bits = pickle.load(f)
                    obj.seqs = pickle.load(f)
                    obj.nts = pickle.load(f)
                    obj.ntlufs = pickle.load(f)
                    obj.deleted_unames = pickle.load(f)
                    obj.deleted_instructions = pickle.load(f)
                    obj.iarray = pickle.load(f)
            except Exception as e:
                print(e)
                return None
            return True
        else:
            return None