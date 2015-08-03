
import os
import subprocess
import random
import shutil
import time
import threading
import socket
from pylab import IDAState,IDAItem


class Pyllabreate:

    auto_time = 10.0

    def __init__(self,git_folder):
        self.debug = False
        
        #I cannot use distutils.spawn in ida :-(
        pipe = subprocess.PIPE
        p = subprocess.Popen("which git",stdout=pipe,stderr=pipe,shell=True)
        self.git_cmd = p.communicate()[0].strip()

        #TODO better userid
        self.userid = socket.gethostname()+"_"+str(random.randint(1000,9999))

        self.git_folder = git_folder
        self.snapshot_folder = os.path.join(self.git_folder,"snapshot")
        if not os.path.exists(self.snapshot_folder):
            os.makedirs(self.snapshot_folder)

        self.auto_enabled = False
        self.looper_thread = None


    def _exec_cmd(self,cmd):
        args = [self.git_cmd] + cmd
        if self.debug:
            print "EXECUTING:",repr(args)
        pipe = subprocess.PIPE
        p = subprocess.Popen(args,cwd=self.git_folder,stdout=pipe,stderr=pipe)
        std = p.communicate()
        res = (std[0],std[1],p.returncode)
        if self.debug:
            print "RESULT:",repr(res)
        return res


    ##########

    def start_auto(self):
        print "start_auto!"
        self.auto_enabled = True
        self.looper_thread = threading.Thread(target=self._looper)
        self.looper_thread.start()

    def stop_auto(self):
        print "stop_auto!"
        self.auto_enabled = False #this is atomic!
        #it seems that IDAPython does not like joining...


    def _update_cycle(self):
        print "===update_cycle==="
        self.save()
        self.pull()
        self.load()
        self.push()


    def _looper(self):
        print "thread started!"
        last_run = time.time()
        while True:
            time.sleep(0.1)
            if not self.auto_enabled:
                print "stopping thread"
                return
            if not time.time()-last_run > self.auto_time:
                continue
            last_run = time.time()
            self._update_cycle()


    ##########

    def load(self):
        print "load"
        loaded_state = IDAItem.load(self.snapshot_folder)
        if loaded_state != []:
            loaded_state.apply()
        else:
            print "empty state!"


    def save(self):
        print "save"
        #paranoid check
        if(os.path.exists(os.path.join(self.snapshot_folder,"function_names"))):
            shutil.rmtree(self.snapshot_folder)
        else:
            print "something is wrong with your git_folder:",self.git_folder
            return
        real_state = IDAState()
        real_state.dump(self.snapshot_folder)


    def push(self):
        print "push"
        self._exec_cmd(["add","."])
        self._exec_cmd(["commit","-am",self.userid+"[autosave]"])
        #TODO ideally we want the user to be able to select the branch, but we need to put explicitly origin/master the first time
        self._exec_cmd(["push","origin","master"]) 


    def pull(self):
        print "pull"
        res = self._exec_cmd(["pull","-Xtheirs","origin","master"])
        self._exec_cmd(["clean","-f","-d"])

