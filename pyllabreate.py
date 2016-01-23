
import idautils #pylint:disable=import-error,unused-import
import idaapi #pylint:disable=import-error,unused-import
import idc #pylint:disable=import-error,unused-import

import os
import subprocess
import random
import shutil
import time
import threading
import socket
import Queue
import idaapi
from pylab import IDAState,IDAItem


class Pyllabreate:

    auto_time = 15.0

    def __init__(self,local=None,remote=None,repository="origin",branch="master",debug=False):
        self.debug = debug
        self.repository = repository
        self.branch = branch
        
        #I cannot use distutils.spawn in ida :-(
        pipe = subprocess.PIPE
        p = subprocess.Popen("which git",stdout=pipe,stderr=pipe,shell=True)
        self.git_cmd = p.communicate()[0].strip()

        #TODO better userid
        self.userid = socket.gethostname()+"_"+str(random.randint(1000,9999))

        self.git_folder = local
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
        self.first_run = True
        self.looper_thread = threading.Thread(target=self._looper)
        self.looper_thread.start()


    def stop_auto(self):
        print "stop_auto!"
        self.auto_enabled = False #this is atomic!
        #it seems that IDAPython does not like joining...


    def locked_cycle(self):
        self.save()
        self._exec_cmd(["add","."])
        self._exec_cmd(["commit","-am",self.userid+"[autosave]"])
        self._exec_cmd(["merge",self.repository,self.branch, \
                "-X","theirs","-m",self.userid+"[automerge]"])
        self.load()


    def _update_cycle(self):
        print "===update_cycle==="

        self._exec_cmd(["fetch",self.repository,self.branch])
        self._locked_execution(self.locked_cycle,idaapi.MFF_WRITE)
        self._exec_cmd(["push",self.repository,self.branch])
        self._exec_cmd(["clean","-f","-d"])



    def _locked_execution(self,func,ida_lock_type):
        def make_function_locked(func):
            def inner_locked():
                try:
                    start = time.time()
                    return func()
                finally:
                    if self.debug:
                        print "execution locked for:",time.time()-start
                    q.put(None)
            return inner_locked

        q = Queue.Queue()
        idaapi.execute_sync(make_function_locked(func),ida_lock_type)
        q.get()


    def _looper(self):
        print "thread started!"
        last_run = time.time()
        while True:
            time.sleep(0.1)
            if not self.auto_enabled:
                print "stopping thread"
                return
            if self.first_run == False and time.time()-last_run < self.auto_time:
                continue
            self.first_run = False
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
            #in case pylab saves in a differential way, we do not want to delete this
            shutil.rmtree(self.snapshot_folder)
        else:
            #this is the first time we save or something is wrong with git_folder
            pass
        real_state = IDAState()
        real_state.dump(self.snapshot_folder)



'''
add immediate pull after init (option, default on)
add debug option in init
add git_address/local option in init (normally: local = git repo folder, if only git_address: local in tmp)
add binary to repo
add idbs to repo  
origin/master everywhere (values by deault, changeable in init)
avoid ida freeze on exit

==============
fetch
---
save
commit
merge -X theirs (because rebase prefer ours even with -X theirs)
clean files
load
---
push


'''

