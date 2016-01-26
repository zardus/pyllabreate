
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

    def __init__(self,local=None,remote=None,repository="origin",branch="master",auto_time=15.0,debug=True):
        #FIXME: for now we keep debug = True as default
        self.debug = debug
        self.repository = repository
        self.branch = branch
        self.auto_time = auto_time
        
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

    def start_auto(self,keep_local=False,base_commit=None):
        #FIXME ideally keep_local should be default, but it needs to be implemented and tested
        print "start_auto!"
        self.auto_enabled = True
        self.first_run = True
        self.looper_thread = threading.Thread(target=self._looper,args=[keep_local,base_commit])
        self.looper_thread.start()


    def stop_auto(self):
        print "stop_auto!"
        self.auto_enabled = False #this is atomic!
        #it seems that IDAPython does not like joining...


    def locked_cycle(self):
        self.save()
        self._exec_cmd(["add","."])
        self._exec_cmd(["commit","-am",self.userid+"[autosave]"])
        self._exec_cmd(["merge",self.repository+"/"+self.branch, \
                "-X","theirs","-m",self.userid+"[automerge]"])
        self.load()


    def _update_cycle(self,first_run,keep_local,base_commit):
        print "===update_cycle===",first_run,keep_local,base_commit

        if first_run:
            if not keep_local:
                self._exec_cmd(["pull","-u",self.repository,self.branch])
                self._locked_execution(self.load,idaapi.MFF_WRITE)
            else:
                pass
                '''
                #basically we want to rebase what has been done on top of the local changes
                #in case of conflicts what has been done on git wins (which is in the master branch)
                git pull
                if base_commit != None:
                    first_commit = base_commit
                else:
                    first_commit = git rev-list --max-parents=0 HEAD
                git checkout -b tmp1 first_commit
                    save
                    git add .
                    git commit -am "initial stuff"
                    git checkout self.branch
                    git merge tmp1 -X ours
                    load
                git push
                git clean -f -d
                '''
        else:
            self._exec_cmd(["fetch",self.repository,self.branch])
            self._locked_execution(self.locked_cycle,idaapi.MFF_WRITE)
            self._exec_cmd(["push","-u",self.repository,self.branch])
            self._exec_cmd(["clean","-f","-d"])



    def _locked_execution(self,to_lock_function,ida_lock_type):
        def make_function_waitable(f):
            def inner():
                try:
                    start = time.time()
                    return f()
                finally:
                    if self.debug:
                        print "execution locked for:",time.time()-start
                    q.put(None)
            return inner

        q = Queue.Queue()
        idaapi.execute_sync(make_function_waitable(to_lock_function),ida_lock_type)
        q.get()


    def _looper(self,keep_local,base_commit):
        print "thread started!"
        last_run = time.time()
        first_run  = True
        while True:
            time.sleep(0.1)
            if not self.auto_enabled:
                print "stopping thread"
                return
            if first_run == False and time.time()-last_run < self.auto_time:
                continue
            last_run = time.time()
            self._update_cycle(first_run,keep_local,base_commit)
            first_run = False


    def load(self):
        if self.debug:
            print "load"
        loaded_state = IDAItem.load(self.snapshot_folder)
        if loaded_state != []:
            loaded_state.apply()
        else:
            print "empty state!"


    def save(self):
        if self.debug:
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



