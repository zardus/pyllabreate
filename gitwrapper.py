#!/usr/bin/python

import git
from os.path import join
from distutils.spawn import find_executable  
import socket
import os
import subprocess
import random

class GitWrapper():

    def __init__(self,remote,local,userid=None,debug=False):
        self.remote = remote
        self.local = local
        self.gitcmd = find_executable("git")
        if userid==None:
            self.userid = socket.gethostname()+"_"+str(random.randint(1000,9999))
        else:
            self.userid = userid
        self.debug = debug


    def exec_cmd(self,cmd):
        args = [self.gitcmd] + cmd
        if self.debug:
            print "EXECUTING:",repr(args)
        pipe = subprocess.PIPE
        p = subprocess.Popen(args,cwd=self.local,stdout=pipe,stderr=pipe)
        std = p.communicate()
        res = (std[0],std[1],p.returncode)
        if self.debug:
            print "RESULT:",repr(res)
        return res


    def is_new(self):
        if(os.path.exists(join(self.local,".git"))):
            return False
        else:
            return True


    def git_init(self):
        if(not os.path.exists(self.local)):
            os.makedirs(self.local)

        self.exec_cmd(["init"])
        self.exec_cmd(["remote","add","origin",self.remote])
        open((join(self.local,"pyllabreate")),'wb').write("pyllabreate")
        self.exec_cmd(["commit","-am","origin","master"])


    def commit_state(self):
        self.exec_cmd(["add","."])
        self.exec_cmd(["commit","-am",self.userid+"[autosave]"])


    def pull_state(self):
        res = self.exec_cmd(["pull","-Xtheirs","origin","master"])
        '''
        if res[2]!=0: #conflict
            #TODO better handling of conflicts
            res = self.exec_cmd(["stash"])
            res = self.exec_cmd(["pull","origin","master"])
        '''
        self.exec_cmd(["clean","-f","-d"])
            

    def push_state(self):
        res = self.exec_cmd(["push","origin","master"])


    def update(self):
        if(self.is_new()):
            self.git_init()

        self.commit_state()
        self.pull_state()
        self.push_state()




if __name__ == "__main__":
    import sys
    import time
    #print sys.argv
    g = GitWrapper(sys.argv[1],sys.argv[2],debug=True)
    while True:
        #get info from ida and write it into files in self.local
        g.update()
        #read files in self.local and push back to ida
        print "="*10,"SLEEPING"
        time.sleep(10.0)

'''
./gitwrapper.py git@bitbucket.org:antonio_bianchi_333/test2.git /tmp/t3
'''



