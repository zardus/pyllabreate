
import threading
import time

git_folder = None
auto_enabled = False
auto_time = 10.0
looper_thread = None

def ttt():
    print "ttt"


def update_cycle():
    print "===update_cycle==="
    save()
    pull()
    load()
    push()


def looper():
    global auto_enabled
    print "thread started!"
    last_run = time.time()
    while True:
        #print "-"
        time.sleep(0.1)
        if not auto_enabled:
            print "stopping thread"
            return
        if not time.time()-last_run > auto_time:
            continue
        last_run = time.time()
        update_cycle()


#####
def set_git_folder(fname):
    global git_folder
    git_folder = fname


def print_settings():
    print git_folder,auto_enabled,auto_time

#####
def start_auto():
    global auto_enabled
    global looper_thread
    print "start_auto!"
    auto_enabled = True
    looper_thread = threading.Thread(target=looper)
    looper_thread.start()

def stop_auto():
    global auto_enabled
    global looper_thread
    print "stop_auto!"
    auto_enabled = False #this is atomic!
    '''
    print "sleep"
    time.sleep(3.0)
    print "join"
    looper_thread.join()
    print "joined"
    '''

#####
def load():
    print "load!"

def save():
    print "save!"

def push():
    print "push!"

def pull():
    print "pull!"


