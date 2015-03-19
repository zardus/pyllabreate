import idautils #pylint:disable=import-error,unused-import
import idaapi #pylint:disable=import-error,unused-import
import idc #pylint:disable=import-error,unused-import

import os
import json

class ida: #pylint:disable=no-init
    idautils = idautils
    idaapi = idaapi
    idc = idc

class IDAItem(object):
    @staticmethod
    def _dump(obj, dump_file):
        json.dump(obj, dump_file)
        dump_file.write('\n')

    @staticmethod
    def _load(dump_file):
        r = dump_file.readline().strip()
        if len(r) == 0:
            return None
        else:
            return json.loads(r)

    @staticmethod
    def _loads(dump_str):
        return json.loads(dump_str)

    @staticmethod
    def _make_dir(our_dir):
        try: os.makedirs(our_dir)
        except OSError: pass

    @staticmethod
    def _instantiate(attributes):
        if not isinstance(attributes, dict):
            return attributes

        cls = globals()[attributes.pop('__class__')]
        if not issubclass(cls, IDAItem):
            return attributes
        else:
            c = cls.__new__(cls)
            c._set_attributes(attributes)
            return c

    #
    # API
    #

    @property
    def should_dump(self): #pylint:disable=no-self-use
        return True

    @property
    def should_apply(self): #pylint:disable=no-self-use
        return True

    @property
    def uuid(self):
        raise NotImplementedError()

    @staticmethod
    def _is_collection(a):
        return isinstance(a, (dict, tuple, list, set))

    def _all_attributes(self):
        return { k:v for k,v in self.__dict__.items() if not k.startswith('_') }

    @staticmethod
    def _needs_dir(a):
        return isinstance(a, IDAItem) and len(a.ida_items) + len(a.collections) > 0

    @property
    def collections(self):
        return { k:v for k,v in self._all_attributes().items() if self._is_collection(v) }

    @property
    def literals(self):
        a = { k:v for k,v in self._all_attributes().items() if not self._is_collection(v) and not isinstance(v, IDAItem) }
        a['__class__'] = self.__class__.__name__.split('.')[-1]
        return a

    @property
    def ida_items(self):
        return { k:v for k,v in self._all_attributes().items() if isinstance(v, IDAItem) }

    def _set_attributes(self, s):
        self.__dict__.update({ k:v for k,v in s.items() if not k.startswith('_') })

    #
    # This is getting out of hand
    #

    def dump(self, where):
        if not self.should_dump:
            return

        if IDAItem._needs_dir(self):
            self._make_dir(where)
            with open(os.path.join(where, 'literals'), 'w') as f:
                self._dump(self.literals, f)

            for attr, members in self.collections.items():
                IDAItem.dump_multiple(members, os.path.join(where, attr))

            for attr, members in self.ida_items.items():
                IDAItem.dump(members, os.path.join(where, attr))
        else:
            if type(where) is not file:
                with open(where, 'a') as f:
                    return self.dump(f)
            else:
                self._dump(self.literals, where)

    @staticmethod
    def dump_multiple(what, where):
        for o in what:
            if IDAItem._needs_dir(o): o.dump(os.path.join(where, o.uuid))
            else: o.dump(where)

    @staticmethod
    def load(where):
        if os.path.isdir(where) and os.path.exists(os.path.join(where, 'literals')):
            # this is a normal item
            with open(os.path.join(where, 'literals')) as f:
                self = IDAItem._instantiate(IDAItem._load(f))

            for c in os.listdir(where):
                if c == 'literals': continue
                i = IDAItem.load(os.path.join(where, c))
                setattr(self, c, i)

            return self
        elif os.path.isdir(where):
            # this is a collection
            result = [ ]
            for c in os.listdir(where):
                if c == 'literals': continue
                result.append(IDAItem.load(os.path.join(where, c)))
            return result
        else:
            with open(where) as f:
                results = [ ]
                while True:
                    s = IDAItem._load(f)
                    if s is None: break
                    else: results.append(IDAItem._instantiate(s))
                return results

class Instruction(IDAItem):
    def __init__(self, addr):
        self.addr = addr
        self.comment = ida.idc.Comment(self.addr)
        self.repeatable_comment = ida.idc.RptCmt(self.addr)

    def apply(self):
        ida.idc.MakeComm(self.addr, self.comment)
        ida.idc.MakeRptComm(self.addr, self.comment)

    @property
    def should_dump(self):
        return self.comment or self.repeatable_comment

    @property
    def should_apply(self):
        return self.comment or self.repeatable_comment

    @property
    def uuid(self):
        return '%x' % self.addr


class Block(IDAItem):
    def __init__(self, start_addr, end_addr):
        self.start = start_addr
        self.end = end_addr
        self.instructions = [ Instruction(i) for i in ida.idautils.Heads(self.start, self.end) ]

    @property
    def uuid(self):
        return '%x' % self.start

class Function(IDAItem):
    def __init__(self, f_addr):
        self.addr = f_addr
        self.name = ida.idc.Name(self.addr)

        chart = ida.idaapi.FlowChart(ida.idaapi.get_func(self.addr))
        self.blocks = [ Block(block.startEA, block.endEA) for block in chart ]

    @property
    def uuid(self):
        return '%x' % self.addr

class IDAState(IDAItem):
    def __init__(self):
        ida_functions = list(ida.idautils.Functions(0, ida.idc.MaxEA()))
        self.functions = [ Function(f) for f in ida_functions ]

    @property
    def uuid(self):
        return 'state'

real_state = IDAState()
real_state.dump('/tmp/asdf')
#loaded_state = IDAItem.load('/tmp/asdf')
