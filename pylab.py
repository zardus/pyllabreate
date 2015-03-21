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
    def _fix_path(s):
        return s.replace('/', '_')

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
        return '%x' % self.addr #pylint:disable=no-member

    def __lt__(self, other):
        return self.uuid < other.uuid
    def __gt__(self, other):
        return self.uuid > other.uuid
    def __le__(self, other):
        return self.uuid <= other.uuid
    def __ge__(self, other):
        return self.uuid >= other.uuid

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

    def apply(self): pass

    #
    # Static stuff
    #

    @staticmethod
    def _is_collection(a):
        return isinstance(a, (dict, tuple, list, set))

    def _all_attributes(self):
        return { k:v for k,v in self.__dict__.items() if not k.startswith('_') }

    @staticmethod
    def _needs_dir(a):
        return isinstance(a, IDAItem) and len(a.ida_items) + len(a.collections) > 0

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
                self._make_dir(where)
                IDAItem.dump_multiple(members, os.path.join(where, self._fix_path(attr)))

            for attr, members in self.ida_items.items():
                IDAItem.dump(members, os.path.join(where, self._fix_path(attr)))
        else:
            if type(where) is not file:
                with open(where, 'a') as f:
                    return self.dump(f)
            else:
                self._dump(self.literals, where)

    @staticmethod
    def dump_multiple(what, where):
        for o in what:
            if IDAItem._needs_dir(o): o.dump(os.path.join(where, IDAItem._fix_path(o.uuid)))
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

#
# Actual IDA constructs
#

class Comment(IDAItem):
    def __init__(self, addr):
        self.addr = addr
        self.comment = ida.idc.Comment(self.addr)
        self.repeatable_comment = ida.idc.RptCmt(self.addr)

    def apply(self):
        if self.comment: ida.idc.MakeComm(self.addr, str(self.comment))
        if self.repeatable_comment: ida.idc.MakeRptCmt(self.addr, str(self.repeatable_comment))

    @classmethod
    def export(cls, function_addr):
        results = [ ]
        for i in idautils.FuncItems(function_addr):
            c = Comment(i)
            if c.comment or c.repeatable_comment:
                results.append(c)
        return sorted(results)

class Member(IDAItem):
    def __init__(self, sid, offset, name, size):
        self.offset = offset
        self.name = name
        self.size = size
        self.struct_name = ida.idc.GetStrucName(sid)

        self.flag = ida.idc.GetMemberFlag(sid, offset)
        self.type = ida.idc.GetType(ida.idc.GetMemberId(sid, offset))
        self.comment = ida.idc.GetMemberComment(sid, offset, False)
        self.repeatable_comment = ida.idc.GetMemberComment(sid, offset, True)

    @property
    def sid(self):
        return ida.idc.GetStrucIdByName(str(self.struct_name))

    @property
    def typeid(self): #pylint:disable=no-self-use
        return -1

    def overlaps(self, other):
        their_bytes = set(range(other.offset, other.offset + other.size))
        our_bytes = set(range(self.offset, self.offset + self.size))
        return len(our_bytes | their_bytes) != 0

    def _overlapping_members(self):
        overlapping = [ ]

        others = ida.idautils.StructMembers(self.sid)
        for offset,name,size in others:
            m = Member(self.sid, offset, name, size)
            if self.overlaps(m): overlapping.append(m)

        return overlapping

    def apply(self):
        # first, delete any overlapping members
        overlapping = self._overlapping_members()
        for o in overlapping:
            ida.idc.DelStrucMember(o.sid, o.offset)

        # now, actually apply ours!
        m = ida.idc.AddStrucMember(self.sid, str(self.name), self.offset, self.flag, self.typeid, self.size)
        print str(self.name), m

        if self.comment:
            ida.idc.SetMemberComment(self.sid, self.offset, str(self.comment), False)
        if self.repeatable_comment:
            ida.idc.SetMemberComment(self.sid, self.offset, str(self.repeatable_comment), True)


    @classmethod
    def export(cls, sid):
        results = [ ]

        for offset, name, size in ida.idautils.StructMembers(sid):
            results.append(Member(sid, offset, name, size))

        return results

class Struct(IDAItem):
    def __new__(cls, *args, **kwargs):
        self = object.__new__(cls, *args, **kwargs)
        self.members = [ ]
        return self

    def __init__(self, sid):
        self.name = ida.idc.GetStrucName(sid)
        self.size = ida.idc.GetStrucSize(sid)
        self.comment = ida.idc.GetStrucComment(sid, False)
        self.repeatable_comment = ida.idc.GetStrucComment(sid, False)

        self.members = Member.export(sid)

    @property
    def uuid(self):
        return self.name

    def apply_members(self):
        print "STARTING FOR %s" % self.name
        for m in self.members:
            m.apply()

    def apply_self(self):
        sid = ida.idc.GetStrucIdByName(str(self.name))
        if sid == ida.idc.BADADDR:
            sid = ida.idc.AddStruc(ida.idc.GetStrucQty(), str(self.name))
            ida.idc.SetStrucName(sid, str(self.name))

        ida.idc.SetStrucComment(sid, str(self.comment), False)
        ida.idc.SetStrucComment(sid, str(self.repeatable_comment), True)

    @classmethod
    def export(cls):
        results = [ ]

        for _, struct_idx, _ in ida.idautils.Structs():
            results.append(Struct(struct_idx))

        for f in ida.idautils.Functions(0, ida.idc.MaxEA()):
            f = idc.GetFrame(f)
            if f: results.append(Struct(f))

        return results

class FunctionInfo(IDAItem):
    def __new__(cls, *args, **kwargs):
        self = object.__new__(cls, *args, **kwargs)
        self.comments = [ ]
        return self

    def __init__(self, f_addr):
        self.addr = f_addr
        self.comments = Comment.export(f_addr)

    def apply(self):
        for c in self.comments:
            c.apply()

    @classmethod
    def export(cls):
        return sorted(cls(f) for f in ida.idautils.Functions(0, ida.idc.MaxEA()))

class FunctionName(IDAItem):
    def __init__(self, f_addr):
        self.addr = f_addr
        self.name = ida.idc.Name(self.addr)

    def apply(self):
        if ida.idc.Name(self.addr) != str(self.name):
            ida.idc.MakeName(self.addr, str(self.name))

    @classmethod
    def export(cls):
        return sorted(cls(f) for f in ida.idautils.Functions(0, ida.idc.MaxEA()))

class IDAState(IDAItem):
    def __new__(cls, *args, **kwargs):
        self = object.__new__(cls, *args, **kwargs)
        self.function_comments = [ ]
        self.function_names = [ ]
        self.structures = [ ]
        return self

    def __init__(self):
        self.function_comments = FunctionInfo.export()
        self.function_names = FunctionName.export()
        self.structures = Struct.export()

    def apply(self):
        for f in self.function_names: f.apply()
        for f in self.function_comments: f.apply()

        # make all the structs first, then make the members
        for f in self.structures: f.apply_self()
        for f in self.structures: f.apply_members()

    @property
    def uuid(self):
        return 'state'

#real_state = IDAState()
#real_state.dump('/tmp/asdf')
loaded_state = IDAItem.load('/tmp/asdf')
loaded_state.apply() #pylint:disable=no-member
