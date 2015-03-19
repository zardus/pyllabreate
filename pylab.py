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
    def _dump(self, obj, dump_file): #pylint:disable=no-self-use
        json.dump(obj, dump_file)
        dump_file.write('\n')

    def _load(self, dump_file): #pylint:disable=no-self-use
        return json.load(dump_file)

    def _make_dir(self, our_dir): #pylint:disable=no-self-use
        try: os.makedirs(our_dir)
        except OSError: pass

class Instruction(IDAItem):
    def __init__(self, addr):
        self._addr = addr
        self._comment = ida.idc.Comment(self._addr)

    def to_literal(self):
        return { 'addr': self._addr, 'comment': self._comment }

class Block(IDAItem):
    def __init__(self, start_addr, end_addr):
        self._start = start_addr
        self._end = end_addr
        self._instructions = { }

        for i in ida.idautils.Heads(self._start, self._end):
            self._instructions[i] = Instruction(i)

    def export(self, directory):
        block_file = os.path.join(directory, '%x' % self._start)
        #self._make_dir(block_dir)

        with open(block_file, 'w') as block_file:
            self._dump({ 'start': self._start, 'end': self._end }, block_file)
            for i in self._instructions.values():
                self._dump(i.to_literal(), block_file)

class Function(IDAItem):
    def __init__(self, f_addr):
        self._addr = f_addr
        self._name = ida.idc.Name(self._addr)
        self._blocks = { }

        chart = ida.idaapi.FlowChart(ida.idaapi.get_func(self._addr))
        for block in chart:
            self._blocks[block.startEA] = Block(block.startEA, block.endEA)

    def export(self, directory):
        our_dir = os.path.join(directory, '%x' % self._addr)
        self._make_dir(our_dir)

        with open(os.path.join(our_dir, 'name'), 'w') as name_file:
            self._dump(self._name, name_file)

        block_dir = os.path.join(our_dir, 'blocks')
        self._make_dir(block_dir)
        for b in self._blocks.values():
            b.export(block_dir)

class Exporter(object):
    def __init__(self, directory):
        self._dir = directory

    def export(self):
        all_functions = list(ida.idautils.Functions(0, ida.idc.MaxEA()))

        for f_addr in all_functions:
            f = Function(f_addr)
            f.export(self._dir)

Exporter('/tmp/asdf').export()
