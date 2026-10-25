"""Conservative ED6 bytecode span parser and text relocation.

opcodes.json contains numeric format facts derived from Calmare's 3rd.yml;
no game data is embedded. Unknown formats fail closed. PSP-specific command
differences must be demonstrated against the input before being supported.
"""
from dataclasses import dataclass
import bisect
import json
from pathlib import Path
import struct

from formats import FormatError, ed6_header, require, u16

SPEC = json.loads((Path(__file__).parent/'recipes'/'opcodes.json').read_text())


@dataclass
class Span:
    start: int
    end: int
    kind: str


class Script:
    def __init__(self, data):
        self.data = data
        self.header = ed6_header(data)
        self.pos = self.header['code_start']
        self.texts, self.labels, self.lengths, self.instructions = [], [], [], []
        self.function_refs = []
        self.funcs = [u16(data, p) for p in range(self.header['function_table'],
                      self.header['string_table'], 2)]
        self.functions = []
        for i, start in enumerate(self.funcs):
            end = self.funcs[i+1] if i+1 < len(self.funcs) else self.header['function_table']
            require(start == self.pos and end >= start, 'Invalid function sequence')
            rows = self.code(end)
            self.functions.append(rows)
        require(self.pos == self.header['function_table'], 'Unparsed code bytes')
        self.string_spans = []
        p = self.header['string_table']
        while p < len(data):
            end = data.find(b'\0', p)
            require(end >= p, 'Unterminated string table')
            self.string_spans.append(Span(p, end+1, 'name'))
            p = end+1
        starts = {r['start'] for r in self.instructions}
        require(all(target in starts for _, target in self.labels),
                'Branch target is not an instruction boundary')

    def number(self, n):
        require(self.pos+n <= self.header['function_table'], 'Operand crosses code boundary')
        value = int.from_bytes(self.data[self.pos:self.pos+n], 'little')
        self.pos += n
        return value

    def string(self, kind):
        start = self.pos
        while True:
            ch = self.number(1)
            if ch == 0:
                break
            if kind == 'text':
                if ch == 7:
                    self.number(1)
                elif ch == 0x1f:
                    self.number(2)
        if kind != 'resource':
            self.texts.append(Span(start, self.pos, kind))

    def expr(self):
        while True:
            op = self.number(1)
            if op == 1:
                return
            if op == 0:
                self.number(4)
            elif op in (0x1e, 0x1f):
                self.number(2)
            elif op in (0x20, 0x23):
                self.number(1)
            elif op == 0x21:
                self.number(3)
            elif op == 0x1c:
                self.insn()
            else:
                require(2 <= op <= 0x1d or op == 0x22, 'Unknown expression opcode')

    def arg(self, spec, previous):
        if isinstance(spec, int):
            return self.number(spec)
        if isinstance(spec, list):
            values = []
            for item in spec:
                values.append(self.arg(item, values))
            return values
        if isinstance(spec, dict):
            count_spec, case = spec['switch']
            for _ in range(self.arg(count_spec, [])):
                self.arg(case, [])
            return None
        if spec in ('TString', 'Menu', 'Text'):
            self.string('text' if spec == 'Text' else 'string')
        elif spec == 'String':
            self.string('resource')
        elif spec == 'Label':
            pos = self.pos
            self.labels.append((pos, self.number(2)))
        elif spec == 'FuncId':
            pos = self.pos
            value = self.number(3)
            self.function_refs.append((pos, value & 255, value >> 8))
        elif spec == 'Expr':
            self.expr()
        elif spec in ('Pos2', 'Pos3', 'RPos3', 'EffPlayPos'):
            self.number(8 if spec == 'Pos2' else 12)
        elif spec in ('Fork', 'ForkLoop'):
            pos = self.pos
            length = self.number(1)
            start = self.pos
            self.code(start+length)
            self.lengths.append((pos, start, self.pos))
            if spec == 'Fork' and length:
                require(self.number(1) == 0, 'Invalid fork terminator')
            elif spec == 'ForkLoop':
                self.insn()
                self.insn()
        elif spec in ('QuestList', 'PartySelectOptional'):
            while self.number(2) != 0xffff:
                pass
        elif spec == 'PartySelectMandatory':
            self.number(8)
        elif spec == 'TcMembers':
            self.number(4)
        elif spec == 'EvoSave':
            pass
        elif spec == 'ScPartySetSlot':
            if 0x7f <= previous[1] <= 0xfe:
                self.number(1)
        else:
            raise FormatError('Unsupported operand '+str(spec))
        return None

    def args(self, spec):
        if isinstance(spec, dict):
            previous = []
            for s in spec['head']:
                previous.append(self.arg(s, previous))
            case = self.number(1)
            require(case < len(spec['cases']), 'Unknown command variant')
            self.args(spec['cases'][case])
        else:
            require(spec is not None, 'Unknown command')
            previous = []
            for s in spec:
                previous.append(self.arg(s, previous))

    def insn(self):
        start = self.pos
        op = self.number(1)
        nt, nl, nn, nf = len(self.texts), len(self.labels), len(self.lengths), len(self.function_refs)
        try:
            self.args(SPEC[op])
        except FormatError as e:
            raise FormatError(f'{start:#x}, opcode {op:#x}: {e}') from e
        row = {'start': start, 'end': self.pos, 'opcode': op,
               'texts': self.texts[nt:], 'labels': self.labels[nl:],
               'lengths': self.lengths[nn:], 'function_refs': self.function_refs[nf:]}
        self.instructions.append(row)
        return row

    def code(self, end):
        result = []
        while self.pos < end:
            result.append(self.insn())
        require(self.pos == end, 'Instruction crosses function/fork boundary')
        return result

    def normalized(self, row):
        # Keep every non-text operand byte. Only relocatable fields are masked.
        edits = [(t.start, t.end, b'\0TEXT\0') for t in row['texts']]
        edits += [(p, p+2, b'\0\0') for p, _ in row['labels']]
        edits += [(p, p+1, b'\0') for p, _, _ in row['lengths']]
        return self._edit(self.data, row['start'], row['end'], edits)

    @staticmethod
    def _edit(data, start, end, edits):
        out, cursor = bytearray(), start
        for a, b, value in sorted(edits):
            require(cursor <= a <= b <= end, 'Overlapping edits')
            out.extend(data[cursor:a]); out.extend(value); cursor = b
        out.extend(data[cursor:end])
        return bytes(out)

    def rebuild(self, replacements):
        """Replace explicit text spans, relocate branches, lengths and header pointers."""
        allowed = {(s.start, s.end) for s in self.texts+self.string_spans}
        require(all((a, b) in allowed and isinstance(v, bytes) for a, b, v in replacements),
                'Edit outside a known text span')
        replacements = sorted(replacements)
        require(all(replacements[i][1] <= replacements[i+1][0]
                    for i in range(len(replacements)-1)), 'Overlapping replacement spans')
        ends, deltas, total = [], [], 0
        for a, b, v in replacements:
            require(v.endswith(b'\0'), 'Translated field must be terminated')
            total += len(v)-(b-a)
            ends.append(b); deltas.append(total)

        def relocate(pos):
            require(not any(a < pos < b for a, b, _ in replacements),
                    'Pointer into replaced text')
            i = bisect.bisect_right(ends, pos)-1
            return pos + (deltas[i] if i >= 0 else 0)

        out = bytearray(self._edit(self.data, 0, len(self.data), replacements))

        def write(pos, size, value):
            require(0 <= value < 1 << (size*8), f'{size*8}-bit relocation overflow')
            pos = relocate(pos)
            out[pos:pos+size] = value.to_bytes(size, 'little')

        for pos, target in self.labels:
            write(pos, 2, relocate(target))
        for pos, start, end in self.lengths:
            write(pos, 1, relocate(end)-relocate(start))
        for pos in [0x42, 0x46, 0x4a, 0x4e, 0x52, 0x56, 0x5a, 0x60]:
            write(pos, 2, relocate(u16(self.data, pos)))
        for i, target in enumerate(self.funcs):
            write(self.header['function_table']+2*i, 2, relocate(target))
        # A parser round trip must preserve all non-text instructions and references.
        rebuilt = Script(bytes(out))
        require(len(rebuilt.instructions) == len(self.instructions), 'Instruction count changed')
        require(all(self.normalized(a) == rebuilt.normalized(b)
                    for a,b in zip(self.instructions, rebuilt.instructions)),
                'Non-text instruction bytes changed')
        before = {r['start']:i for i,r in enumerate(self.instructions)}
        after = {r['start']:i for i,r in enumerate(rebuilt.instructions)}
        require([before[target] for _,target in self.labels] ==
                [after[target] for _,target in rebuilt.labels], 'Branch destination changed')
        require([before[target] for target in self.funcs] ==
                [after[target] for target in rebuilt.funcs], 'Function destination changed')
        return bytes(out)
