#!/usr/bin/env python3

import argparse
import os
import re
import sys

SMB3_FNS_FILE       = 'smb3.fns'
SMB3_PRG_TEMPLATE   = 'prg{:03}.asm'

JAVA_SYMBOL_TEMPLATE = '''
package inesloader;

import inesloader.SMB3Symbols;
import inesloader.SMB3Symbols.BankSymbol;

public class SMB3AutoSymsBank{0} {{
    public static final BankSymbol[] SMB3_BANK{0:03}_SYMS = {{
'''

def main(sysargs):
    parser = argparse.ArgumentParser(description='Parse out all the symbols within SMB3\'s asm files.')
    parser.add_argument('disasmdir', help='Path to the top-level directory of the SMB3 disassembly.')

    args = parser.parse_args()
    args.disasmdir = os.path.realpath(args.disasmdir)

    # Symbols and includes, but ignore commented lines
    # For symbols, we don't want ".func" macros (?! is a negative lookahead)
    sympat = '^([^;\s\.]+?):((?!\.func).)*?$'
    incpat = '^[^;]+?\.include[ ]+"(.*?)".*?$'

    syms = {}
    for i in range(32):
        symbank = lambda xx: (xx[0], {'bank': i, 'addr': 0})
        fname = os.path.join(args.disasmdir, 'PRG', SMB3_PRG_TEMPLATE.format(i))
        try:
            with open(fname, 'r') as f:
                data = f.read()

            syms.update(map(symbank, re.findall(sympat, data, re.MULTILINE)))

            for inc in re.findall(incpat, data, re.MULTILINE):
                ext = '' if '.asm' in inc else '.asm'
                incfile = os.path.join(args.disasmdir, inc + ext)
                with open(incfile, 'r') as f:
                    data = f.read()

                syms.update(map(symbank, re.findall(sympat, data, re.MULTILINE)))

                # Only need one level of recursion here, and we technically
                # don't even need this because all the symbols are in the
                # higher level files. These are all just data bytes.
                for inc2 in re.findall(incpat, data, re.MULTILINE):
                    ext = '' if '.asm' in inc2 else '.asm'
                    incfile = os.path.join(args.disasmdir, inc2 + ext)
                    with open(incfile, 'r') as f:
                        data = f.read()

                    syms.update(map(symbank, re.findall(sympat, data, re.MULTILINE)))

            #with open(fname + '.syms', 'w') as f:
            #    for s in syms:
            #        f.write('{}\n'.format(s))
        except Exception as e:
            print(e)

    print('Found {} symbols.'.format(len(syms)))

    fnsname = os.path.join(args.disasmdir, SMB3_FNS_FILE)
    try:
        fnsinfo = os.lstat(fnsname)
    except FileNotFoundError as e:
        print('Failed to open "{}". Has SMB3 been assembled?'.format(fnsname))
        return 1

    with open(fnsname, 'r') as f:
        fnslines = f.readlines()

    outfs = [None]*32
    for i in range(len(outfs)):
        outfs[i] = open(os.path.realpath('./SMB3AutoSymsBank{}.java'.format(i)), 'w')
        outfs[i].write(JAVA_SYMBOL_TEMPLATE.format(i))


    for s in syms:
        try:
            fnspat = '^{}[ ]+= \$[0-9A-F][0-9A-F][0-9A-F][0-9A-F]$'.format(s)
            line = next(re.search(fnspat, l).group(0) for l in fnslines if re.search(fnspat, l) is not None)
            syms[s]['addr'] = int('0x'+line[-4:], 0)

            outfs[syms[s]['bank']].write('        new BankSymbol("{}", {}, 0x{:X}),\n'.format(s, syms[s]['bank'], syms[s]['addr']))
        except StopIteration as e:
            print('Did not find symbol "{}"'.format(s))

    for i in range(len(outfs)):
        outfs[i].write('    };\n}')
        outfs[i].close()

    return 0

if __name__ == '__main__':
    main(sys.argv[1:])
