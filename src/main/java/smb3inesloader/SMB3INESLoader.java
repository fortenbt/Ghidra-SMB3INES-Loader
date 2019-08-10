package inesloader;

import inesloader.SMB3Symbols;
import inesloader.SMB3Symbols.Symbol;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SMB3INESLoader extends AbstractLibrarySupportLoader {
    /*
    private static class Bank {
        int bank;
        FlatProgramAPI api;
        private Bank(FlatProgramAPI api, int bank) {
            this.bank = bank;
            this.api = api;
        }
        private Address addr(int addr) {
            short a16 = (short)addr;
            String s = String.format("bank%03d::%04x", this.bank, a16);
            try {
                return this.api.toAddr(s);
            } catch(Exception e) {
                Msg.error(this, String.format("Failed to create bank address from bank %03d and address 0x%04X", this.bank, a16), e);
                return null;
            }
        }
    }
    */

    private static class NESMemorySegment {
        String name;
        int addr;
        int size;

        private NESMemorySegment(String name, int addr, int size) {
            this.name = name;
            this.addr = addr;
            this.size = size;
        }
    }

    private static final int INES_MAGIC = 0x1a53454e;   // 'N' 'E' 'S' '\x1A'
    private static final int PRG_BANK_SIZE = 0x2000;    // Banks are 8 KB
    private static final int[] SMB3_BANKS = {
        0xC000, //  Bank 000
        0xA000, //  Bank 001
        0xA000, //  Bank 002
        0xA000, //  Bank 003
        0xA000, //  Bank 004
        0xA000, //  Bank 005
        0xC000, //  Bank 006
        0xA000, //  Bank 007
        0xA000, //  Bank 008
        0xA000, //  Bank 009
        0xC000, //  Bank 010
        0xA000, //  Bank 011
        0xA000, //  Bank 012
        0xA000, //  Bank 013
        0xC000, //  Bank 014
        0xA000, //  Bank 015
        0xA000, //  Bank 016
        0xA000, //  Bank 017
        0xA000, //  Bank 018
        0xA000, //  Bank 019
        0xA000, //  Bank 020
        0xA000, //  Bank 021
        0xC000, //  Bank 022
        0xA000, //  Bank 023
        0xA000, //  Bank 024
        0xC000, //  Bank 025
        0xA000, //  Bank 026
        0xA000, //  Bank 027
        0xA000, //  Bank 028
        0xC000, //  Bank 029
        0x8000, //  Bank 030
        0xE000, //  Bank 031
    };

    private static final NESMemorySegment[] SMB3_SEGMENTS = {
        new NESMemorySegment("SPRITE_RAM", 0x200, 0x100),
        new NESMemorySegment("RAM", 0x300, 0x500),
        new NESMemorySegment("PPU_REGS", 0x2000, 0x8),
        new NESMemorySegment("2A03_REGS", 0x4000, 0x18),
        new NESMemorySegment("MMC3_SRAM", 0x6000, 0x2000),
    };

    private INESHeader header;
    private FlatProgramAPI api;

    @Override
    public String getName() {
        return "Super Mario Bros. 3 INES Nintendo Entertainment System ROM";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        BinaryReader reader = new BinaryReader(provider, true);
        if (reader.readNextInt() == INES_MAGIC)
            return List.of(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));
        return new ArrayList<>();
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
            MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
        BinaryReader reader = new BinaryReader(provider, true);

        this.api = new FlatProgramAPI(program, monitor);
        this.header = new INESHeader(reader);

        /**
         * INES header specifies number of 16 KB units, but each bank
         * is only 8 KB, so we have to loop through double.
         */
        for (int i = 0; i < this.header.cPRGROM16KbUnits*2; i++) {
            InputStream input = provider.getInputStream(this.header.toDataType().getLength() + (i * PRG_BANK_SIZE));
            String segName = String.format("bank%03d", i);

            boolean overlay = (i < 30);
            createSegment(input, segName, this.api.toAddr(SMB3_BANKS[i]), PRG_BANK_SIZE, true, false, true, overlay);
        }

        /**
         * SMB3 RAM & PPU segments
         */
        for(NESMemorySegment seg : SMB3_SEGMENTS) {
            createUninitializedSegment(seg.name, this.api.toAddr(seg.addr), seg.size, true, true, true, false);
        }

        loadEntry();
        labelSymbols();
    }

    private void labelSymbols() {
        FlatProgramAPI api = this.api;
        for (Symbol s : SMB3Symbols.IO_SYMS) {
            try {
                api.createLabel(api.toAddr(s.addr), s.name, true);
            } catch (Exception e) {
                Msg.error(this, e.getMessage());
            }
        }
        for (Symbol s : SMB3Symbols.ZERO_PAGE_COMMON_SYMS) {
            try {
                api.createLabel(api.toAddr(s.addr), s.name, true);
            } catch (Exception e) {
                Msg.error(this, e.getMessage());
            }
        }
        for (Symbol s : SMB3Symbols.LOW_STACK_SYMS) {
            try {
                api.createLabel(api.toAddr(s.addr), s.name, true);
            } catch (Exception e) {
                Msg.error(this, e.getMessage());
            }
        }
        for (Symbol s : SMB3Symbols.SPRITE_SYMS) {
            try {
                api.createLabel(api.toAddr(s.addr), s.name, true);
            } catch (Exception e) {
                Msg.error(this, e.getMessage());
            }
        }
        for (Symbol s : SMB3Symbols.RAM_SYMS) {
            try {
                api.createLabel(api.toAddr(s.addr), s.name, true);
            } catch (Exception e) {
                Msg.error(this, e.getMessage());
            }
        }
    }

    private void loadEntry() {
        Address IntReset = makeVectorTable();
        if (IntReset == null) {
            return;
        }
        this.api.addEntryPoint(IntReset);
    }

    private Address makeVectorTable() {
        FlatProgramAPI api = this.api;
        int pIntNMI   = 0xfffa;
        int pIntReset = 0xfffc;
        int pIntIRQ   = 0xfffe;
        Address IntReset = null; /* We'll return this. */

        try {
            int nmi = api.getShort(api.toAddr(pIntNMI)) & 0xffff;
            int reset = api.getShort(api.toAddr(pIntReset)) & 0xffff;
            int irq = api.getShort(api.toAddr(pIntIRQ)) & 0xffff;
            IntReset = api.toAddr(reset);

            api.createLabel(api.toAddr(pIntNMI), "Vector_Table", true);
            createPointer(api.toAddr(pIntNMI));
            createPointer(api.toAddr(pIntReset));
            createPointer(api.toAddr(pIntIRQ));

            api.createFunction(api.toAddr(nmi), "IntNMI");
            api.disassemble(api.toAddr(nmi));
            api.createFunction(IntReset, "IntReset");
            api.disassemble(IntReset);
            api.createFunction(api.toAddr(irq), "IntIRQ");
            api.disassemble(api.toAddr(irq));
        } catch(Exception e) {
            Msg.error(this, "Failed to create VectorTable", e);
            return null;
        }
        return IntReset;
    }

    private void createSegment(InputStream input, String name, Address start, long length, boolean read, boolean write, boolean exec, boolean overlay) {
        try {
            MemoryBlock blk = this.api.createMemoryBlock(name, start, input, length, overlay);
            blk.setRead(read);
            blk.setWrite(write);
            blk.setExecute(exec);
        } catch (Exception e) {
            Msg.error(this, e.getMessage());
        }
    }

    private void createUninitializedSegment(String name, Address start, long length, boolean read, boolean write, boolean exec, boolean overlay) {
        Program program = this.api.getCurrentProgram();
        try {
            MemoryBlock blk = program.getMemory().createUninitializedBlock(name, start, length, overlay);
            blk.setRead(read);
            blk.setWrite(write);
            blk.setExecute(exec);
        } catch (Exception e) {
            Msg.error(this, e.getMessage());
        }
    }

    private int createPointer(Address addr) {
        FlatProgramAPI api = this.api;
        try {
            api.createData(addr, PointerDataType.dataType);
        } catch (Exception e) {
            Msg.error(this, String.format("Failed to create pointer at 0x%X", addr.getOffset()), e);
        }
        return 0;
    }
}
