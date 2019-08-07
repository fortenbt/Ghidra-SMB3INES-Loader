package inesloader;

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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SMB3INESLoader extends AbstractLibrarySupportLoader {
    private static class SMB3RamSegment {
        String name;
        int addr;
        int size;

        private SMB3RamSegment(String name, int addr, int size) {
            this.name = name;
            this.addr = addr;
            this.size = size;
        }
    }

    private static final int INES_MAGIC = 0x1a53454e;   // 'N' 'E' 'S' '\x1A'
    private static final int PRG_BANK_SIZE = 0x2000;    // Banks are 8 KB
    private static final int SMB3_BANK_VAS[] = {
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

    private static final SMB3RamSegment[] SMB3_RAM_SEGMENTS = {
        new SMB3RamSegment("SPRITE_RAM", 0x200, 0x100),
        new SMB3RamSegment("RAM", 0x300, 0x500),
        new SMB3RamSegment("MMC3_SRAM", 0x6000, 0x2000),
    };

    private INESHeader header;

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
        FlatProgramAPI api = new FlatProgramAPI(program, monitor);

        header = new INESHeader(reader);

        /**
         * INES header specifies number of 16 KB units, but each bank
         * is only 8 KB, so we have to loop through double.
         */
        for (int i = 0; i < header.cPRGROM16KbUnits*2; i++) {
            InputStream input = provider.getInputStream(header.toDataType().getLength() + (i * PRG_BANK_SIZE));
            String segName = String.format("bank%03d", i);

            createSegment(api, input, segName, api.toAddr(SMB3_BANK_VAS[i]), PRG_BANK_SIZE, true, false, true, true);
        }

        /**
         * SMB3 RAM segments
         */
        for(SMB3RamSegment seg : SMB3_RAM_SEGMENTS) {
            createUninitializedSegment(api, seg.name, api.toAddr(seg.addr), seg.size, true, true, true, false);
        }

        // TODO: How to create pointers/data/symbols within individual overlay blocks?
        // This doesn't seem to work. Perhaps using an AddressSpace somehow? Are overlay blocks even what we want?
        // This currently gives a CodeUnitInsertionException saying there's insufficient memory at 0xFFFC for a 2-byte pointer.
        //createPointer(program, api.toAddr(0xFFFC));
    }

    private void createSegment(FlatProgramAPI api, InputStream input, String name, Address start, long length, boolean read, boolean write, boolean exec, boolean overlay) {
        try {
            MemoryBlock blk = api.createMemoryBlock(name, start, input, length, overlay);
            blk.setRead(read);
            blk.setWrite(write);
            blk.setExecute(exec);
        } catch (Exception e) {
            Msg.error(this, e.getMessage());
        }
    }

    private void createUninitializedSegment(FlatProgramAPI api, String name, Address start, long length, boolean read, boolean write, boolean exec, boolean overlay) {
        Program program = api.getCurrentProgram();
        try {
            MemoryBlock blk = program.getMemory().createUninitializedBlock(name, start, length, overlay);
            blk.setRead(read);
            blk.setWrite(write);
            blk.setExecute(exec);
        } catch (Exception e) {
            Msg.error(this, e.getMessage());
        }
    }

    private int createPointer(Program program, Address addr) {
        Data d = program.getListing().getDataAt(addr);
        if (d == null) {
            try {
                d = program.getListing().createData(addr, PointerDataType.dataType, 2);
            } catch (CodeUnitInsertionException | DataTypeConflictException e) {
                Msg.error(this, String.format("Failed to create pointer at 0x%X", addr.getOffset()), e);
            }
        }
        if (d == null) {
            return 0;
        }
        return d.getLength();
    }
}
