package inesloader;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class INESHeader implements StructConverter {
    public int magic;
    public byte cPRGROM16KbUnits;
    public byte cCHRROM8KbUnits;
    public byte flags6;
    public byte flags7;
    public byte flags8;
    public byte flags9;
    public byte flags10;
    public byte[] pad;

    public INESHeader(BinaryReader reader) throws IOException {
        reader.setPointerIndex(0);
        magic = reader.readNextInt();
        cPRGROM16KbUnits = reader.readNextByte();
        cCHRROM8KbUnits = reader.readNextByte();
        flags6 = reader.readNextByte();
        flags7 = reader.readNextByte();
        flags8 = reader.readNextByte();
        flags9 = reader.readNextByte();
        flags10 = reader.readNextByte();
        pad = reader.readNextByteArray(5);
    }

    @Override
    public DataType toDataType() {
        Structure struct = new StructureDataType("INESHeader_t", 0);
        struct.add(DWORD, 4, "magic", null);
        struct.add(BYTE, 1, "cPRGROM16KbUnits", null);
        struct.add(BYTE, 1, "cCHRROM8KbUnits", null);
        struct.add(BYTE, 1, "flags6", null);
        struct.add(BYTE, 1, "flags7", null);
        struct.add(BYTE, 1, "flags8", null);
        struct.add(BYTE, 1, "flags9", null);
        struct.add(BYTE, 1, "flags10", null);
        struct.add(new ArrayDataType(BYTE, 5, 1), "pad", null);
        return struct;
    }
}
