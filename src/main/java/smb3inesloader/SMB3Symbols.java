package inesloader;

public class SMB3Symbols {
    public static class Symbol {
        String name;
        int addr;
        public Symbol(String name, int addr) {
            this.name = name;
            this.addr = addr;
        }
    }

    private static final Symbol[] IO_SYMS = {
        new Symbol("PPU_CTL1", 0x2000),
        new Symbol("PPU_CTL2", 0x2001),
        new Symbol("PPU_STAT", 0x2002),
        new Symbol("PPU_SPR_ADDR", 0x2003),
        new Symbol("PPU_SPR_DATA", 0x2004),
        new Symbol("PPU_SCROLL", 0x2005),
        new Symbol("PPU_VRAM_ADDR", 0x2006),
        new Symbol("PPU_VRAM_DATA", 0x2007),

        new Symbol("PAPU_CTL1", 0x4000),
        new Symbol("PAPU_RAMP1", 0x4001),
        new Symbol("PAPU_FT1", 0x4002),
        new Symbol("PAPU_CT1", 0x4003),
        new Symbol("PAPU_CTL2", 0x4004),
        new Symbol("PAPU_RAMP2", 0x4005),
        new Symbol("PAPU_FT2", 0x4006),
        new Symbol("PAPU_CT2", 0x4007),
        new Symbol("PAPU_TCR1", 0x4008),
        new Symbol("PAPU_TFREQ1", 0x400A),
        new Symbol("PAPU_TFREQ2", 0x400B),
        new Symbol("PAPU_NCTL1", 0x400C),
        new Symbol("PAPU_NFREQ1", 0x400E),
        new Symbol("PAPU_NFREQ2", 0x400F),
        new Symbol("PAPU_MODCTL", 0x4010),
        new Symbol("PAPU_MODDA", 0x4011),
        new Symbol("PAPU_MODADDR", 0x4012),
        new Symbol("PAPU_MODLEN", 0x4013),
        new Symbol("PAPU_EN", 0x4015),

        new Symbol("SPR_DMA", 0x4014),

        new Symbol("JOYPAD", 0x4016),

        new Symbol("FRAMECTR_CTL", 0x4017),

        new Symbol("apu_unused_1", 0x4009),
        new Symbol("apu_unused_2", 0x400D),
    };

    private static final Symbol[] ZERO_PAGE_COMMON_SYMS = {
        new Symbol("Temp_Var1", 0x00),
        new Symbol("Temp_Var2", 0x01),
        new Symbol("Temp_Var3", 0x02),
        new Symbol("Temp_Var4", 0x03),
        new Symbol("Temp_Var5", 0x04),
        new Symbol("Temp_Var6", 0x05),
        new Symbol("Temp_Var7", 0x06),
        new Symbol("Temp_Var8", 0x07),
        new Symbol("Temp_Var9", 0x08),
        new Symbol("Temp_Var10", 0x09),
        new Symbol("Temp_Var11", 0x0A),
        new Symbol("Temp_Var12", 0x0B),
        new Symbol("Temp_Var13", 0x0C),
        new Symbol("Temp_Var14", 0x0D),
        new Symbol("Temp_Var15", 0x0E),
        new Symbol("Temp_Var16", 0x0F),
        new Symbol("VBlank_Tick", 0x10),
        // 0x11 unused
        new Symbol("Horz_Scroll_Hi", 0x12),
        new Symbol("PPU_CTL1_Mod", 0x13), /* NOT DURING GAMEPLAY, this is used as an additional modifier to PPU_CTL1 */
        new Symbol("Vert_Scroll_Hi", 0x14),
        new Symbol("Level_ExitToMap", 0x15),
        new Symbol("Counter_1", 0x16),
        new Symbol("PPU_CTL2_Copy", 0x17),
        new Symbol("Pad_Holding", 0x18),
        new Symbol("Pad_Input", 0x19),
        new Symbol("Roulette_RowIdx", 0x1A),
        new Symbol("Pal_Force_Set12", 0x1B),
        new Symbol("PlantInfest_ACnt", 0x1C),
        new Symbol("VBlank_TickEn", 0x1D),
        new Symbol("Map_Enter2PFlag", 0x1E),
        new Symbol("Map_EnterViaID", 0x1F),
        new Symbol("Map__MULTIPLE_1", 0x20),
        // 0x21 unused
        new Symbol("Level_Width", 0x22),
        new Symbol("Scroll_ColumnR_and_VOffsetT", 0x23),
        new Symbol("Scroll_ColumnL_and_VOffsetB", 0x24),
        new Symbol("Scroll_ColorStrip", 0x25), /* 0x25 - 0x5A */
        new Symbol("Scroll_LastDir", 0x5B),
        new Symbol("Scroll_RightAndVert_Upd", 0x5C),
        new Symbol("Scroll_LeftUpd", 0x5D),
        new Symbol("Graphics_Queue", 0x5E),
        // 0x5F unused
        // 0x60 unused
        new Symbol("Level_LayPtr_AddrL", 0x61),
        new Symbol("Level_LayPtr_AddrH", 0x62),
        new Symbol("Map_Tile_AddrL", 0x63),
        new Symbol("Map_Tile_AddrH", 0x64),
        new Symbol("Level_ObjPtr_AddrL", 0x65),
        new Symbol("Level_ObjPtr_AddrH", 0x66),
        // 0x67 unuse,
        // 0x68 unused
        new Symbol("Video_Upd_AddrL", 0x69),
        new Symbol("Video_Upd_AddrH", 0x6A),
        new Symbol("Music_Base_L", 0x6B),
        new Symbol("Music_Base_H", 0x6C),
        new Symbol("Sound_Sqr_FreqL", 0x6D),
        new Symbol("Sound_Sqr_FreqH", 0x6E),
        new Symbol("Sound_Map_EntrV", 0x6F),
        new Symbol("Sound_Map_EntV2", 0x70),
        new Symbol("Music_PatchAdrL", 0x71),
        new Symbol("Music_PatchAdrH", 0x72),
        new Symbol("Sound_Map_Off", 0x73),
        // 0x74 - 0xF3 are context-dependent
        new Symbol("Scroll_OddEven", 0xF4),
        new Symbol("Controller1Press", 0xF5),
        new Symbol("Controller2Press", 0xF6),
        new Symbol("Controller1", 0xF7),
        new Symbol("Controller2", 0xF8),
        // 0xF9 unused
        // 0xFA unused
        // 0xFB unused
        new Symbol("Vert_Scroll", 0xFC),
        new Symbol("Horz_Scroll", 0xFD),
        // 0xFE unused
        new Symbol("PPU_CTL1_Copy", 0xFF),
    };

    private static final Symbol[] LOW_STACK_SYMS = {
        new Symbol("Update_Select", 0x100),
        new Symbol("Raster_Effect", 0x101),
        new Symbol("Debug_Flag", 0x160),
    };

    private static final Symbol[] SPRITE_SYMS = {
        new Symbol("Sprite_RAM", 0x200),
    };

    private static final Symbol[] RAM_SYMS = {
        new Symbol("Graphics_BufCnt", 0x300),
        new Symbol("Graphics_Buffer", 0x301), /* 0x301 - 0x36B */
        new Symbol("TileChng_VRAM_H", 0x36C),
        new Symbol("TileChng_VRAM_L", 0x36D),
        new Symbol("TileChng_Pats", 0x36E), /* 0x36E - 0x371 */
        new Symbol("Level_SizeOrig", 0x372),
        new Symbol("Level_PipeExitDir", 0x373),
        new Symbol("Level_7VertCopy", 0x374),
        new Symbol("Level_PipeNotExit", 0x375),
        new Symbol("Level_PauseFlag", 0x376),
        new Symbol("Level_SkipStatusBarUpd", 0x377),
        new Symbol("Raster_State", 0x378),
        /* 0x379 - 0x37F unused */
        new Symbol("Scroll_ToVRAMHi", 0x380),
        new Symbol("Scroll_Last_Col8AndOff8", 0x381),
        new Symbol("Scroll_PatStrip", 0x382), /* 0x382 - 0x3B7 */
        new Symbol("Scroll_ToVRAMHA", 0x3B8),
        new Symbol("Scroll_LastAttr", 0x3B9),
        new Symbol("Scroll_AttrStrip", 0x3BA), /* 0x3BA - 0x3C7 */
        new Symbol("World_Num_Debug", 0x3C8),
        new Symbol("Map_StarsDeltaX", 0x3C9),
        new Symbol("Map_StarsDeltaY", 0x3CA),
        /* 0x3CB - 0x3DA unused */
        new Symbol("Map_Stars_PRelX", 0x3DB),
        new Symbol("Map_Stars_PRelY", 0x3DC),
        new Symbol("Player_Power", 0x3DD),
        new Symbol("Level_JctCtl", 0x3DE),
        new Symbol("Level_JctFlag", 0x3DF),
        /* 0x3E0 unused */
        new Symbol("Map_DrawPanState", 0x3E1),
        new Symbol("ObjGroupRel_Idx", 0x3E2),
        new Symbol("InvFlip_VAddrHi", 0x3E3),
        /* 0x3E4 unused */
        new Symbol("InvFlip_Frame", 0x3E5),
        new Symbol("InvFlip_Counter", 0x3E6),
        new Symbol("InvStart_Item", 0x3E7),
        new Symbol("InvHilite_X", 0x3E8),
        new Symbol("InvHilite_Item", 0x3E9),
        new Symbol("THouse_ID", 0x3EA),
        new Symbol("THouse_Treasure", 0x3EB),
        new Symbol("Coins_Earned", 0x3EC),
        new Symbol("Map_Powerup_Poof", 0x3ED),
        new Symbol("Level_FreeVertScroll", 0x3EE),
        new Symbol("Level_7Vertical", 0x3EF),
        new Symbol("Level_SelXStart", 0x3F0),
        new Symbol("Update_Request", 0x3F1),
        new Symbol("Map_Starman", 0x3F2),
        new Symbol("Map_Power_Disp", 0x3F3),
        new Symbol("Map_Warp_PrevWorld", 0x3F4),

        /* 0x4XX 0x5XX are context-dependent memory */

        /* 0x600 - 0x601 unused */
        new Symbol("Level_Tile_Head", 0x602),
        new Symbol("Level_Tile_GndL", 0x603),
        new Symbol("Level_Tile_GndR", 0x604),
        new Symbol("Level_Tile_InFL", 0x605),
        new Symbol("Level_Tile_InFU", 0x606),
        new Symbol("Level_Tile_Whack", 0x607),
        new Symbol("Level_Tile_Quad", 0x608), /* 0x608 - 0x60B */
        /* 0x60C unused */
        new Symbol("Level_Tile_Slope", 0x60D), /* 0x60D - 0x610 */
        /* 0x611 unused */
        new Symbol("Scroll_Cols2Upd", 0x612),
        /* 0x613 - 0x618 unused */
        new Symbol("Bonus_CoinsYVel", 0x619), /* 0x619 - 0x61E */
        new Symbol("Bonus_CoinsY", 0x61F), /* 0x61F - 0x624 */
        new Symbol("Bonus_CoinsXVel", 0x625), /* 0x625 - 0x62A */
        new Symbol("Bonus_CoinsX", 0x62B), /* 0x62B - 0x630 */
        new Symbol("Bonus_CoinsYVelFrac", 0x631), /* 0x631 - 0x636 */
        /* 0x637 - 0x63C unused */
        new Symbol("Bonus_CoinsXVelFrac", 0x63D), /* 0x63D - 0x642 */
        /* 0x643 - 0x64A unused */
        new Symbol("Object_TileFeet", 0x64B),
        new Symbol("Object_TileWall", 0x64C),
        /* 0x64D unused */
        new Symbol("Object_AttrFeet", 0x64E),
        new Symbol("Object_AttrWall", 0x64F),
        /* 0x650 unused */
        new Symbol("Objects_SprHVis", 0x651), /* 0x651 - 0x658 */
        new Symbol("Objects_SpawnIdx", 0x659), /* 0x659 - 0x660 */
    };

    public static final Symbol[][] SMB3_MANUAL_SYMS = {
        IO_SYMS,
        ZERO_PAGE_COMMON_SYMS,
        LOW_STACK_SYMS,
        SPRITE_SYMS,
        RAM_SYMS,
    };
}
