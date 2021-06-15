package smsloader.rom;

import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.Pointer16DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.task.TaskMonitor;
import smsloader.RomHeader;

public class PhantasyStar {

	public static boolean added(
		Program program,
		Address address,
		TaskMonitor monitor,
		MessageLog log,
		Boolean ignoreChecksum,
		Boolean ignoreVersion,
		int overrideProductCode
	) {
		try {
			RomHeader rom_header = new RomHeader(program);
			if (check(rom_header, ignoreChecksum, ignoreVersion, overrideProductCode))
				return false;

			Instruction instruction = program.getListing().getInstructionAt(address);
			String addressString = address.toString();
			// log.appendMsg("'Analyzing' Phantasy Star AddressSetview " + addressString);

			AddressSpace bank12_space = program.getAddressFactory().getAddressSpace(String.format("bank_%02d", 12));
			switch (addressString) {
				case "ram:1cdf":
					instruction.addOperandReference(1, bank12_space.getAddress(0xba62), RefType.DATA,
							SourceType.DEFAULT);
			}

			return true;
		} catch (Exception e) {
			log.appendException(e);
		}
		return false;
	}

	/**
	 * TODO: try to migrate all these to logic in smsanalyszer?
	 * @param program
	 * @param addressSetView
	 * @param monitor
	 * @param log
	 * @param ignoreChecksum
	 * @param ignoreVersion
	 * @param overrideProductCode
	 * @return
	 */
	public static boolean added(
		Program program,
		AddressSetView addressSetView,
		TaskMonitor monitor,
		MessageLog log,
		Boolean ignoreChecksum,
		Boolean ignoreVersion,
		int overrideProductCode
	) {
		try {
			RomHeader rom_header = new RomHeader(program);
			if (check(rom_header, ignoreChecksum, ignoreVersion, overrideProductCode))
				return false;

			log.appendMsg("'Analyzing' Phantasy Star AddressSetview");

			FlatProgramAPI api = new FlatProgramAPI(program, monitor);
			AddressSpace ram = api.getAddressFactory().getAddressSpace("ram");

			AddressSpace bank12_space = program.getAddressFactory().getAddressSpace(String.format("bank_%02d", 12));

			// 		LAB_ram_0679                                    XREF[1]:     ram:06ce(j)  
			// ram:0679 21 45 be        LD         HL,0xbe45
			// ram:067c cd cf 31        CALL       ShowDialogue_B12                                 undefined ShowDialogue_B12()
			// ram:067f cd 19 2d        CALL       ShowYesNoPrompt                                  undefined ShowYesNoPrompt()
			// ram:0682 20 41           JR         NZ,LAB_ram_06c5
			// ram:0684 21 1b be        LD         HL,0xbe1b
			// ram:0687 cd cf 31        CALL       ShowDialogue_B12                                 undefined ShowDialogue_B12()
	
			program.getListing().getInstructionAt(ram.getAddress(0x1cdf))
				.addOperandReference(1, bank12_space.getAddress(0xba62), RefType.DATA, SourceType.DEFAULT);
			
			program.getListing().getInstructionAt(ram.getAddress(0x1cdf))
				.addOperandReference(1, bank12_space.getAddress(0xba62), RefType.DATA, SourceType.DEFAULT);
			
			program.getListing().getInstructionAt(ram.getAddress(0x1ce8))
				.addOperandReference(1, bank12_space.getAddress(0xba82), RefType.DATA, SourceType.DEFAULT);
			
			program.getListing().getInstructionAt(ram.getAddress(0x1cf9))
				.addOperandReference(1, bank12_space.getAddress(0xba93), RefType.DATA, SourceType.DEFAULT);

			program.getListing().getInstructionAt(ram.getAddress(0x1d35))
				.addOperandReference(1, bank12_space.getAddress(0xbaa3), RefType.DATA, SourceType.DEFAULT);

			return true;
		} catch (Exception e) {
			log.appendException(e);
		}
		return false;
	}

	public static void load(
		ByteProvider provider,
		LoadSpec loadSpec,
		List<Option> options,
		Program program,
		TaskMonitor monitor,
		MessageLog log,
		RomHeader rom_header,
		Memory memory,
		AddressSpace ram,
		AddressSpace io,
		Boolean ignoreChecksum,
		Boolean ignoreVersion,
		int overrideProductCode
	) {
		if (check(rom_header, ignoreChecksum, ignoreVersion, overrideProductCode)) {
			return;
		}
		
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		log.appendMsg("Loading Phantasy Star");
		try {
			api.createLabel(ram.getAddress(0x0052), "WaitForVInt", true);
			api.createLabel(ram.getAddress(0x0084), "MainSetup", true);
			api.createLabel(ram.getAddress(0x00AF), "MainGameLoop", true);

			api.createLabel(ram.getAddress(0x00BE), "GameModeTbl", true);
			EnumDataType game_mode_enum = new EnumDataType("GameMode", 2);
			game_mode_enum.add("InitIntro", 0);
			game_mode_enum.add("InitIntro_COPY", 1);
			game_mode_enum.add("LoadIntro", 2);
			game_mode_enum.add("Intro", 3);
			game_mode_enum.add("LoadShip", 4);
			game_mode_enum.add("Ship", 5);
			game_mode_enum.add("MODE6", 6); // UNUSED?
			game_mode_enum.add("MODE7", 7); // UNUSED?
			game_mode_enum.add("LoadMap", 8);
			game_mode_enum.add("Map", 9);
			game_mode_enum.add("LoadDungeon", 0xA);
			game_mode_enum.add("Dungeon", 0xB);
			game_mode_enum.add("LoadInteraction", 0xC);
			game_mode_enum.add("Interaction", 0xD);
			game_mode_enum.add("LoadRoad", 0xE);
			game_mode_enum.add("Road", 0xF);
			game_mode_enum.add("LoadNameInput", 0x10);
			game_mode_enum.add("NameInput", 0x11);
			game_mode_enum.add("MODE0x12", 0x12); // UNUSED?
			game_mode_enum.add("MODE0x13", 0x13); // UNUSED?

			ArrayDataType game_mode_table = new ArrayDataType(new Pointer16DataType(), 20, 2);
			DataUtilities.createData(program, ram.getAddress(0x00BE), game_mode_table, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0x05d0), "GameMode_" + game_mode_enum.getName(0), true);
			api.createLabel(ram.getAddress(0x074D), "GameMode_" + game_mode_enum.getName(2), true);
			api.createLabel(ram.getAddress(0x05d6), "GameMode_" + game_mode_enum.getName(3), true);
			api.createLabel(ram.getAddress(0x0a5c), "GameMode_" + game_mode_enum.getName(4), true);
			api.createLabel(ram.getAddress(0x086F), "GameMode_" + game_mode_enum.getName(5), true);
			// api.createLabel(ram.getAddress(0x0B07), "GameMode_" + game_mode_enum.getName(6), true);
			// api.createLabel(ram.getAddress(0x0B07), "GameMode_" + game_mode_enum.getName(7), true);
			api.createLabel(ram.getAddress(0x0B6A), "GameMode_" + game_mode_enum.getName(8), true);
			api.createLabel(ram.getAddress(0x0B08), "GameMode_" + game_mode_enum.getName(9), true);
			api.createLabel(ram.getAddress(0x0F7D), "GameMode_" + game_mode_enum.getName(10), true);
			api.createLabel(ram.getAddress(0x0F3C), "GameMode_" + game_mode_enum.getName(11), true);
			api.createLabel(ram.getAddress(0x3C52), "GameMode_" + game_mode_enum.getName(12), true);
			api.createLabel(ram.getAddress(0x3B9C), "GameMode_" + game_mode_enum.getName(13), true);
			api.createLabel(ram.getAddress(0x0ED7), "GameMode_" + game_mode_enum.getName(14), true);
			api.createLabel(ram.getAddress(0x0E8B), "GameMode_" + game_mode_enum.getName(15), true);
			api.createLabel(ram.getAddress(0x4034), "GameMode_" + game_mode_enum.getName(16), true);
			api.createLabel(ram.getAddress(0x03EB9), "GameMode_" + game_mode_enum.getName(17), true);
			api.createLabel(ram.getAddress(0x0467C), "GameMode_" + game_mode_enum.getName(18), true);
			// api.createLabel(ram.getAddress(0x467C), "GameMode_" + game_mode_enum.getName(19), true);
			// api.createLabel(ram.getAddress(0x08587), "GameMode_" + game_mode_enum.getName(20), true);

			api.createLabel(ram.getAddress(0x00E6), "GetPtrAndJump", true);
			api.createLabel(ram.getAddress(0x00F1), "PauseLoop", true);
			api.createLabel(ram.getAddress(0x00fB), "VInt", true);

			ArrayDataType jump_table = new ArrayDataType(new Pointer16DataType(), 12, 2);
			DataUtilities.createData(program, ram.getAddress(0x018f), jump_table, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(ram.getAddress(0x02e5), "CallSndUpdate", true);
			api.createLabel(ram.getAddress(0x02ed), "CallSndInit", true);
			api.createLabel(ram.getAddress(0x02f5), "CallSndMute", true);
			api.createLabel(ram.getAddress(0x0339), "ReadJoypad", true);
			api.createLabel(ram.getAddress(0x05b1), "UpdateRNGSeed", true);

			DataUtilities.createData(program, ram.getAddress(0x0807), new StringDataType(), 0x40, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			addpointers(0xDFC, 0xDFD, program, ram);// ?
			addpointers(0x12C4, 0x12D4, program, ram);

			api.createLabel(ram.getAddress(0x16F1), "UnlockCharacter", true);
			api.createLabel(ram.getAddress(0x170d), "AwardEXP", true);
			// B03_AlisLevelTable,B03_MyauLevelTable,B03_OdinLevelTable,B03_NoahLevelTable

			api.createLabel(ram.getAddress(0x1754), "CalculateExp", true);
			// apply enum bank number to 0x175d
			api.createLabel(ram.getAddress(0x17ba), "UpdateCharStats", true);
			// fn
			// iy = char stats
			// ix = level table

			api.createLabel(ram.getAddress(0x183a), "ItemEquipBoosts", true);
			ArrayDataType item_equip_boosts = new ArrayDataType(new ByteDataType(), 0x187a - 0x0183a, 1);
			DataUtilities.createData(program, ram.getAddress(0x183a), item_equip_boosts, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0x187a), "IsCharacterAlive_FromC267", true);
			api.createLabel(ram.getAddress(0x187d), "IsCharacterAlive", true);

			api.createLabel(ram.getAddress(0x1912), "BattleMenu_OptionTbl", true);
			addpointers(0x1912, 0x191c, program, ram);
			api.createLabel(ram.getAddress(0x191c), "BattleMenu_Attack", true);
			api.createLabel(ram.getAddress(0x19de), "BattleMenu_Magic", true);
			api.createLabel(ram.getAddress(0x1b9e), "BattleMenu_Item", true);
			api.createLabel(ram.getAddress(0x192b), "BattleMenu_Talk", true);

			addpointers(0x198A, 0x199c, program, ram);
			api.createLabel(ram.getAddress(0x199c), "BattleMenu_Run", true);

			EnumDataType magic_id = new EnumDataType("MagicID", 1);
			magic_id.add("Nothing", 0x0);
			magic_id.add("Heal", 0x1);
			magic_id.add("Cure", 0x2);
			magic_id.add("Wall", 0x3);
			magic_id.add("Prot", 0x4);
			magic_id.add("Fire", 0x5);
			magic_id.add("Thun", 0x6);
			magic_id.add("Wind", 0x7);
			magic_id.add("Rope", 0x8);
			magic_id.add("Bye", 0x9);
			magic_id.add("Help", 0xA);
			magic_id.add("Terr", 0xB);
			magic_id.add("Trap", 0xC);
			magic_id.add("Exit", 0xD);
			magic_id.add("Open", 0xE);
			magic_id.add("Rise", 0xF);
			magic_id.add("Chat", 0x10);
			magic_id.add("Tele", 0x11);
			magic_id.add("Fly", 0x12);

			api.createLabel(ram.getAddress(0x1a57), "BattleMagicList", true);
			ArrayDataType magic_list = new ArrayDataType(magic_id, 5, 1);
			StructureDataType character_magic_list = new StructureDataType("CharacterMagicList", 0);
			character_magic_list.add(magic_list, 5, "Alis", "");
			character_magic_list.add(magic_list, 5, "Myau", "");
			character_magic_list.add(magic_list, 5, "Noah", "");
			DataUtilities.createData(program, ram.getAddress(0x1a57), character_magic_list, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			addpointers(0x1A66, 0x1AAE, program, ram);

			AddressSpace bank12_address = api.getAddressFactory().getAddressSpace("bank_12");
			addpointers(0x1B73, 0x1B87, program, bank12_address);
			
			api.createLabel(ram.getAddress(0x1c97), "PlayerMenu_OptionTbl", true);
			addpointers(0x1c97, 0x1ca1, program, ram);
			api.createLabel(ram.getAddress(0x1ca1), "PlayerMenu_Stats", true);
			api.createLabel(ram.getAddress(0x1d4d), "PlayerMenu_Magic", true);
			api.createLabel(ram.getAddress(0x2168), "PlayerMenu_Item", true);
			api.createLabel(ram.getAddress(0x2839), "PlayerMenu_Search", true);
			api.createLabel(ram.getAddress(0x1cdf), "PlayerMenu_Save", true);
			
			api.createLabel(ram.getAddress(0x2d25), "WaitForButton1Or2", true);
			 
			api.createLabel(ram.getAddress(0x1ddc), "MPCostData", true);
			ArrayDataType mp_cost_data = new ArrayDataType(new ByteDataType(), 0x13, 1);
			DataUtilities.createData(program, ram.getAddress(0x1ddc), mp_cost_data, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0x1def), "MapMagicList", true);
			//
			// StructureDataType map_magic_list = new StructureDataType("MapMagicList", 0);
			// map_magic_list.add(magic_list, 5, "Alis", "");
			// map_magic_list.add(magic_list, 5, "Myau", "");
			// map_magic_list.add(magic_list, 5, "Noah", "");
			//
			DataUtilities.createData(program, ram.getAddress(0x1def), character_magic_list, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			addpointers(0x1dfe, 0x1E24, program, ram);

			api.createLabel(ram.getAddress(0x21fb), "ItemActionJmpTbl", true);
			addpointers(0x21fb, 0x2201, program, ram);
			api.createLabel(ram.getAddress(0x2201), "ItemAction_Use", true);
			api.createLabel(ram.getAddress(0x26c8), "ItemAction_Equip", true);
			api.createLabel(ram.getAddress(0x2752), "ItemAction_Drop", true);

			api.createLabel(ram.getAddress(0x220a), "ItemUseJmpTbl", true);
			addpointers(0x220a, 0x228a, program, ram);
			api.createLabel(ram.getAddress(0x228a), "ItemUse_NoEffect", true);
			api.createLabel(ram.getAddress(0x2299), "ItemUse_Wand", true);
			api.createLabel(ram.getAddress(0x22af), "ItemUse_LandRover", true);
			api.createLabel(ram.getAddress(0x22e5), "ItemUse_Hovercraft", true);
			api.createLabel(ram.getAddress(0x231a), "ItemUse_IceDigger", true);
			api.createLabel(ram.getAddress(0x2333), "ItemUse_Cola", true);
			// heal 10
			api.createLabel(ram.getAddress(0x2337), "ItemUse_Burger", true);
			// heal 40
			api.createLabel(ram.getAddress(0x2369), "ItemUse_Flute", true);
			api.createLabel(ram.getAddress(0x239d), "ItemUse_Flash", true);
			api.createLabel(ram.getAddress(0x23e2), "ItemUse_Escaper", true);
			api.createLabel(ram.getAddress(0x23ec), "ItemUse_Transfer", true);
			api.createLabel(ram.getAddress(0x2416), "ItemUse_MagicHat", true);
			api.createLabel(ram.getAddress(0x242f), "ItemUse_Alsulin", true);
			// TODO: apply enum? decompile seems to have it figured out.
			// api.setEOLComment(ram.getAddress(0x2471), "ItemID_IronAxe");
			// api.setEOLComment(ram.getAddress(0x2475), "ItemID_IronArmor");
			api.createLabel(ram.getAddress(0x2491), "ItemUse_Polymaterial", true);
			api.createLabel(ram.getAddress(0x24be), "HumanCharacterIsAlive", true);
			api.createLabel(ram.getAddress(0x24e9), "ItemUse_DungeonKey", true);
			api.createLabel(ram.getAddress(0x2524), "ItemUse_Sphere", true);
			api.createLabel(ram.getAddress(0x2537), "ItemUse_EclipseTorch", true);
			api.createLabel(ram.getAddress(0x2589), "ItemUse_AeroPrism", true);
			api.createLabel(ram.getAddress(0x25c3), "ItemUse_Nuts", true);
			api.createLabel(ram.getAddress(0x2613), "ItemUse_Hapsby", true);
			api.createLabel(ram.getAddress(0x26b0), "ItemUse_NoUse", true);
			api.createLabel(ram.getAddress(0x2631), "ItemUse_Compass", true);
			api.createLabel(ram.getAddress(0x267c), "ItemUse_MiracleKey", true);
			
			api.createLabel(ram.getAddress(0x277c), "Inventory_RemoveItem", true);
			api.createLabel(ram.getAddress(0x277f), "Inventory_RemoveItem2", true); // referenced from LABEL_5401
			api.createLabel(ram.getAddress(0x282e), "Inventory_FindFreeSlot", true);
			// TODO: make const and apply
			api.setEOLComment(ram.getAddress(0x2831), "InventoryMaxNum");
			api.createLabel(ram.getAddress(0x279f), "Inventory_AddItem", true);
			// FUN_ram_2b84 ?
			api.setEOLComment(ram.getAddress(0x2d2d), "Button_1_Mask|Button_2_Mask");

			api.createLabel(ram.getAddress(0x2d51), "CheckOptionSelect", true);
			api.createLabel(ram.getAddress(0x2d60), "OptionSelect_Loop", true);
			api.setEOLComment(ram.getAddress(0x2d2d), "ButtonUp_Mask|ButtonDown_Mask");
			api.setEOLComment(ram.getAddress(0x2d74), "ButtonUp");
			api.setEOLComment(ram.getAddress(0x2d7d), "ButtoDown");

			api.createLabel(ram.getAddress(0x2d19), "ShowYesNoPrompt", true);
			
			api.createLabel(ram.getAddress(0x31bb), "CharacterNames", true);
			StructureDataType character_names = new StructureDataType("CharacterNames", 0);
			character_names.add(new StringDataType(), 4, "Alis", "");
			character_names.add(new StringDataType(), 4, "Myau", "");
			character_names.add(new StringDataType(), 4, "Odin", "");
			character_names.add(new StringDataType(), 4, "Noah", "");
			DataUtilities.createData(program, ram.getAddress(0x31bb), character_names, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0x31cf), "ShowDialogue_B12", true);

			api.createLabel(ram.getAddress(0x336c), "Display65TerminatedString", true);
			api.setEOLComment(ram.getAddress(0x3292), "Dialogue_NumberFromC2C5");

			api.setEOLComment(ram.getAddress(0x335b), "Dialogue_Terminator65");

			addpointers(0x3C2A, 0x3c52, program, ram);

			StructureDataType bank_address_map2 = new StructureDataType("BankAddressMap2", 0);
			bank_address_map2.add(new ByteDataType(), 1, "BankNumber", "");
			bank_address_map2.add(new Pointer16DataType(), 2, "Address", "");
			bank_address_map2.add(new Pointer16DataType(), 2, "Address2", "");
			StructureDataType bank_address_map = new StructureDataType("BankAddressMap", 0);
			bank_address_map.add(new ByteDataType(), 1, "BankNumber", "");
			bank_address_map.add(new Pointer16DataType(), 2, "Address", "");
			StructureDataType bank_address_map_set = new StructureDataType("BankAddressMapSet", 0);
			bank_address_map_set.add(bank_address_map2, 5, "Set1", "");
			bank_address_map_set.add(bank_address_map, 3, "Set2", "");
			ArrayDataType bank_address_map_set_array = new ArrayDataType(bank_address_map_set, 10, 1);
			Data d_array = DataUtilities.createData(program, ram.getAddress(0x3DA6), bank_address_map_set_array, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			ReferenceManager refman = program.getReferenceManager();
			for(int i = 0; i < d_array.getNumComponents(); i++) {
				Data dd_set = d_array.getComponent(i);
				for(int j = 0; j < dd_set.getNumComponents(); j++) {
					Data ddd_address_map = dd_set.getComponent(j); // either map or map2
					Data dddd_bank_number = ddd_address_map.getComponent(0);
					int bank_number = dddd_bank_number.getByte(0); // <32 no mask needed
					for(int k = 1; k < ddd_address_map.getNumComponents(); k ++) {
						Data dddd_pointer = ddd_address_map.getComponent(k);
						if(bank_number > 0){
							Address address = dddd_pointer.getAddress();
							byte[] bytes = dddd_pointer.getBytes();
						
							long bank_address_int = bytes[0]&0xff | ((bytes[1]<< 8)&0xff00);
							AddressSpace bank_space = program.getAddressFactory().getAddressSpace(String.format("bank_%02d", bank_number));
							Address bank_address = bank_space.getAddress(bank_address_int);
							refman.removeAllReferencesFrom(address);
							refman.addMemoryReference(address, bank_address, RefType.DATA, SourceType.USER_DEFINED, 0);
						}
					}
				}
			}

			/* Bank 1 */
			
			// first byte looks like bank number.
			// the first two bytes[0-1] of the first two sets look like addresses, but the rest don't
			StructureDataType bank_byte4 = new StructureDataType("BankByte4", 0);
			bank_byte4.add(new ByteDataType(), 1, "BankNumber", "");
			bank_byte4.add(new ByteDataType(), 4, "bytes", "");
			ArrayDataType bank_byte4_mapping_array = new ArrayDataType(bank_byte4, 9, 1);
			DataUtilities.createData(program, ram.getAddress(0x471E), bank_byte4_mapping_array, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			addpointers(0x4773, 0x48DF, program, ram);

			api.createLabel(ram.getAddress(0x4F9B), "Purchase_Gas_Shield", true);
			/* money -1000, add GasShield, subtracts money before findfreeslot? */
			api.createLabel(ram.getAddress(0x52d0), "Get_Crystal", true);
			api.createLabel(ram.getAddress(0x5401), "Get_Eclipse_Torch", true);

			api.createLabel(ram.getAddress(0x575a), "ShowDialogue_B2", true);

			addpointers(0x5827, 0x5853, program, ram);

			api.setEOLComment(ram.getAddress(0x5b11), "ButtonUp_Mask|ButtonDown_Mask|ButtonLeft_Mask|ButtonRight_Mask");

			api.createLabel(ram.getAddress(0x5f63), "Map_RunRandomBattles", true);
			api.createLabel(ram.getAddress(0x5fd8), "Dungeon_GetEncounter", true);
			
			// bank 14 pointers
			AddressSpace bank14_address = api.getAddressFactory().getAddressSpace("bank_14");
			addpointers(0x6345, 0x63A5, program, bank14_address);

			// regular bank 1 pointers
			addpointers(0x63B8, 0x63CE, program, ram);
			
			api.setEOLComment(ram.getAddress(0x66e4), "ButtonUp_Mask|ButtonDown_Mask|ButtonLeft_Mask|ButtonRight_Mask");
			
			// Bank 6 pointers
			AddressSpace bank06_address = api.getAddressFactory().getAddressSpace("bank_06");
			addpointers(0x6E75, 0x6E8B, program, bank06_address);
			
			ArrayDataType bank_address_mapping_array2 = new ArrayDataType(bank_address_map, (0x7143 - 0x705f) / 3, 1);
			Data d1 = DataUtilities.createData(program, ram.getAddress(0x705F), bank_address_mapping_array2, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			for(int j = 0; j < d1.getNumComponents(); j++) {
				Data ddd_address_map = d1.getComponent(j); // always map
				Data dddd_bank_number = ddd_address_map.getComponent(0);
				int bank_number = dddd_bank_number.getByte(0); // <32 no mask needed
				for(int k = 1; k < ddd_address_map.getNumComponents(); k ++) {
					Data dddd_pointer = ddd_address_map.getComponent(k);
					if(bank_number > 0){
						Address address = dddd_pointer.getAddress();
						byte[] bytes = dddd_pointer.getBytes();
					
						long bank_address_int = bytes[0]&0xff | ((bytes[1]<< 8)&0xff00);
						AddressSpace bank_space = program.getAddressFactory().getAddressSpace(String.format("bank_%02d", bank_number));
						Address bank_address = bank_space.getAddress(bank_address_int);
						refman.removeAllReferencesFrom(address);
						refman.addMemoryReference(address, bank_address, RefType.DATA, SourceType.USER_DEFINED, 0);
					}
				}
			}

			api.createLabel(ram.getAddress(0x7afd), "FadeOut", true);
			api.createLabel(ram.getAddress(0x7b05), "FadeOut2", true);
			api.createLabel(ram.getAddress(0x7b18), "FadeIn", true);
			api.createLabel(ram.getAddress(0x7b20), "FadeIn2", true);

			api.createLabel(ram.getAddress(0x7da3), "ItemNames", true);
			ArrayDataType item_names = new ArrayDataType(new StringDataType(), (0x7fab - 0x7da3) / 8, 8);
			DataUtilities.createData(program, ram.getAddress(0x7da3), item_names, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			// TODO: bit type
			// =================================================================
			// bits 0-1 = 0 = Weapon; 1 = Armor; 2 = Shield
			// bit 2 = If set, item cannot be thrown away
			// bit 4 = If set, Alis can equip item
			// bit 5 = If set, Myau can equip item
			// bit 6 = If set, Odin can equip item
			// bit 7 = If set, Noah can equip item
			// =================================================================
			api.createLabel(ram.getAddress(0x7fab), "ItemData", true); // ... 7feb
			ArrayDataType item_data = new ArrayDataType(new ByteDataType(), 0x7feb - 0x7fab, 1);
			DataUtilities.createData(program, ram.getAddress(0x7fab), item_data, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			/* Rom Header */

			/* bank2 */

			// MemoryBlock bank_02 = memory.getBlock("bank_02");
			api.createLabel(ram.getAddress(0x8000), "DialogueBlock", true);
			// api.createLabel(bank_02.getAddress(0x8000),"DialogueBlock", true);
			addpointers(0x8000, 0x82aa, program, ram);
			api.createLabel(ram.getAddress(0x82aa), "Dialogue_Index_0002", true);
			// TODO: 0x02aa pointer names

			api.createLabel(ram.getAddress(0xba81), "DialogueWordBlock", true);
			addpointers(0xba81, 0xbb81, program, ram);
			api.createLabel(ram.getAddress(0xbb81), "Dialogue_Word_Index_00", true);
			// TODO: 0x100 pointer names
			
			/* ram */
			
			api.createLabel(ram.getAddress(0xC202), "Game_mode", true);
			DataUtilities.createData(program, ram.getAddress(0xC202), game_mode_enum, 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(ram.getAddress(0xC212), "Game_is_paused", true);
			DataUtilities.createData(program, ram.getAddress(0xC212), new BooleanDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(ram.getAddress(0xC21b), "Fade_timer", true);
			DataUtilities.createData(program, ram.getAddress(0xC21b), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(ram.getAddress(0xC204), "Ctrl_1", true);
			DataUtilities.createData(program, ram.getAddress(0xC204), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(ram.getAddress(0xC204), "Ctrl_1_held", true);
			DataUtilities.createData(program, ram.getAddress(0xC204), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(ram.getAddress(0xC205), "Ctrl_1_pressed", true);
			DataUtilities.createData(program, ram.getAddress(0xC205), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(ram.getAddress(0xC20C), "RNG_seed", true);
			DataUtilities.createData(program, ram.getAddress(0xC20C), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(ram.getAddress(0xC204), "Ctrl_1", true);
			DataUtilities.createData(program, ram.getAddress(0xC204), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(ram.getAddress(0xC269), "Cursor_pos", true);
			DataUtilities.createData(program, ram.getAddress(0xC269), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(ram.getAddress(0xC26E), "Option_total_num", true); // number of options available for an
																				// interactive menu (e.g. player menu)
			DataUtilities.createData(program, ram.getAddress(0xC26E), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(ram.getAddress(0xC29E), "Interaction_Type", true); // Background?
			DataUtilities.createData(program, ram.getAddress(0xC29E), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(ram.getAddress(0xC2C2), "CurrentCharacter", true); // Used for battle dialogue etc
			DataUtilities.createData(program, ram.getAddress(0xC2C2), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(ram.getAddress(0xC2C4), "CurrentItem", true); // Used in dialogue, Inventory_AddItem etc
			
			EnumDataType item_id = new EnumDataType("ItemID", 1);
			item_id.add("Nothing", 0x0);
			item_id.add("WoodCane", 0x1);
			item_id.add("ShortSword", 0x2);
			item_id.add("IronSword", 0x3);
			item_id.add("Wand", 0x4);
			item_id.add("IronFang", 0x5);
			item_id.add("IronAxe", 0x6);
			item_id.add("TitaniumSword", 0x7);
			item_id.add("CeramicSword", 0x8);
			item_id.add("NeedleGun", 0x9);
			item_id.add("SilverFang", 0xA);
			item_id.add("HeatGun", 0xB);
			item_id.add("LightSaber", 0xC);
			item_id.add("LaserGun", 0xD);
			item_id.add("LaconiaSword", 0xE);
			item_id.add("LaconiaAxe", 0xF);
			item_id.add("LeatherArmor", 0x10);
			item_id.add("WhiteMantle", 0x11);
			item_id.add("LightSuit", 0x12);
			item_id.add("IronArmor", 0x13);
			item_id.add("ThickFur", 0x14);
			item_id.add("ZirconiaArmor", 0x15);
			item_id.add("DiamondArmor", 0x16);
			item_id.add("LaconiaArmor", 0x17);
			item_id.add("FradeMantle", 0x18);
			item_id.add("LeatherShield", 0x19);
			item_id.add("BronzeShield", 0x1A);
			item_id.add("IronShield", 0x1B);
			item_id.add("CeramicShield", 0x1C);
			item_id.add("Gloves", 0x1D);
			item_id.add("LaserShield", 0x1E);
			item_id.add("MirrorShield", 0x1F);
			item_id.add("LaconiaShield", 0x20);
			item_id.add("Landrover", 0x21);
			item_id.add("Hovercraft", 0x22);
			item_id.add("IceDigger", 0x23);
			item_id.add("Cola", 0x24);
			item_id.add("Burger", 0x25);
			item_id.add("Flute", 0x26);
			item_id.add("Flash", 0x27);
			item_id.add("Escaper", 0x28);
			item_id.add("Transfer", 0x29);
			item_id.add("MagicHat", 0x2A);
			item_id.add("Alsulin", 0x2B);
			item_id.add("Polymaterial", 0x2C);
			item_id.add("DungeonKey", 0x2D);
			item_id.add("Sphere", 0x2E);
			item_id.add("EclipseTorch", 0x2F);
			item_id.add("AeroPrism", 0x30);
			item_id.add("Nuts", 0x31);
			item_id.add("Hapsby", 0x32);
			item_id.add("RoadPass", 0x33);
			item_id.add("Passport", 0x34);
			item_id.add("Compass", 0x35);
			item_id.add("Cake", 0x36);
			item_id.add("Letter", 0x37);
			item_id.add("LaconiaPot", 0x38);
			item_id.add("MagicLamp", 0x39);
			item_id.add("AmberEye", 0x3A);
			item_id.add("GasShield", 0x3B);
			item_id.add("Crystal", 0x3C);
			item_id.add("MSystem", 0x3D);
			item_id.add("MiracleKey", 0x3E);
			item_id.add("Zillion", 0x3F);
			item_id.add("Secrets", 0x40);
			DataUtilities.createData(program, ram.getAddress(0xC2C4), item_id, 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC2C5), "CurrentDialogueNumber", true); // unsigned 2 bytes, little endian,
																					// used in dialogue, control
																					// character $5E
			DataUtilities.createData(program, ram.getAddress(0xC2C5), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC2C8), "CurrentBattle_EnemyName", true); // 8 bytes
			DataUtilities.createData(program, ram.getAddress(0xC2C8), new StringDataType(), 0x8, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC2D0), "CurrentBattle_EXPReward", true); // unsigned 2 bytes, little endian
			DataUtilities.createData(program, ram.getAddress(0xC2D0), new WordDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC2D9), "Dungeon_entrance_points_addr", true);
			DataUtilities.createData(program, ram.getAddress(0xC2D9), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC30A), "Dungeon_direction", true);
			DataUtilities.createData(program, ram.getAddress(0xC30A), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC30C), "Dungeon_position", true);
			DataUtilities.createData(program, ram.getAddress(0xC30C), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC30D), "Dungeon_index", true);
			DataUtilities.createData(program, ram.getAddress(0xC30D), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			StructureDataType character_stats = new StructureDataType("CharacterStats", 0);
			character_stats.add(new ByteDataType(), 1, "Status", "");
			character_stats.add(new ByteDataType(), 1, "curr_hp", "");
			character_stats.add(new ByteDataType(), 1, "curr_mp", "");
			character_stats.add(new WordDataType(), 2, "exp", "");
			character_stats.add(new ByteDataType(), 1, "level", "");
			character_stats.add(new ByteDataType(), 1, "max_hp", "");
			character_stats.add(new ByteDataType(), 1, "max_mp", "");
			character_stats.add(new ByteDataType(), 1, "attack", "");
			character_stats.add(new ByteDataType(), 1, "defense", "");
			character_stats.add(item_id, 1, "weapon", "");
			character_stats.add(item_id, 1, "armor", "");
			character_stats.add(item_id, 1, "shield", "");
			character_stats.add(new ByteDataType(), 1, "unknown", "");
			character_stats.add(new ByteDataType(), 1, "battle_magic_num", "");
			character_stats.add(new ByteDataType(), 1, "map_magic_num", "");

			api.createLabel(ram.getAddress(0xC400), "Alis_stats", true);
			api.createLabel(ram.getAddress(0xC400), "Char_stats", true);
			DataUtilities.createData(program, ram.getAddress(0xC400), character_stats, 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC410), "Myau_stats", true);
			DataUtilities.createData(program, ram.getAddress(0xC410), character_stats, 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC420), "Odin_stats", true);
			DataUtilities.createData(program, ram.getAddress(0xC420), character_stats, 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC430), "Noah_stats", true);
			DataUtilities.createData(program, ram.getAddress(0xC430), character_stats, 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC4C0), "Inventory", true);
			DataUtilities.createData(program, ram.getAddress(0xC4C0), item_id, 0x18, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC4E0), "Current_money", true);
			DataUtilities.createData(program, ram.getAddress(0xC4E0), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC4E2), "Inventory_curr_num", true);
			DataUtilities.createData(program, ram.getAddress(0xC4E2), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC4F0), "Party_curr_num", true); // starts from 0
			DataUtilities.createData(program, ram.getAddress(0xC4F0), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC500), "Dialogue_flags", true); // table holding flags for dialogues; if
																				// value is $FF, dialogue is not loaded
			// DataUtilities.createData(program, ram.getAddress(0xC500), new ByteDataType(),
			// 0x1, false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xC600), "Event_flags", true); // used for chests and scripted encounters in
																			// dungeons
			// DataUtilities.createData(program, ram.getAddress(0xC600), new ByteDataType(),
			// 0x1, false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xCB00), "System_stack", true);
			DataUtilities.createData(program, ram.getAddress(0xCB00), new ByteDataType(), 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(ram.getAddress(0xCB00), "Dungeon_layout", false);
			EnumDataType dungeon_tile = new EnumDataType("DungeonTile", 1);
			dungeon_tile.add("Empty", 0x0);
			dungeon_tile.add("Wall", 0x1);
			dungeon_tile.add("Floor up", 0x2);
			dungeon_tile.add("Floor down", 0x3);
			dungeon_tile.add("Unlocked door", 0x4); // bit 7 determines if it's open (set) or not (clear)
			dungeon_tile.add("Dungeon key door", 0x5);
			dungeon_tile.add("Magically locked door", 0x6);
			dungeon_tile.add("Fake wall", 0x7);
			dungeon_tile.add("Object", 0x8); // (Check out B03_ObjectData)
			dungeon_tile.add("Exit up", 0xA);
			dungeon_tile.add("Exit down", 0xB);
			dungeon_tile.add("Exit door", 0xC);
			dungeon_tile.add("Exit locked door", 0xD);
			dungeon_tile.add("Ext magical door", 0xE);
			ArrayDataType dungeon_layout = new ArrayDataType(dungeon_tile, 0x100, dungeon_tile.getLength());
			DataUtilities.createData(program, ram.getAddress(0xCB00), dungeon_layout, 0x1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			// $100 bytes; 1 byte per tile;
			// 0 = Empty
			// 1 = Wall
			// 2 = Floor up
			// 3 = Floor down
			// 4 = Unlocked door ; bit 7 determines if it's open (set) or not (clear)
			// 5 = Dungeon key door
			// 6 = Magically locked door
			// 7 = Fake wall
			// 8 = Object (Check out B03_ObjectData)
			// $A = Exit up
			// $B = Exit down
			// $C = Exit door
			// $D = Exit locked door
			// $E = Ext magical door

			/* Bank 03 */
			AddressSpace bank03_address = api.getAddressFactory().getAddressSpace("bank_03");

			api.createLabel(bank03_address.getAddress(0x8180), "B03_EncounterPoolData", true);
			EnumDataType enemy_id = new EnumDataType("EnemyID", 1);
			enemy_id.add("Nothing", 0x0);
			enemy_id.add("Sworm", 0x1);
			enemy_id.add("GrSlime", 0x2);
			enemy_id.add("WingEye", 0x3);
			enemy_id.add("ManEater", 0x4);
			enemy_id.add("Scorpion", 0x5);
			enemy_id.add("GScorpi", 0x6);
			enemy_id.add("BlSlime", 0x7);
			enemy_id.add("NFarmer", 0x8);
			enemy_id.add("OwlBear", 0x9);
			enemy_id.add("DeadTree", 0xA);
			enemy_id.add("Scorpius", 0xB);
			enemy_id.add("EFarmer", 0xC);
			enemy_id.add("GiantFly", 0xD);
			enemy_id.add("Crawler", 0xE);
			enemy_id.add("Barbrian", 0xF);
			enemy_id.add("GoldLens", 0x10);
			enemy_id.add("RdSlime", 0x11);
			enemy_id.add("WereBat", 0x12);
			enemy_id.add("BigClub", 0x13);
			enemy_id.add("Fishman", 0x14);
			enemy_id.add("EvilDead", 0x15);
			enemy_id.add("Tarantul", 0x16);
			enemy_id.add("Manticor", 0x17);
			enemy_id.add("Skeleton", 0x18);
			enemy_id.add("AntLion", 0x19);
			enemy_id.add("Marman", 0x1A);
			enemy_id.add("Dezorian", 0x1B);
			enemy_id.add("Leech", 0x1C);
			enemy_id.add("Vampire", 0x1D);
			enemy_id.add("Elephant", 0x1E);
			enemy_id.add("Ghoul", 0x1F);
			enemy_id.add("Shelfish", 0x20);
			enemy_id.add("Executer", 0x21);
			enemy_id.add("Wight", 0x22);
			enemy_id.add("SkullEn", 0x23);
			enemy_id.add("Ammonite", 0x24);
			enemy_id.add("Sphinx", 0x25);
			enemy_id.add("Serpent", 0x26);
			enemy_id.add("Sandworm", 0x27);
			enemy_id.add("Lich", 0x28);
			enemy_id.add("Octopus", 0x29);
			enemy_id.add("Stalker", 0x2A);
			enemy_id.add("EvilHead", 0x2B);
			enemy_id.add("Zombie", 0x2C);
			enemy_id.add("Batalion", 0x2D);
			enemy_id.add("RobotCop", 0x2E);
			enemy_id.add("Sorcerer", 0x2F);
			enemy_id.add("Nessie", 0x30);
			enemy_id.add("Tarzimal", 0x31);
			enemy_id.add("Golem", 0x32);
			enemy_id.add("AndroCop", 0x33);
			enemy_id.add("Tentacle", 0x34);
			enemy_id.add("Giant", 0x35);
			enemy_id.add("Wyvern", 0x36);
			enemy_id.add("Reaper", 0x37);
			enemy_id.add("Magician", 0x38);
			enemy_id.add("Horseman", 0x39);
			enemy_id.add("Frostman", 0x3A);
			enemy_id.add("Amundsen", 0x3B);
			enemy_id.add("RdDragn", 0x3C);
			enemy_id.add("GrDragn", 0x3D);
			enemy_id.add("Shadow", 0x3E);
			enemy_id.add("Mammoth", 0x3F);
			enemy_id.add("Centaur", 0x40);
			enemy_id.add("Marauder", 0x41);
			enemy_id.add("Titan", 0x42);
			enemy_id.add("Medusa", 0x43);
			enemy_id.add("WtDragn", 0x44);
			enemy_id.add("BlDragn", 0x45);
			enemy_id.add("GdDragn", 0x46);
			enemy_id.add("DrMad", 0x47);
			enemy_id.add("Lassic", 0x48);
			enemy_id.add("DarkFalz", 0x49);
			enemy_id.add("Saccubus", 0x4A);
			ArrayDataType enemy_encounter = new ArrayDataType(enemy_id, 0x8, 1);
			ArrayDataType enemy_encounter_pool = new ArrayDataType(enemy_encounter, 0x5E, 8);
			DataUtilities.createData(program, bank03_address.getAddress(0x8180), enemy_encounter_pool, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(bank03_address.getAddress(0x8470), "B03_MapEncounterIDList", true);
			// TODO: type?

			api.createLabel(bank03_address.getAddress(0x867f), "B03_EnemyData", false);

			StructureDataType enemy_data = new StructureDataType("EnemyData", 0);
			enemy_data.add(new StringDataType(), 8, "Name", "");
			enemy_data.add(new ByteDataType(), 8, "Unknown", "");
			enemy_data.add(new ByteDataType(), 1, "BankNumber", "");
			enemy_data.add(new Pointer16DataType(), 2, "GrapicsPointer", "");
			enemy_data.add(new ByteDataType(), 1, "Unknown2", "");
			enemy_data.add(new ByteDataType(), 1, "Party number", "");
			enemy_data.add(new ByteDataType(), 1, "HP", "");
			enemy_data.add(new ByteDataType(), 1, "Attack", "");
			enemy_data.add(new ByteDataType(), 1, "Defense", "");
			enemy_data.add(new ByteDataType(), 1, "Item drop", "");
			enemy_data.add(new WordDataType(), 2, "Meseta", "");
			enemy_data.add(new ByteDataType(), 1, "Trap chance", "");
			enemy_data.add(new WordDataType(), 2, "EXP", "");
			enemy_data.add(new ByteDataType(), 1, "Unknown3", "");
			enemy_data.add(new ByteDataType(), 1, "Run chance", "");
			/*
			 * log.appendMsg("enemy_id.getLength() " + enemy_id.getLength());
			 * log.appendMsg("enemy_id.getCount() " + enemy_id.getCount());
			 * log.appendMsg("enemy_data.getLength() " + enemy_data.getLength());
			 */
			ArrayDataType enemy_data_array = new ArrayDataType(enemy_data, enemy_id.getCount(), enemy_data.getLength());
			DataUtilities.createData(program, bank03_address.getAddress(0x867f), enemy_data_array, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			api.createLabel(bank03_address.getAddress(0x867f), "Enemy_None", true);

			addpointers(0x96F4, 0x980C, program, bank03_address);

			api.createLabel(bank03_address.getAddress(0xa935), "B03_DungeonEntrancePoints", true);
			// 6 bytes per data
			StructureDataType dungeon_entrance_point = new StructureDataType("DungeonEntrancePoint", 0);
			dungeon_entrance_point.add(new ByteDataType(), 6, "Point", "");
			ArrayDataType dungeon_entrance_point_array = new ArrayDataType(dungeon_entrance_point,
					(0xaf5c - 0xa935) / dungeon_entrance_point.getLength(), dungeon_entrance_point.getLength());
			DataUtilities.createData(program, bank03_address.getAddress(0xa935), dungeon_entrance_point_array, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(bank03_address.getAddress(0xaf5c), "B03_ObjectData", true);
			StructureDataType object_data = new StructureDataType("ObjectData", 0);
			object_data.add(new ByteDataType(), 1, "DungeonID", "");
			object_data.add(new ByteDataType(), 1, "Coordinates", " (YX)");
			object_data.add(new Pointer16DataType(), 2, "FlagAddress",
					"Flag address in RAM; either Dialogue_flags $C500 + number or Event_flags $C600 + number; if value in that address is $FF, the current object will be ignored");
			EnumDataType object_type = new EnumDataType("ObjectType", 1);
			object_type.add("Item", 0);
			object_type.add("Meseta", 1);
			object_type.add("Battle", 2);
			object_type.add("Dialogue", 3);
			object_data.add(object_type, 1, "ObjectType", "0 = Item; 1 = Meseta; 2 = Battle; 3 = Dialogue");
			UnionDataType content_type = new UnionDataType("ContentType");
			content_type.add(item_id, 1, "Item", "it holds the item ID; if byte 7 is > 0, the chest contains a trap)");
			content_type.add(new WordDataType(), 2, "Meseta", "");
			StructureDataType enemy_id_item_id = new StructureDataType("EnemyIdItemId", 0);
			enemy_id_item_id.addBitField(enemy_id, 4, "Nibble1", "");
			enemy_id_item_id.insertBitField(0, 1, 4, item_id, 4, "Nibble2", "");
			content_type.add(enemy_id_item_id, 2, "EnemyId", "byte 6 is the enemy ID, byte 7 is the item dropped");
			content_type.add(new Pointer16DataType(), 2, "DialogueId", "");
			object_data.add(content_type, 2, "Content", "which depends on type (byte 5)");
			
			// if type = Item, 
			// if type = Meseta, it holds the Meseta value (word)
			// if type = Battle, byte 6 is the enemy ID, byte 7 is the item dropped
			// if type = Dialogue, byte 6 is the dialogue ID
			
			ArrayDataType object_data_array = new ArrayDataType(object_data,
					(0xb473 - 1 - 0xaf5c) / object_data.getLength(), object_data.getLength());
			DataUtilities.createData(program, bank03_address.getAddress(0xaf5c), object_data_array, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(bank03_address.getAddress(0xb473), "DungeonTransitionData", true);
			StructureDataType dungeon_transition = new StructureDataType("DungeonTransition", 0);
			dungeon_transition.add(new ByteDataType(), 1, "DungeonID", "");
			dungeon_transition.add(new ByteDataType(), 1, "Coordinates", "(YX)");
			dungeon_transition.add(new ByteDataType(), 1, "TargetMap", "$FF means it's a room with an NPC");
			 // TODO; <del>break up into sub-types?</del> --- Use Union
			UnionDataType y_dialog = new UnionDataType("YDialogID");
			y_dialog.add(new ByteDataType(), 1, "Y", "");
			EnumDataType dialog_id = new EnumDataType("DialogID", 1);
			/*
			 * TODO: fill out dialog id numbers could be some dialog pointertable in bank12?
			 */
			y_dialog.add(dialog_id, 1, "DialogID", "");
			dungeon_transition.add(y_dialog, 1, "Y", "if TargetMap = $FF, it holds the dialogue ID");
			UnionDataType x_spriteindex = new UnionDataType("XSpriteIndex");
			x_spriteindex.add(new ByteDataType(), 1, "X", "");
			EnumDataType sprite_index = new EnumDataType("SpriteIndex", 1);
			/* TODO: fill out sprite index */
			x_spriteindex.add(sprite_index, 1, "SpriteIndex", "");
			dungeon_transition.add(x_spriteindex, 1, "X", "if TargetMap = $FF, it holds the sprite index");
			ArrayDataType dungeon_transition_array = new ArrayDataType(dungeon_transition,
					(0xB5B9 - 0xb473) / dungeon_transition.getLength(), dungeon_transition.getLength());
			DataUtilities.createData(program, bank03_address.getAddress(0xb473), dungeon_transition_array, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			api.createLabel(bank03_address.getAddress(0xb70d), "B03_ShopData", true);
			StructureDataType shop_item = new StructureDataType("ShopItem", 0);
			shop_item.add(item_id, 1, "Item", "");
			shop_item.add(new WordDataType(), 2, "Cost", "");
			ArrayDataType shop_item_array = new ArrayDataType(shop_item, 3, shop_item.getLength());

			StructureDataType shop_data = new StructureDataType("ShopData", 0);
			shop_data.add(new ByteDataType(), 1, "ItemCount", "");
			shop_data.add(shop_item_array, shop_item_array.getLength(), "Items", "");
			ArrayDataType shop_data_array = new ArrayDataType(shop_data, (0xb8af - 0xb70d) / shop_data.getLength(),
					shop_data.getLength());
			DataUtilities.createData(program, bank03_address.getAddress(0xb70d), shop_data_array, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			api.createLabel(bank03_address.getAddress(0xb8af), "B03_AlisLevelTable", true);
			api.createLabel(bank03_address.getAddress(0xb99f), "B03_MyauLevelTable", true);
			api.createLabel(bank03_address.getAddress(0xba8f), "B03_OdinLevelTable", true);
			api.createLabel(bank03_address.getAddress(0xbb7f), "B03_NoahLevelTable", true);
			StructureDataType level_entry = new StructureDataType("LevelEntry", 0);
			level_entry.add(new ByteDataType(), 1, "MaxHP", "");
			level_entry.add(new ByteDataType(), 1, "attack", "");
			level_entry.add(new ByteDataType(), 1, "defense", "");
			level_entry.add(new ByteDataType(), 1, "max MP", "");
			level_entry.add(new WordDataType(), 2, "5-6 = exp",
					"it's little endian so you need to read byte 6 first, byte 5 second");
			level_entry.add(new ByteDataType(), 1, "BattleSpellCount", "number of spells available in battle");
			level_entry.add(new ByteDataType(), 1, "WorldSpellCount", "number of spells available outside of battle");
			ArrayDataType level_entry_array = new ArrayDataType(level_entry, 30, level_entry.getLength());
			ArrayDataType level_entry_array_array = new ArrayDataType(level_entry_array, 4,
					level_entry_array.getLength() * 8);
			DataUtilities.createData(program, bank03_address.getAddress(0xb8af), level_entry_array_array, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			/**
			 * Bank 12, sound driver and dialog.
			 */

			api.createLabel(bank12_address.getAddress(0x8000), "Snd_InitDriver", true);
			api.createLabel(bank12_address.getAddress(0x8043), "Snd_UpdateAll", true);
			api.createLabel(bank12_address.getAddress(0x801f), "Snd_SilencePSG", true);
			
			addpointers(0x8253, 0x82EF, program, bank12_address);
			addpointers(0x8530, 0x8554, program, bank12_address);
			addpointers(0xA877, 0xA88D, program, bank12_address);
			addpointers(0xA916, 0xA920, program, bank12_address);

			// Dialogue from here on
			// Control characters:
			// $40 apostrophe
			// $5B current character name
			// $5C enemy name
			// $5D current item name
			// $5E reads 2 byte unsigned number from $C525 and displays it
			// $60 newline
			// $61 newpage
			// $62 terminator
			// $63 terminator
			// $65 terminator
			for (int address = 0xB108; address < 0xbfdc; address++) {
				DataUtilities.createData(program, bank12_address.getAddress(address), new CharDataType(), 0x1, false,
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			}
			api.createLabel(bank12_address.getAddress(0xB108), "EnemyDodges", true);
			api.createLabel(bank12_address.getAddress(0xB118), "CurrentCharacterDodges", true);
			api.createLabel(bank12_address.getAddress(0xba62), "InProgress", true);
			// TODO: Dialogue_Terminator65 string analyzer.

			/* Bank 15 */
			AddressSpace bank15_address = api.getAddressFactory().getAddressSpace("bank_15");
			
			// =================================================================
			// Each tile is stored in a nybble (4 bits)
			// 0 = Empty
			// 1 = Wall
			// 2 = Floor up
			// 3 = Floor down
			// 4 = Unlocked door ; bit 7 determines if it's open (set) or not (clear)
			// 5 = Dungeon key door
			// 6 = Magically locked door
			// 7 = Fake wall
			// 8 = Object (Check out B03_ObjectData)
			// $A = Exit up
			// $B = Exit down
			// $C = Exit door
			// $D = Exit locked door
			// $E = Ext magical door
			// =================================================================

			api.createLabel(bank15_address.getAddress(0x9f6e), "B15_DungeonLayouts", true);
			
			StructureDataType packed_dungeon_tile = new StructureDataType("PackedDungeonTile", 0);
			packed_dungeon_tile.addBitField(dungeon_tile, 4, "Nibble1", "");
			packed_dungeon_tile.insertBitField(0, 1, 4, dungeon_tile, 4, "Nibble2", "");
			ArrayDataType packed_dungeon_layout = new ArrayDataType(packed_dungeon_tile, 8 * 16,
					packed_dungeon_tile.getLength());
			ArrayDataType packed_dungeon_layout_array = new ArrayDataType(packed_dungeon_layout, 61,
					dungeon_layout.getLength());
			DataUtilities.createData(program, bank15_address.getAddress(0x9f6e), packed_dungeon_layout_array, 1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			// 8*16*61+x9f6e = 128*61+x9f6e = x1e80+x9f6e == xBDEE = LABEL_B15_BDEE:
			api.createLabel(bank15_address.getAddress(0x9f6e), "Dungeon_MedusaCave", true);
			api.createLabel(bank15_address.getAddress(0x9fee), "Dungeon_TriadaPrison", true);
			// TODO: 59 more Dungeon Labels

			/* Bank 21 */
			AddressSpace bank21_address = api.getAddressFactory().getAddressSpace("bank_21");
			addpointers(0x8000, 0x8200, program, bank21_address);

		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private static void addpointers(int start_address, int end_address, Program program, AddressSpace addressSpace)
			throws CodeUnitInsertionException, AddressOutOfBoundsException {
		for (int address_int = start_address; address_int < end_address; address_int += 2) {
			Address address = addressSpace.getAddress(address_int);
			DataUtilities.createData(program, address, new Pointer16DataType(), 2, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
		}
	}

	private static boolean check(
		RomHeader rom_header,
		Boolean ignoreChecksum,
		Boolean ignoreVersion,
		int overrideProductCode
	) {
		return (!ignoreChecksum && rom_header.checksum() != 0xEA38)
				|| (rom_header.productCode() != 0x9500 && rom_header.productCode() != overrideProductCode)
				|| (!ignoreVersion && rom_header.version() != 2);
	}
}
