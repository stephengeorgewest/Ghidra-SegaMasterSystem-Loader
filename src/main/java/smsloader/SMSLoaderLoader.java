/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package smsloader;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import smsloader.rom.PhantasyStar;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.flatapi.FlatProgramAPI;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class SMSLoaderLoader extends AbstractLibrarySupportLoader {
	private static final String OPTION_APPLY_ROM_DATA = "Apply Rom Specific Data";
	private static final String OPTION_IGNORE_CHECKSUM = "Ignore Rom Header Checksum";
	private static final String OPTION_IGNORE_VERSION = "Ignore Rom Header Version Number";
	private static final String OPTION_OVERRIDE_PRODUCT = "Override Rom Header Product Code 0x";

	@Override
	public String getName() {

		// Name the loader
		return "Sega Master System & Game Gear (SMS/GG)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		RomHeader h = findHeader(provider);
		if(h != null) loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("z80:LE:16:default", "default"), true));
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		// Load the bytes from 'provider' into the 'program'.
		
		//
		// The Sega Master System/GG Memory Map
		//
		// 0x0000 - 0xbfff: ROM
		// 0xc000 - 0xdfff: RAM
		// 0xe000 - 0xffff: RAM Mirror
		//		
		
		try {			
			AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
			Memory memory = program.getMemory();
			
			// 0x0000 - 0xbfff: ROM
			Address addr = ram.getAddress(0x0);
			MemoryBlock rom_block = memory.createInitializedBlock("ROM", addr, 0xC000, (byte)0x00, monitor, false);
			rom_block.setRead(true);
			rom_block.setWrite(false);
			rom_block.setExecute(true);

			long maxLen = provider.length();
			if(maxLen > 0xc000)	{
				maxLen = 0xc000;
			}
			
			// read the ROM bytes and attach them to the Ghidra program
			byte romBytes[] = provider.readBytes(0, maxLen);			
			memory.setBytes(addr, romBytes);
			
			// execution starts at byte 0
			FlatProgramAPI api = new FlatProgramAPI(program, monitor);
			api.createLabel(ram.getAddress(0x0), "_START", true);
			api.createLabel(ram.getAddress(0x38), "_IRQ_HANDLER", true);
			api.createLabel(ram.getAddress(0x66), "_NMI_HANDLER", true);
						

			api.createLabel(ram.getAddress(0x7ff0), "Header", true);
			StructureDataType rom_header_type = new StructureDataType("RomHeader", 0);
			rom_header_type.add(new StringDataType(), 8, "TMR SEGA", "");
			rom_header_type.add(new WordDataType(), 2, "Reserved", "");
			rom_header_type.add(new WordDataType(), 2, "Checksum", "");
			rom_header_type.add(new WordDataType(), 2, "Product Code", "");
			rom_header_type.add(new ByteDataType(), 1, "Version", "");
			rom_header_type.add(new ByteDataType(), 1, "Region Code", "(SMS Export)");
			DataUtilities.createData(program, ram.getAddress(0x7ff0), rom_header_type, 0x1, false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			
			// https://www.smspower.org/Development/Mappers?from=Development.Mapper
			// TODO: check size program
			int bank_count = 32;
			EnumDataType bank_enum = new EnumDataType("BankNumber", 1/*(int)Math.ceil(Math.log(bank_count)/Math.log(2))*//*1,2,4,8*/);
			for(int i=/*0*/3; i < bank_count; i++){
				String bank_string = String.format("bank_%02d",i);
				bank_enum.add(bank_string, i);
				InputStream stream = provider.getInputStream(0x4000 * i);
				Address address = ram.getAddress(0x8000);;
				long length = 0x4000;// Banks are 16 KB
				boolean overlay = true;
				MemoryBlock bank_block = memory.createInitializedBlock(bank_string, address, stream, length, monitor, overlay);
				bank_block.setRead(true);
				bank_block.setWrite(false);
				bank_block.setExecute(true);
			}
			
			// 0xc000 - 0xdfff: RAM
			addr = ram.getAddress(0xc000);
			MemoryBlock ram_block = memory.createUninitializedBlock("System RAM", addr, 0x2000, false);
			ram_block.setRead(true);
			ram_block.setWrite(true);
			ram_block.setExecute(false);
			
			// 0xe000 - 0xfffb: RAM Mirror, TODO: no clue how to tell Ghidra that this is a mirror
			// https://github.com/NationalSecurityAgency/ghidra/issues/1956
			addr = ram.getAddress(0xe000);
			MemoryBlock ram_mirror_block = memory.createUninitializedBlock("System RAM (Mirror)", addr, 0x1ffc, false);
			ram_mirror_block.setRead(true);
			ram_mirror_block.setWrite(true);
			ram_mirror_block.setExecute(false);
			
			String newLine = System.getProperty("line.separator");
			MemoryBlockUtils.createUninitializedBlock(
				program,
				false,/* Overlay */
				"RomBankControl",
				ram.getAddress(0xfffc),
				0x0004,
				"ControlRegister:" + newLine +
				"	Bit	Function" + newLine +
				"	7	'ROM write' enable" + newLine +
				"	6-5	Unused" + newLine +
				"	4	RAM enable ($c000-$ffff)"+ newLine +
				"	3	RAM enable ($8000-$bfff)"+ newLine +
				"	2	RAM bank select"+ newLine +
				"	1-0	Bank shift"+ newLine +
				"" + newLine +
				"BankSelect[n]:" + newLine +
				"	Control register	ROM bank select for slot" + newLine +
				"	$fffd	0 ($0000-$3fff)" + newLine +
				"	$fffe	1 ($4000-$7fff)" + newLine +
				"	$ffff	2 ($8000-$bfff)" + newLine +
				"https://www.smspower.org/Development/Mappers",
			"program", false/*R*/, true/*W*/, false/*X*/, log);

			api.createLabel(ram.getAddress(0xfffc), "ControlRegister", true);
			StructureDataType control_register_type = new StructureDataType("ControlRegisterType", 0);
			control_register_type.addBitField(new ByteDataType(), 2, "Bank shift", "");
			control_register_type.insertBitField(0,1,2, new ByteDataType(), 1, "RAM bank select", "");
			control_register_type.insertBitField(0,1,3, new ByteDataType(), 1, "RAM enable ($8000-$bfff)", "");
			control_register_type.insertBitField(0,1,4, new ByteDataType(), 1, "RAM enable ($c000-$ffff)", "");
			control_register_type.insertBitField(0,1,5, new ByteDataType(), 2, "Unused", "");
			control_register_type.insertBitField(0,1,7, new ByteDataType(),1, "'ROM write' enable", "");
			
			ArrayDataType bank_controls = new ArrayDataType(bank_enum,3,1);
			api.createLabel(ram.getAddress(0xfffd), "BankSelect", true);
			DataUtilities.createData(program, ram.getAddress(0xfffd), bank_controls, 0x1, false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			/*
			Adding BankSelect as an array to control_register_type leads to:

			ControlRegister._0_1_ = 0x80;
			ControlRegister.BankSelect[0] = 0;
			ControlRegister.BankSelect[1] = 1;
			ControlRegister.BankSelect[2] = bank_02;
			*/
			/*control_register_type.add(bank_controls,"BankSelect","");
			DataUtilities.createData(program, ram.getAddress(0xfffc), control_register_type, 0x1, false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			*/
			/*
			Adding BankSelect indivitually leads to:

			ControlRegister = 0x80;
			BankSelect0 = 0;
			BankSelect1 = 1;
			BankSelect2 = bank_02;
			*//*
			api.createLabel(ram.getAddress(0xfffd), "BankSelect0", true);
			DataUtilities.createData(program, ram.getAddress(0xfffd), bank_enum, 0x1, false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			api.createLabel(ram.getAddress(0xfffe), "BankSelect1", true);
			DataUtilities.createData(program, ram.getAddress(0xfffe), bank_enum, 0x1, false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			api.createLabel(ram.getAddress(0xffff), "BankSelect2", true);
			DataUtilities.createData(program, ram.getAddress(0xffff), bank_enum, 0x1, false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			*/
			
			AddressSpace[] a = program.getAddressFactory().getAllAddressSpaces();
			/*for(int i= 0; i < a.length; i++){
				log.appendMsg("space " + i + ": " + a[i].getName());
			}*//*space 0: const
				space 1: unique
				space 2: ram
				space 3: io
				space 4: register
				space 5: OTHER
				space 6: EXTERNAL
				space 7: stack
				space 8: HASH
				space 9: bank_02
				*/
			AddressSpace io = a[3];

			// https://www.smspower.org/uploads/Development/smstech-20021112.txt
			MemoryBlockUtils.createUninitializedBlock(
				program,
				false,/* Overlay */
				"Memory control",
				io.getAddress(0x003e),
				0x0001,
				"",
			"program", true/*R*/, true/*W*/, false/*X*/, log);

			api.createLabel(io.getAddress(0x3f), "IO-Port-Control", true);
			api.createLabel(io.getAddress(0x7f), "VPD-PSG", true);
			api.createLabel(io.getAddress(0xbe), "VDPData", true);
			api.createLabel(io.getAddress(0xbf), "VPDAddress-Status", true);
			api.createLabel(io.getAddress(0xdc), "Port1", true);
			api.createLabel(io.getAddress(0xdd), "Port2", true);
			
			MemoryBlockUtils.createUninitializedBlock(
				program,
				false,/* Overlay */
				"I/O port control",
				io.getAddress(0x003f),
				0x0001,
				"",
			"program", true/*R*/, true/*W*/, false/*X*/, log);

			MemoryBlockUtils.createUninitializedBlock(
				program,
				false,/* Overlay */
				"VPD(R)/PSG(W)",
				io.getAddress(0x007f),
				0x0001,
				"Programable Sound Generators: https://www.smspower.org/Development/SN76489?from=Development.PSG",
			"program", true/*R*/, true/*W*/, false/*X*/, log);

			MemoryBlockUtils.createUninitializedBlock(
				program,
				false,/* Overlay */
				"VDPData",
				io.getAddress(0x00be),
				0x0001,
				"Video Display Processor: https://www.smspower.org/uploads/Development/msvdp-20021112.txt?sid=986fbf6f2211ba086f3f4047785c4bec",
			"program", true/*R*/, true/*W*/, false/*X*/, log);

			MemoryBlockUtils.createUninitializedBlock(
				program,
				false,/* Overlay */
				"VPDAddress/Status",
				io.getAddress(0x00bf),
				0x0001,
				"Video Display Processor: https://www.smspower.org/uploads/Development/msvdp-20021112.txt?sid=986fbf6f2211ba086f3f4047785c4bec",
			"program", true/*R*/, true/*W*/, false/*X*/, log);

			MemoryBlockUtils.createUninitializedBlock(
				program,
				false,/* Overlay */
				"IOPort1",
				io.getAddress(0x00dc),
				0x0001,
				"",
			"program", true/*R*/, true/*W*/, false/*X*/, log);
			
			MemoryBlockUtils.createUninitializedBlock(
				program,
				false,/* Overlay */
				"IOPort2",
				io.getAddress(0x00dd),
				0x0001,
				"",
			"program", true/*R*/, true/*W*/, false/*X*/, log);

			Boolean apply_rom_data = false;
			Boolean ignore_checksum = false;
			Boolean ignore_version = false;
			int override_product_version = -1;
			for (Option o:options){
				if(o == null) continue;
				Object value = o.getValue();
				if(value == null) continue;
				switch(o.getName()){
					case OPTION_APPLY_ROM_DATA: apply_rom_data = (boolean)value; break;
					case OPTION_IGNORE_CHECKSUM: ignore_checksum = (boolean)value; break;
					case OPTION_IGNORE_VERSION: ignore_version = (boolean)value; break;
					case OPTION_OVERRIDE_PRODUCT: override_product_version = Integer.parseInt((String)value,16);
				}
			}

			byte[] bytes = new byte[5];
			memory.getBytes(ram.getAddress(0x7ffa), bytes);

			RomHeader rom_header = new RomHeader(
				bytes
			);

			log.appendMsg(rom_header.toString());

			if(apply_rom_data){
				/*EAD8, 9500, 02 specific */
				PhantasyStar.load(program, rom_header, memory, ram, io, monitor, log,
				ignore_checksum,
				ignore_version,
				override_product_version);
			}
		} catch(Exception e) {
			log.appendException(e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(
		ByteProvider provider,
		LoadSpec loadSpec,
		DomainObject domainObject,
		boolean isLoadIntoProgram
	) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		list.add(new Option(OPTION_APPLY_ROM_DATA, true, Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-applyRomData"));
		list.add(new Option(OPTION_IGNORE_CHECKSUM, false, Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-ignoreRomChecksum"));
		list.add(new Option(OPTION_IGNORE_VERSION, false, Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-ignoreRomVersion"));

		String default_product_code = "";
		try {
			RomHeader h = findHeader(provider);
			default_product_code = String.format("%x", h.productCode());
		} catch(Exception e) {}
		list.add(new Option(OPTION_OVERRIDE_PRODUCT, default_product_code, String.class, Loader.COMMAND_LINE_ARG_PREFIX + "-overrideProductCode"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		List<String> validationErrorStr = new ArrayList<>();
		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(OPTION_APPLY_ROM_DATA) || name.equals(OPTION_IGNORE_CHECKSUM) || name.equals(OPTION_IGNORE_VERSION)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						validationErrorStr.add("Invalid type for option: " + name + " - " + option.getValueClass());
					}
				}
				else if (name.equals(OPTION_OVERRIDE_PRODUCT)) {
					if (!String.class.isAssignableFrom(option.getValueClass())) {
						validationErrorStr.add("Invalid type for option: " + name + " - " + option.getValueClass());
					}
					try {
						Integer.parseInt((String)option.getValue(), 16);
						validationErrorStr.add("Invalid value for option: " + name.replaceFirst(" 0x", "") + ", Must be [0-9A-Z]{1,4}");
					} catch  (Exception e) {
						validationErrorStr.add("Invalid value for option: " + name.replaceFirst(" 0x", "") + ", Must be between 0 and 0xFFFF");
					}
				}
			}
		}
		String superError = super.validateOptions(provider, loadSpec, options, program);
		if(superError != null) validationErrorStr.add( superError );
		if (validationErrorStr.size() > 0) {
			return validationErrorStr.stream().filter(str -> str!=null).collect(Collectors.joining("\r\n"));
		}
		return null;
	}
	
	private RomHeader findHeader(ByteProvider provider) throws IOException {
		// Validate this is a proper SMS/GG file by looking for the header
		
		// The 16-byte SMS/GG header can be found at one these offsets within the file
		long headerOffsets[] = {0x1ff0, 0x3ff0, 0x7ff0};
		long sizeOfHeader = 16;
		String signature = "TMR SEGA";
		
		for(int i = 0; i < headerOffsets.length; i++) {
			
			if(provider.length() < headerOffsets[i] + sizeOfHeader) {
				break;
			}
			
			// the first 8 bytes of header are a signature
			byte sig[] = provider.readBytes(headerOffsets[i], 8);
			if(Arrays.equals(sig, signature.getBytes())) {
				// found the SMS/GG header, this is a valid format
				return new RomHeader(provider.readBytes(headerOffsets[i]+8+2, 5));
			}			
		}
		return null;
	}

}
