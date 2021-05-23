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

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.flatapi.FlatProgramAPI;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class SMSLoaderLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {

		// Name the loader
		return "Sega Master System & Game Gear (SMS/GG)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
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
				loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("z80:LE:16:default", "default"), true));
				break;
			}			
		}	
		
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
			// 0x0000 - 0xbfff: ROM
			Address addr = ram.getAddress(0x0);
			MemoryBlock block = program.getMemory().createInitializedBlock("ROM", addr, 0xC000, (byte)0x00, monitor, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);

			long maxLen = provider.length();
			if(maxLen > 0xc000)	{
				maxLen = 0xc000;
			}
			
			// read the ROM bytes and attach them to the Ghidra program
			byte romBytes[] = provider.readBytes(0, maxLen);			
			program.getMemory().setBytes(addr, romBytes);
			
			// execution starts at byte 0
			AddressSet addrSet = new AddressSet(addr); // TODO: no clue how AddressSet works
			program.getFunctionManager().createFunction("Start", addr, addrSet, SourceType.IMPORTED);
						
			FlatProgramAPI api = new FlatProgramAPI(program, monitor);
			
			// https://www.smspower.org/Development/Mappers?from=Development.Mapper
			for(int i=/*0*/2; i < 32; i++){
				InputStream stream = provider.getInputStream(0x4000 * i);
				Address address = ram.getAddress(0x8000);;
				long length = 0x4000;// Banks are 16 KB
				boolean overlay = true;
				block = program.getMemory().createInitializedBlock(String.format("bank_%02d",i), address, stream, length, monitor, overlay);
				block.setRead(true);
				block.setWrite(false);
				block.setExecute(true);
			}

			// 0xc000 - 0xdfff: RAM
			addr = ram.getAddress(0xc000);
			block = program.getMemory().createInitializedBlock("System RAM", addr, 0x2000, (byte)0x00, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			
			// 0xe000 - 0xfffb: RAM Mirror, TODO: no clue how to tell Ghidra that this is a mirror
			// https://github.com/NationalSecurityAgency/ghidra/issues/1956
			addr = ram.getAddress(0xe000);
			block = program.getMemory().createInitializedBlock("System RAM (Mirror)", addr, 0x1ffc, (byte)0x00, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			
			String newLine = System.getProperty("line.separator");
			block = MemoryBlockUtils.createUninitializedBlock(
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
			api.createLabel(ram.getAddress(0xfffd), "BankSelect0", true);
			api.createLabel(ram.getAddress(0xfffe), "BankSelect1", true);
			api.createLabel(ram.getAddress(0xffff), "BankSelect2", true);
			

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

		}catch(Exception e) {
			log.appendException(e);
		}
		
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

}
